import shutil, subprocess, sys
from pathlib import Path
from src.parser import parse_jocky_source
from src.llvm_ir_gen import emit_llvm_ir

ROOT = Path(__file__).resolve().parents[1]

def test_module_llvm_backend_emits_all_forensic_hooks():
    source = (ROOT / "examples" / "full_forensic.jky").read_text()
    module = parse_jocky_source(source)
    ir = emit_llvm_ir(module, source_file="full_forensic.jky")
    for op in module.operations:
        assert f"@jocky_collect_{op.op_type}" in ir
    assert "define i32 @main()" in ir

def test_native_llvm_build_smoke(tmp_path):
    clang = shutil.which("clang")
    if not clang:
        import pytest
        pytest.skip("clang unavailable")
    out = tmp_path / "jocky_demo"
    r = subprocess.run([sys.executable, "-m", "src.jockyc", str(ROOT / "examples" / "forensic_demo.jky"), "-o", str(out)], cwd=ROOT, text=True, capture_output=True)
    assert r.returncode == 0, r.stderr
    assert out.exists()
