"""Authentic, read-only Linux endpoint collectors used by JOCKY agents."""
import os, re, json, socket, platform, shutil, subprocess, time
try:
    import pwd
except ImportError:  # Windows: POSIX passwd database is unavailable
    pwd = None
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional



def _run(cmd, timeout=8):
    try:
        return subprocess.check_output(cmd, text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        return ""


def system_info():
    os_release = {}
    try:
        for line in open('/etc/os-release', encoding='utf-8', errors='replace'):
            if '=' in line:
                k,v=line.rstrip().split('=',1); os_release[k]=v.strip().strip('"')
    except Exception: pass
    try: user=pwd.getpwuid(os.getuid()).pw_name if pwd is not None else os.environ.get("USERNAME", "unknown")
    except Exception: user=os.environ.get('USER','unknown')
    # Prefer an actual interactive login session when one is available.
    who_text = _run(['who'], timeout=5)
    who_users = [line.split()[0] for line in who_text.splitlines() if line.split()]
    if who_users:
        user = who_users[0]
    uptime=0
    try: uptime=float(open('/proc/uptime').read().split()[0])
    except Exception: pass
    # Collect additional host specifications from proc/sysfs using read-only APIs.
    cpu_cores = os.cpu_count() or 0
    processor = platform.processor() or ''
    if not processor:
        try:
            for line in open('/proc/cpuinfo', errors='replace'):
                if line.lower().startswith('model name') and ':' in line:
                    processor = line.split(':',1)[1].strip(); break
        except Exception: pass
    total_ram_gb = free_ram_gb = None
    try:
        meminfo = {}
        for line in open('/proc/meminfo', errors='replace'):
            if ':' in line:
                k,v=line.split(':',1); meminfo[k]=int(v.strip().split()[0]) * 1024
        total = meminfo.get('MemTotal',0); avail = meminfo.get('MemAvailable', meminfo.get('MemFree',0))
        total_ram_gb = round(total/1024**3, 2); free_ram_gb = round(avail/1024**3, 2)
    except Exception: pass
    disk_total_gb = disk_free_gb = None
    try:
        du = shutil.disk_usage('/')
        disk_total_gb = round(du.total/1024**3, 2); disk_free_gb = round(du.free/1024**3, 2)
    except Exception: pass
    boot_time = None
    try:
        boot_time = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp()-uptime, timezone.utc).isoformat()
    except Exception: pass
    return {
        'hostname': socket.gethostname(), 'operating_system': os_release.get('PRETTY_NAME') or platform.platform(),
        'kernel': platform.release(), 'os_version': os_release.get('VERSION',''),
        'architecture': platform.machine(), 'architecture_bits': platform.architecture()[0],
        'system_directory':'/', 'logged_in_user':user, 'uptime_seconds': int(uptime),
        'python_version': platform.python_version(), 'processor': processor, 'cpu_cores': cpu_cores,
        'total_ram_gb': total_ram_gb, 'free_ram_gb': free_ram_gb,
        'total_disk_gb': disk_total_gb, 'free_disk_gb': disk_free_gb, 'boot_time': boot_time,
        'timezone': datetime.now().astimezone().tzname(),
        'timestamp': datetime.now(timezone.utc).isoformat(), 'source':'Linux endpoint (read-only)'
    }


def _sha256_file(path):
    import hashlib
    try:
        h=hashlib.sha256()
        with open(path,'rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _linux_file_metadata(path: str, is_dir: bool = False) -> Dict[str, Any]:
    """Autopsy-style live metadata for a Linux filesystem object."""
    st=os.lstat(path)
    owner=str(st.st_uid); group=str(st.st_gid)
    try:
        import pwd, grp
        owner=pwd.getpwuid(st.st_uid).pw_name
        group=grp.getgrgid(st.st_gid).gr_name
    except Exception: pass
    birth=None
    if shutil.which("stat"):
        out=_run(["stat","-c","%w",path],5).strip()
        if out and out not in ("-","0"):
            birth=out
    ext=os.path.splitext(path)[1] if not is_dir else ""
    mismatch=detect_extension_mismatch(path,ext) if not is_dir else {}
    return {
        "inode": st.st_ino, "device_id": st.st_dev, "uid": st.st_uid, "gid": st.st_gid,
        "owner": owner, "group": group, "mode": oct(st.st_mode & 0o7777), "nlink": st.st_nlink,
        "created_time": birth, "change_time": datetime.fromtimestamp(st.st_ctime,timezone.utc).isoformat(),
        "modified_time": datetime.fromtimestamp(st.st_mtime,timezone.utc).isoformat(),
        "access_time": datetime.fromtimestamp(st.st_atime,timezone.utc).isoformat(),
        "sha256": _sha256_file(path) if (not is_dir and os.path.isfile(path)) else None,
        "mismatch_flag": mismatch.get("mismatch",False), "detected_type": mismatch.get("detected_type", "Directory" if is_dir else "File"),
        "magic_hex": mismatch.get("magic_hex","")
    }


_PROCESS_HASH_CACHE = {}
_PROCESS_CPU_CACHE = {}

def _cached_executable_sha256(exe):
    if not exe or not os.path.isfile(exe):
        return None
    try:
        st = os.stat(exe)
        key = (exe, st.st_mtime_ns, st.st_size)
        cached = _PROCESS_HASH_CACHE.get(key)
        if cached:
            return cached
        digest = _sha256_file(exe)
        # Keep the cache bounded by executable path, replacing stale entries.
        for k in list(_PROCESS_HASH_CACHE):
            if k[0] == exe and k != key:
                _PROCESS_HASH_CACHE.pop(k, None)
        if digest:
            _PROCESS_HASH_CACHE[key] = digest
        return digest
    except Exception:
        return None

def _memory_maps(pid):
    rows=[]
    try:
        with open(f'/proc/{pid}/maps', errors='replace') as fh:
            for line in fh:
                parts=line.rstrip().split(None,5)
                if len(parts) < 5: continue
                addr, perms, offset, dev, inode = parts[:5]
                path = parts[5] if len(parts) > 5 else ''
                start,end=(addr.split('-',1)+[''])[:2]
                rows.append({'start':'0x'+start,'end':'0x'+end,'permissions':perms,'offset':'0x'+offset,'device':dev,'inode':inode,'path':path})
    except Exception:
        pass
    return rows[:1000]

def processes(limit=300):
    result=[]
    hz=os.sysconf(os.sysconf_names['SC_CLK_TCK'])
    boot_epoch=None
    try: boot_epoch=datetime.now(timezone.utc).timestamp()-float(open('/proc/uptime').read().split()[0])
    except Exception: pass
    for name in os.listdir('/proc'):
        if not name.isdigit(): continue
        pid=int(name)
        try:
            stat=open(f'/proc/{pid}/stat').read().split()
            cmdline=open(f'/proc/{pid}/cmdline','rb').read().replace(b'\0',b' ').decode(errors='replace').strip()
            status={}
            for line in open(f'/proc/{pid}/status', errors='replace'):
                if ':' in line:
                    k,v=line.split(':',1); status[k]=v.strip()
            uid=int(status.get('Uid','0').split()[0]);
            try: user=pwd.getpwuid(uid).pw_name
            except Exception: user=str(uid)
            exe=''
            try: exe=os.readlink(f'/proc/{pid}/exe')
            except Exception: pass
            start_ticks=int(stat[21]); start_time=(boot_epoch+start_ticks/hz if boot_epoch else None)
            proc_ticks=int(stat[13])+int(stat[14])
            now_mono=time.monotonic() if 'time' in globals() else __import__('time').monotonic()
            prev_cpu=_PROCESS_CPU_CACHE.get(pid)
            cpu_percent=None
            if prev_cpu:
                dt=max(0.001, now_mono-prev_cpu[0])
                cpu_percent=round(((proc_ticks-prev_cpu[1])/max(1,hz))/dt*100.0,2)
            _PROCESS_CPU_CACHE[pid]=(now_mono,proc_ticks)
            def proc_link(link):
                try: return os.readlink(f'/proc/{pid}/{link}')
                except Exception: return None
            cwd=proc_link('cwd')
            root=proc_link('root')
            fd_paths=[]
            try:
                for fd in os.listdir(f'/proc/{pid}/fd')[:250]:
                    try:
                        target=os.readlink(f'/proc/{pid}/fd/{fd}')
                        if target and not target.startswith(('socket:','pipe:','anon_inode:')):
                            fd_paths.append({'fd':fd,'path':target})
                    except Exception: continue
            except Exception: pass
            open_files=sorted({x['path'] for x in fd_paths if x.get('path')})[:200]
            directories=sorted({x for x in [cwd,root] if x})
            directories += sorted({os.path.dirname(x) for x in open_files if x.startswith('/')})[:200]
            ppid=int(stat[3])
            vmrss_kb=int(status.get('VmRSS','0 kB').split()[0])
            vmpeak_kb=int(status.get('VmPeak','0 kB').split()[0])
            vmsize_kb=int(status.get('VmSize','0 kB').split()[0])
            executable_hash=_cached_executable_sha256(exe)
            result.append({'pid':pid,'ppid':ppid,'name':stat[1].strip('()'),'executable':exe,
                           'executable_sha256':executable_hash,
                           'command_line':cmdline,'user':user,'memory_kb':vmrss_kb,'memory_percent':None,'cpu_percent':cpu_percent,
                           'vm_peak_kb':vmpeak_kb,'vm_size_kb':vmsize_kb,
                           'state':stat[2],'threads':int(status.get('Threads','0')),
                           'start_time':datetime.fromtimestamp(start_time,timezone.utc).isoformat() if start_time else None,
                           'working_directory':cwd,'root_directory':root,'open_files':open_files,
                           'file_descriptors':fd_paths,'accessed_directories':sorted(set(directories))[:200],
                           'memory_maps':_memory_maps(pid),
                           'file_access_note':'Point-in-time /proc file-descriptor view; not historical file-access auditing.',
                           'source':'/proc'})
        except Exception: continue
        if len(result)>=limit: break
    children={}
    for r in result: children.setdefault(r['ppid'],[]).append(r['pid'])
    by_pid={r['pid']:r for r in result}
    for r in result:
        r['child_pids']=sorted(children.get(r['pid'],[]))
        r['child_count']=len(r['child_pids'])
        r['child_processes']=[{'pid':cpid,'name':by_pid.get(cpid,{}).get('name'),'executable':by_pid.get(cpid,{}).get('executable')} for cpid in r['child_pids']]
        parent=by_pid.get(r['ppid'])
        r['parent_name']=parent.get('name') if parent else None
        r['parent_executable']=parent.get('executable') if parent else None
    total_ram_kb=0
    try:
        for line in open('/proc/meminfo', errors='replace'):
            if line.startswith('MemTotal:'): total_ram_kb=int(line.split()[1]); break
    except Exception: pass
    if total_ram_kb:
        for r in result:
            r['memory_percent']=round((r.get('memory_kb',0)/total_ram_kb)*100,2)
    return sorted(result,key=lambda x:x['pid'])


def network():
    out=[]
    text=_run(['ss','-tunap']) or _run(['netstat','-tunap'])
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith(('Netid','Proto','Active')): continue
        p=line.split()
        if len(p)<5: continue
        proto=p[0]; local=p[4] if proto in ('tcp','udp','tcp6','udp6') else ''
        remote=p[5] if len(p)>5 else ''
        state=p[1] if proto.startswith('tcp') and len(p)>1 else ''
        users=' '.join(p[6:]) if len(p)>6 else ''
        pid=None
        m=re.search(r'pid=(\d+)',users)
        if m: pid=int(m.group(1))
        def split_ep(ep):
            if ep.startswith('[') and ']:' in ep:
                a,b=ep.rsplit(']:',1); return a.strip('[]'),b
            if ':' in ep: return ep.rsplit(':',1)
            return ep,''
        la,lp=split_ep(local); ra,rp=split_ep(remote)
        out.append({'protocol':proto.upper(),'local_address':la,'local_port':lp,'remote_address':ra,'remote_port':rp,'state':state,'pid':pid,'process':users,'source':'ss/netstat'})
    return out


def users():
    """Return interactive/human Linux accounts, not service/system accounts."""
    result=[]
    try:
        active_sessions = {}
        text = _run(['who'], timeout=5)
        for line in text.splitlines():
            parts = line.split()
            if parts:
                active_sessions.setdefault(parts[0], []).append({
                    'terminal': parts[1] if len(parts) > 1 else '',
                    'login_date': ' '.join(parts[2:5]) if len(parts) >= 5 else '',
                    'source': 'who'
                })

        # Respect the distribution's configured UID_MIN when available.
        uid_min = 1000
        try:
            for line in open('/etc/login.defs', errors='replace'):
                if line.strip().startswith('UID_MIN'):
                    uid_min = int(line.split()[1]); break
        except Exception:
            pass
        excluded_shells = {'/usr/sbin/nologin', '/sbin/nologin', '/bin/false', '/usr/bin/false'}
        seen=set()
        for u in pwd.getpwall():
            # Human login accounts normally have UID >= UID_MIN, a real home,
            # and an interactive shell. This excludes daemon/service accounts.
            if u.pw_uid < uid_min or u.pw_name in seen:
                continue
            if u.pw_shell in excluded_shells:
                continue
            if not (u.pw_dir.startswith('/home/') or u.pw_name == 'root'):
                continue
            seen.add(u.pw_name)
            result.append({
                'username':u.pw_name,'uid':u.pw_uid,'gid':u.pw_gid,'home':u.pw_dir,
                'shell':u.pw_shell,'account_status':'present','logged_in':u.pw_name in active_sessions,
                'login_sessions':active_sessions.get(u.pw_name, []),'source':'/etc/passwd + who (human accounts)'
            })
    except Exception: pass
    return sorted(result, key=lambda x: (not x.get('logged_in',False), x.get('username','').lower()))


def services(limit=200):
    result=[]
    text=_run(['systemctl','list-units','--type=service','--all','--no-legend','--no-pager'],timeout=12)
    for line in text.splitlines():
        p=line.split(None,4)
        if len(p)>=4:
            result.append({'service_name':p[0].removesuffix('.service'),'load_state':p[1],'active_state':p[2],'sub_state':p[3],'description':p[4] if len(p)>4 else '', 'source':'systemctl'})
        if len(result)>=limit: break
    if not result:
        text=_run(['service','--status-all'],timeout=12)
        for line in text.splitlines():
            m=re.match(r'\s*\[\s*([+?-])\s*\]\s+(.*)',line)
            if m: result.append({'service_name':m.group(2).strip(),'active_state':{'+' :'active','-':'inactive','?':'unknown'}[m.group(1)],'source':'service --status-all'})
    return result


def detect_extension_mismatch(filepath: str, ext: str) -> Dict[str, Any]:
    """Inspect magic bytes of a file on Linux to detect disguised file extensions."""
    result = {"mismatch": False, "detected_type": "unknown", "expected_ext": ext, "magic_hex": ""}
    if not os.path.isfile(filepath):
        return result

    try:
        with open(filepath, "rb") as f:
            header = f.read(16)
        result["magic_hex"] = header.hex()[:16].upper()
        ext_lower = ext.lower().lstrip(".")

        if header.startswith(b"\x7fELF"):
            result["detected_type"] = "ELF Executable / Library"
            if ext_lower not in {"elf", "so", "out", "", "bin", "kmod", "ko"}:
                result["mismatch"] = True
        elif header.startswith(b"#!"):
            result["detected_type"] = "Shell Script"
            if ext_lower not in {"sh", "bash", "py", "pl", "rb", "zsh", ""}:
                result["mismatch"] = True
        elif header.startswith(b"MZ"):
            result["detected_type"] = "Windows Executable (EXE/DLL)"
            if ext_lower not in {"exe", "dll", "sys", "com", "scr"}:
                result["mismatch"] = True
        elif header.startswith(b"\x89PNG\r\n\x1a\n"):
            result["detected_type"] = "PNG Image"
            if ext_lower not in {"png"}:
                result["mismatch"] = True
        elif header.startswith(b"\xff\xd8\xff"):
            result["detected_type"] = "JPEG Image"
            if ext_lower not in {"jpg", "jpeg"}:
                result["mismatch"] = True
        elif header.startswith(b"%PDF"):
            result["detected_type"] = "PDF Document"
            if ext_lower not in {"pdf"}:
                result["mismatch"] = True
        elif header.startswith(b"PK\x03\x04"):
            result["detected_type"] = "ZIP Archive / Office Open XML"
            if ext_lower not in {"zip", "docx", "xlsx", "pptx", "jar", "apk"}:
                result["mismatch"] = True
        elif header.startswith(b"\x1f\x8b"):
            result["detected_type"] = "GZIP Compressed Archive"
            if ext_lower not in {"gz", "tgz", "tar.gz"}:
                result["mismatch"] = True
        else:
            result["detected_type"] = ext_lower.upper() or "Text/Data"
    except Exception:
        pass

    return result


def filesystem(path='/'):
    result=[]
    try:
        target=os.path.abspath(path or '/')
        if not os.path.isdir(target): return []
        for e in sorted(os.scandir(target),key=lambda x:x.name.lower())[:500]:
            try:
                is_dir=e.is_dir(follow_symlinks=False)
                meta=_linux_file_metadata(e.path,is_dir)
                result.append({
                    'name':e.name,'filename':e.name,'path':e.path,'is_directory':is_dir,'type':'Directory' if is_dir else 'File',
                    'extension':os.path.splitext(e.name)[1] if not is_dir else '', 'size_bytes':e.stat(follow_symlinks=False).st_size if not is_dir else 0,
                    'size':e.stat(follow_symlinks=False).st_size if not is_dir else 0, 'mode':meta['mode'],'mode_octal':meta['mode'],
                    'attributes':'Directory' if is_dir else ('Read-Only' if not (e.stat(follow_symlinks=False).st_mode & 0o222) else 'Normal'),
                    'owner':meta['owner'],'group':meta['group'],'inode':meta['inode'],'uid':meta['uid'],'gid':meta['gid'],'nlink':meta['nlink'],
                    'created_time':meta['created_time'],'change_time':meta['change_time'],'modified_time':meta['modified_time'],'mtime':meta['modified_time'],'access_time':meta['access_time'],'atime':meta['access_time'],
                    'sha256':meta['sha256'],'is_deleted':False,'status':'PRESENT','mismatch_flag':meta['mismatch_flag'],'detected_type':meta['detected_type'],'magic_hex':meta['magic_hex'],'read_only':True
                })
            except Exception: continue
    except Exception: pass
    return result

def software(limit: int = 500) -> List[Dict[str, Any]]:
    """Collect installed Linux packages using the host package manager.
    Read-only; no package installation/removal is performed.
    """
    rows = []
    commands = [
        (['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\n'], 'dpkg'),
        (['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'], 'rpm'),
        (['pacman', '-Q'], 'pacman'),
    ]
    for cmd, manager in commands:
        if shutil.which(cmd[0]) is None:
            continue
        out = _run(cmd, timeout=20)
        if not out:
            continue
        for line in out.splitlines()[:limit]:
            parts = line.split('\t')
            if manager == 'pacman' and len(parts) >= 2:
                name, version = parts[0], parts[1]
                arch = 'unknown'
            elif len(parts) >= 2:
                name, version = parts[0], parts[1]
                arch = parts[2] if len(parts) > 2 else 'unknown'
            else:
                continue
            rows.append({
                'application_name': name, 'version': version,
                'publisher': manager, 'install_location': '',
                'install_date': '', 'architecture': arch,
                'package_manager': manager
            })
        break
    return rows


def disk_usage(path='/') -> List[Dict[str, Any]]:
    """Return actual filesystem usage for the requested Linux path."""
    try:
        u = shutil.disk_usage(path)
        total_gb = round(u.total / 1024**3, 2)
        free_gb = round(u.free / 1024**3, 2)
        used_gb = round((u.total - u.free) / 1024**3, 2)
        return [{'drive': path, 'drive_type': 'Fixed', 'filesystem': '',
                 'capacity_gb': total_gb, 'used_gb': used_gb,
                 'free_gb': free_gb, 'usage_pct': round((used_gb/total_gb)*100, 1) if total_gb else 0.0}]
    except Exception:
        return []


def scheduled_tasks() -> List[Dict[str, Any]]:
    """Collect cron/anacron entries without modifying them."""
    tasks = []
    for path in ['/etc/crontab', '/etc/anacrontab']:
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                for n, line in enumerate(f, 1):
                    line=line.strip()
                    if line and not line.startswith('#'):
                        tasks.append({'task_name': f'{os.path.basename(path)}:{n}', 'path': path,
                                      'state': 'Configured', 'author': 'system',
                                      'last_run': 'N/A', 'next_run': 'N/A', 'command': line})
        except Exception:
            pass
    return tasks


def environment() -> Dict[str, str]:
    return {k: v for k, v in os.environ.items()
            if not any(x in k.upper() for x in ('SECRET','PASSWORD','PASSWD','TOKEN','PRIVATE_KEY','API_KEY'))}


def logs(limit: int = 100) -> List[Dict[str, Any]]:
    """Collect recent journal/syslog text read-only."""
    out = _run(['journalctl', '-n', str(limit), '--no-pager', '-o', 'short-iso'], timeout=15)
    if not out:
        for path in ['/var/log/syslog', '/var/log/messages']:
            try:
                with open(path, encoding='utf-8', errors='replace') as f:
                    lines = f.readlines()[-limit:]
                out=''.join(lines)
                break
            except Exception:
                pass
    rows=[]
    for line in out.splitlines()[-limit:]:
        rows.append({'timestamp': datetime.now(timezone.utc).isoformat(), 'channel': 'system',
                     'event_id': 0, 'level': 'Information', 'provider': 'Linux',
                     'message': line, 'line': line, 'source': 'Linux'})
    return rows


def network_config() -> List[Dict[str, Any]]:
    return get_linux_network_interfaces()


def mounts() -> List[Dict[str, Any]]:
    rows=[]
    try:
        out=_run(['findmnt','-rn','-o','SOURCE,TARGET,FSTYPE'], timeout=8)
        for line in out.splitlines():
            parts=line.split(None,2)
            if len(parts)==3:
                rows.append({'device':parts[0], 'mount':parts[1], 'filesystem':parts[2]})
    except Exception:
        pass
    return rows


def memory() -> Dict[str, Any]:
    data = dict(get_linux_memory_telemetry())
    # Stable dashboard contract; preserve the underlying live-memory source fields.
    data.setdefault("live_assessment_type", data.get("assessment_type"))
    data["assessment_type"] = "Physical Memory (RAM)"
    return data


def registry() -> List[Dict[str, Any]]:
    return []


def live_events() -> List[Dict[str, Any]]:
    return logs(50)


def recovery() -> List[Dict[str, Any]]:
    return get_linux_recovery_candidates('/')


def offline() -> Dict[str, Any]:
    return {'platform': 'Linux', 'mode': 'live-endpoint-read-only'}

def security_telemetry() -> List[Dict[str, Any]]:
    try:
        from collector.security_telemetry import get_defender_security_telemetry
        return get_defender_security_telemetry()
    except Exception:
        return []

def browser_history(limit: int = 100) -> List[Dict[str, Any]]:
    """Best-effort read-only Chromium/Firefox history extraction."""
    import sqlite3, glob, tempfile
    rows=[]
    candidates = glob.glob(os.path.expanduser('~/.config/google-chrome/*/History')) + glob.glob(os.path.expanduser('~/.config/chromium/*/History'))
    for db in candidates:
        try:
            with tempfile.NamedTemporaryFile(suffix='.sqlite') as tmp:
                shutil.copy2(db, tmp.name)
                con=sqlite3.connect(tmp.name); cur=con.cursor()
                for url,title,ts in cur.execute('SELECT url,title,last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?', (max(1, min(int(limit), 500)),)):
                    rows.append({'browser':'Chromium','url':url,'title':title or '', 'timestamp':str(ts), 'visit_count':1, 'source_path':db})
                con.close()
        except Exception:
            continue
    return rows


def get_linux_login_events() -> List[Dict[str, Any]]:
    """Collect Linux logon and failed authentication events.

    Parses `last`, `/var/log/auth.log`, `/var/log/secure`, or `journald`
    to match the schema of `get_windows_login_events()`.
    """
    logins = []
    # 1. Parse 'last' output for recent logins
    last_text = _run(['last', '-n', '20', '-F'], timeout=8)
    if last_text:
        for line in last_text.splitlines():
            line = line.strip()
            if not line or line.startswith('wtmp begins') or line.startswith('reboot'):
                continue
            parts = line.split()
            if len(parts) >= 10:
                user = parts[0]
                tty = parts[1]
                src_host = parts[2] if parts[2] != 'still' else 'local'
                login_date = ' '.join(parts[3:7])
                logins.append({
                    "event_id": 4624,
                    "timestamp": login_date,
                    "username": user,
                    "sid": f"UID-{hash(user) & 0xffff}",
                    "logon_type": f"Interactive/SSH ({tty})",
                    "source_workstation": src_host,
                    "source_ip": src_host if src_host != 'local' else "127.0.0.1",
                    "authentication_package": "PAM/SSH",
                    "status": "SUCCESS",
                    "description": f"User {user} logged in on {tty} from {src_host}."
                })

    # 2. Parse auth logs for failed login attempts
    auth_log_paths = ['/var/log/auth.log', '/var/log/secure']
    for path in auth_log_paths:
        if os.path.exists(path):
            try:
                lines = open(path, errors='replace').readlines()[-100:]
                for line in lines:
                    if 'Failed password' in line or 'authentication failure' in line:
                        m = re.search(r'for (?:invalid user )?(\S+) from (\S+) port (\d+)', line)
                        if m:
                            user, src_ip, port = m.groups()
                            logins.append({
                                "event_id": 4625,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "username": user,
                                "sid": "S-1-0-0",
                                "logon_type": "3 (Network/SSH)",
                                "source_workstation": "UNKNOWN_HOST",
                                "source_ip": src_ip,
                                "authentication_package": "SSH/PAM",
                                "status": "FAILURE",
                                "failure_reason": "Failed password or invalid user",
                                "description": f"Failed login for user {user} from {src_ip}:{port}."
                            })
            except Exception:
                pass

    # No synthetic login events: an empty result means no matching artifacts were recovered.

    return logins


def get_linux_network_interfaces() -> List[Dict[str, Any]]:
    """Collect Linux network interface configurations matching get_windows_network_interfaces() schema."""
    interfaces = []
    try:
        import psutil
        for name, addresses in psutil.net_if_addrs().items():
            ipv4 = next((a.address for a in addresses if a.family == socket.AF_INET), None)
            ipv6 = next((a.address for a in addresses if a.family == socket.AF_INET6), None)
            mac = next((a.address for a in addresses if getattr(a.family, "name", "") in {"AF_LINK", "AF_PACKET"}), None)
            if not ipv4 and not ipv6 and not mac:
                continue
            stats = psutil.net_if_stats().get(name)
            lowered = name.lower()
            interface_type = "Wi-Fi" if any(token in lowered for token in ("wlan", "wifi", "wireless")) else "Ethernet / Physical"
            interfaces.append({
                "interface_name": name,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "mac_address": mac,
                "dhcp_enabled": None,
                "gateway": None,
                "dns_servers": [],
                "interface_type": interface_type,
                "status": "Connected" if stats and stats.isup else "Disconnected",
                "speed_mbps": stats.speed if stats else None,
            })
            try:
                io = psutil.net_io_counters(pernic=True).get(name)
                if io:
                    interfaces[-1].update({
                        "bytes_sent": int(io.bytes_sent),
                        "bytes_recv": int(io.bytes_recv),
                        "packets_sent": int(io.packets_sent),
                        "packets_recv": int(io.packets_recv),
                        "errin": int(io.errin),
                        "errout": int(io.errout),
                        "dropin": int(getattr(io, "dropin", 0)),
                        "dropout": int(getattr(io, "dropout", 0)),
                    })
            except Exception:
                pass
    except Exception:
        pass
    return interfaces


def get_linux_storage() -> List[Dict[str, Any]]:
    """Collect Linux storage drive information matching get_windows_storage() schema."""
    storage = []
    try:
        u = shutil.disk_usage('/')
        tot_gb = round(u.total / (1024**3), 2)
        free_gb = round(u.free / (1024**3), 2)
        used_gb = round(tot_gb - free_gb, 2)
        pct = round((used_gb / tot_gb) * 100, 1) if tot_gb > 0 else 0.0
        storage.append({
            "drive": "/",
            "drive_type": "Fixed",
            "filesystem": "ext4",
            "capacity_gb": tot_gb,
            "used_gb": used_gb,
            "free_gb": free_gb,
            "usage_pct": pct
        })
    except Exception:
        pass
    return storage


def get_linux_browser_deltas() -> Dict[str, Any]:
    """Helper exposing live browser delta collection from collector/browser_delta.py."""
    from collector.browser_delta import collect_browser_delta_telemetry
    return collect_browser_delta_telemetry()


def get_linux_live_monitor(agent_id: str, server_url: str = "http://127.0.0.1:5000"):
    """Helper instantiating the live monitoring engine from collector/live_monitor.py."""
    from collector.live_monitor import LiveMonitorEngine
    return LiveMonitorEngine(agent_id=agent_id, server_url=server_url)


def get_linux_recovery_candidates(volume: str = "/") -> List[Dict[str, Any]]:
    """Helper exposing deleted file recovery candidate scan on Linux."""
    from collector.recovery import scan_deleted_files
    return scan_deleted_files(volume)


def perform_linux_file_recovery(candidate_id: str, source_path: str, output_dir: str = "evidence/recovered") -> Dict[str, Any]:
    """Helper performing read-only deleted file extraction to evidence vault on Linux."""
    from collector.recovery import recover_deleted_file
    return recover_deleted_file(candidate_id, source_path, output_dir)


def get_linux_memory_telemetry() -> Dict[str, Any]:
    """Helper exposing live RAM statistics and memory dump assessment on Linux."""
    from collector.memory import get_live_memory_statistics
    return get_live_memory_statistics()


# Standardized get_linux_* aliases matching windows_collector.py function names
get_linux_system_info = system_info
get_linux_processes = processes
get_linux_network = network
get_linux_users = users
get_linux_services = services
get_linux_filesystem = filesystem
get_linux_software = software
get_linux_scheduled_tasks = scheduled_tasks
get_linux_environment = environment
get_linux_logs = logs
get_linux_browser_history = browser_history

