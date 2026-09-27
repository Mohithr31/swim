#!/usr/bin/env python3
import argparse, os, pathlib
p=argparse.ArgumentParser(description="Generate an OS-specific JOCKY agent launcher")
p.add_argument("--os",choices=["linux","windows"],required=True)
p.add_argument("--server",required=True)
p.add_argument("-o","--output",required=True)
a=p.parse_args(); out=pathlib.Path(a.output); out.parent.mkdir(parents=True,exist_ok=True)
if a.os=="linux":
    text='#!/usr/bin/env bash\nset -e\nexec python3 -m agent.linux_agent --server "'+a.server+'" "$@"\n'
    text='#!/usr/bin/env bash\nset -e\nexec python3 -m agent.jocky_agent --server "'+a.server+'" --snapshot "$@"\n'; out.write_text(text); os.chmod(out,0o755)
else:
    text='Param([string]$AgentId="",[string]$Passphrase="")\n$argsList=@("-m","agent.windows_agent","--server","'+a.server+'")\nif($AgentId){$argsList+=@("--id",$AgentId)}\nif($Passphrase){$argsList+=@("--passphrase",$Passphrase)}\npython @argsList\n'
    text='Param([string]$AgentId="",[string]$Passphrase="")\n$argsList=@("-m","agent.jocky_agent","--server","'+a.server+'","--snapshot")\nif($AgentId){$argsList+=@("--id",$AgentId)}\nif($Passphrase){$argsList+=@("--passphrase",$Passphrase)}\npython @argsList\n'; out.write_text(text)
print(f"Generated {a.os} launcher: {out.resolve()}")
