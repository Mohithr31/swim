"""
JOCKY Investigator CLI Client
"""
import sys
import os
import argparse
import requests
import json
from typing import Dict, List, Any

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.parser import parse_jocky_source
from src.plan import compile_plan_from_ast


class JockyClient:
    def __init__(self, server_url: str = "http://127.0.0.1:5000", api_key: str = None):
        self.server_url = server_url.rstrip("/")
        self.headers = {"X-API-Key": api_key} if api_key else {}

    def health(self) -> Dict:
        res = requests.get(f"{self.server_url}/api/health", headers=self.headers)
        return res.json()

    def register_device(self, device_id: str, hostname: str, os_name: str) -> Dict:
        payload = {"device_id": device_id, "hostname": hostname, "os": os_name}
        res = requests.post(f"{self.server_url}/api/devices/register", json=payload, headers=self.headers)
        return res.json()

    def list_devices(self) -> List:
        res = requests.get(f"{self.server_url}/api/devices", headers=self.headers)
        return res.json()

    def create_case(self, name: str, description: str = "") -> Dict:
        payload = {"name": name, "description": description}
        res = requests.post(f"{self.server_url}/api/cases", json=payload, headers=self.headers)
        return res.json()

    def list_cases(self) -> List:
        res = requests.get(f"{self.server_url}/api/cases", headers=self.headers)
        return res.json()

    def create_session(self, case_id: str, name: str) -> Dict:
        payload = {"case_id": case_id, "name": name}
        res = requests.post(f"{self.server_url}/api/sessions", json=payload, headers=self.headers)
        return res.json()

    def list_sessions(self, case_id: str = None) -> List:
        url = f"{self.server_url}/api/sessions"
        if case_id:
            url += f"?case_id={case_id}"
        res = requests.get(url, headers=self.headers)
        return res.json()

    def compile_dsl_file(self, file_path: str) -> Dict:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        res = requests.post(f"{self.server_url}/api/compile", json={"source": source}, headers=self.headers)
        return res.json()

    def submit_job(self, session_id: str, agent_id: str, plan_hash: str) -> Dict:
        payload = {"session_id": session_id, "agent_id": agent_id, "plan_hash": plan_hash}
        res = requests.post(f"{self.server_url}/api/jobs", json=payload, headers=self.headers)
        return res.json()

    def list_jobs(self) -> List:
        res = requests.get(f"{self.server_url}/api/jobs", headers=self.headers)
        return res.json()

    def list_evidence(self) -> List:
        res = requests.get(f"{self.server_url}/api/evidence", headers=self.headers)
        data = res.json()
        if isinstance(data, dict) and "rows" in data:
            return data["rows"]
        return data

    def verify_audit(self) -> Dict:
        res = requests.get(f"{self.server_url}/api/audit/verify", headers=self.headers)
        return res.json()

    def generate_report(self, case_id: str) -> Dict:
        res = requests.get(f"{self.server_url}/api/reports/{case_id}", headers=self.headers)
        return res.json()

    def threat_intel_status(self) -> Dict:
        res = requests.get(f"{self.server_url}/api/threat-intel/status", headers=self.headers)
        return res.json()

    def research_indicator(self, indicator: str, indicator_type: str = "auto") -> Dict:
        payload = {"indicator": indicator, "indicator_type": indicator_type}
        res = requests.post(f"{self.server_url}/api/threat-intel/research", json=payload, headers=self.headers)
        return res.json()


def main():
    parser = argparse.ArgumentParser(description="JOCKY Forensic CLI Client")
    parser.add_argument("--server", default="http://127.0.0.1:5000", help="JOCKY Server URL")
    parser.add_argument("--api-key", help="API key")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("health", help="Check server health")
    sub.add_parser("devices", help="List registered devices")
    
    c_case = sub.add_parser("create-case", help="Create investigation case")
    c_case.add_argument("name", help="Case name")
    c_case.add_argument("--desc", default="", help="Case description")

    sub.add_parser("cases", help="List cases")

    c_sess = sub.add_parser("create-session", help="Create collection session")
    c_sess.add_argument("case_id", help="Parent case ID")
    c_sess.add_argument("name", help="Session name")

    sub.add_parser("sessions", help="List sessions")

    c_comp = sub.add_parser("compile", help="Compile JOCKY DSL script")
    c_comp.add_argument("file", help="Path to .jky file")

    c_job = sub.add_parser("submit-job", help="Submit collection job to agent")
    c_job.add_argument("session_id", help="Session ID")
    c_job.add_argument("agent_id", help="Agent ID")
    c_job.add_argument("plan_hash", help="Plan SHA-256 hash")

    sub.add_parser("jobs", help="List jobs")
    sub.add_parser("evidence", help="List collected evidence")
    sub.add_parser("audit-verify", help="Verify audit log chain-of-custody")

    c_rep = sub.add_parser("report", help="Generate case report")
    c_rep.add_argument("case_id", help="Case ID")

    sub.add_parser("threat-intel", help="Check TinyFish threat intel configuration and status")

    c_res = sub.add_parser("research", help="Research an indicator (domain, IP, URL, or hash) via TinyFish")
    c_res.add_argument("indicator", help="Indicator value to search")
    c_res.add_argument("--type", default="auto", help="Indicator type (auto, domain, ipv4, ipv6, url, sha256)")

    args = parser.parse_args()
    client = JockyClient(server_url=args.server, api_key=args.api_key)

    try:
        if args.command == "health":
            print(json.dumps(client.health(), indent=2))
        elif args.command == "threat-intel":
            print(json.dumps(client.threat_intel_status(), indent=2))
        elif args.command == "research":
            print(json.dumps(client.research_indicator(args.indicator, args.type), indent=2))
        elif args.command == "devices":
            print(json.dumps(client.list_devices(), indent=2))
        elif args.command == "create-case":
            print(json.dumps(client.create_case(args.name, args.desc), indent=2))
        elif args.command == "cases":
            print(json.dumps(client.list_cases(), indent=2))
        elif args.command == "create-session":
            print(json.dumps(client.create_session(args.case_id, args.name), indent=2))
        elif args.command == "sessions":
            print(json.dumps(client.list_sessions(), indent=2))
        elif args.command == "compile":
            print(json.dumps(client.compile_dsl_file(args.file), indent=2))
        elif args.command == "submit-job":
            print(json.dumps(client.submit_job(args.session_id, args.agent_id, args.plan_hash), indent=2))
        elif args.command == "jobs":
            print(json.dumps(client.list_jobs(), indent=2))
        elif args.command == "evidence":
            print(json.dumps(client.list_evidence(), indent=2))
        elif args.command == "audit-verify":
            print(json.dumps(client.verify_audit(), indent=2))
        elif args.command == "report":
            res = client.generate_report(args.case_id)
            if "report_markdown" in res:
                print(res["report_markdown"])
            else:
                print(json.dumps(res, indent=2))
        else:
            parser.print_help()
    except Exception as e:
        print(f"[jocky_client-error] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
