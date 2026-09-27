import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_unified_agent_builder_exists():
    p = ROOT / "deploy" / "build_agent.py"
    assert p.exists()
    text = p.read_text(encoding="utf-8")
    assert "--platform" in text
    assert "sha256" in text
    assert "security-control bypass" in text

def test_standalone_manifest_contains_provenance_fields():
    text = (ROOT / "deploy" / "build_standalone.py").read_text(encoding="utf-8")
    for token in ("build_id", "source_revision", "artifact_type", "manifest_sha256"):
        assert token in text

def test_release_builds_both_native_agents():
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "build-linux-agent" in text
    assert "build-windows-agent" in text
    assert "deploy/build_agent.py --platform linux" in text
    assert "deploy/build_agent.py --platform windows" in text
