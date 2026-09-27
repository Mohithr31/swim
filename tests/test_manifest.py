import pytest
import os
import tempfile
from collector.manifest import ManifestGenerator
from collector.verify import verify_manifest_and_evidence


def test_manifest_generation_and_verification():
    with tempfile.TemporaryDirectory() as tmpdir:
        files_dir = os.path.join(tmpdir, "files")
        os.makedirs(files_dir, exist_ok=True)

        file1 = os.path.join(files_dir, "sysinfo.txt")
        file2 = os.path.join(files_dir, "procs.txt")

        with open(file1, "w") as f:
            f.write("OS: Linux 5.15 x86_64")
        with open(file2, "w") as f:
            f.write("PID 1 init\nPID 2 kthreadd")

        manifest_gen = ManifestGenerator()
        manifest_path = os.path.join(tmpdir, "manifest.json")
        manifest = manifest_gen.generate_manifest(
            case_id="case_001",
            session_id="sess_001",
            job_id="job_001",
            agent_id="agent_001",
            files_dir=files_dir,
            output_manifest_path=manifest_path
        )

        assert manifest["case_id"] == "case_001"
        assert manifest["file_count"] == 2
        assert os.path.exists(manifest_path)

        # Verify valid evidence
        res = verify_manifest_and_evidence(manifest_path, files_dir)
        assert res.valid is True
        assert len(res.tampered_files) == 0

        # Tamper with file1 content
        with open(file1, "a") as f:
            f.write("\nTampered content added!")

        res_tampered = verify_manifest_and_evidence(manifest_path, files_dir)
        assert res_tampered.valid is False
        assert len(res_tampered.tampered_files) > 0
