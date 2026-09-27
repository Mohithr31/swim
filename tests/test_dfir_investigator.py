from server.dfir_investigator import investigate


def test_metadata_only_investigation_detects_process_and_ioc():
    result = investigate([
        {"timestamp":"2026-09-24T07:00:00Z","event_type":"process_start","executable":"C:\\Users\\A\\AppData\\Local\\Temp\\x.exe","command_line":"x.exe"},
        {"timestamp":"2026-09-24T07:01:00Z","event_type":"network_connection","domain":"bad.example","remote_port":443},
    ], indicators=["bad.example"])
    assert result["input_records"] == 2
    assert any(f["type"] == "Suspicious process execution" for f in result["findings"])
    assert any(f["type"] == "Indicator match" for f in result["findings"])
    assert len(result["executive_summary"]) <= 250
