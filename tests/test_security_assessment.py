from collector.security_assessment import assess_endpoint

def test_security_assessment_is_read_only():
    result = assess_endpoint()
    assert result["read_only"] is True
    assert "platform" in result
    assert "security_processes" in result
    assert "indicators" in result
