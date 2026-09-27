import pytest
from src.parser import parse_jocky_source, ParserError


def test_parser_valid():
    source = """
    module system_triage {
        collect system
        collect processes
        collect network
    }
    """
    ast = parse_jocky_source(source)
    assert ast.name == "system_triage"
    assert len(ast.operations) == 3
    assert [op.op_type for op in ast.operations] == ["system", "processes", "network"]


def test_parser_invalid_operation():
    source = """
    module malicious_attempt {
        collect system
        collect exec_shell
    }
    """
    with pytest.raises(ParserError) as exc_info:
        parse_jocky_source(source)
    assert "Forbidden or unrecognized forensic operation 'exec_shell'" in str(exc_info.value)


def test_parser_missing_brace():
    source = "module broken collect system }"
    with pytest.raises(ParserError):
        parse_jocky_source(source)
