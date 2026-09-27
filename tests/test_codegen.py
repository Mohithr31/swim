import pytest
from src.parser import parse_jocky_source
from src.codegen import generate_c_code, CodeGeneratorError


def test_codegen_valid():
    source = """
    module test_gen {
        collect system
        collect processes
    }
    """
    ast = parse_jocky_source(source)
    c_code = generate_c_code(ast)

    assert '#include "jocky_runtime.h"' in c_code
    assert "jocky_collect_system()" in c_code
    assert "jocky_collect_processes()" in c_code
    assert 'printf("[JOCKY] Starting forensic collection module: %s\\n", "test_gen");' in c_code


def test_codegen_forbidden_op():
    source = "module test { collect system }"
    ast = parse_jocky_source(source)
    ast.operations[0].op_type = "eval"
    with pytest.raises(CodeGeneratorError):
        generate_c_code(ast)
