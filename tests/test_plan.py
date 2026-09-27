import pytest
from src.parser import parse_jocky_source
from src.plan import compile_plan_from_ast, validate_forensic_plan, PlanCompilerError


def test_plan_compiler_valid():
    source = """
    module triage {
        collect system
        collect processes
        collect network
    }
    """
    ast = parse_jocky_source(source)
    plan = compile_plan_from_ast(ast)
    
    assert plan["version"] == 1
    assert plan["module"] == "triage"
    assert len(plan["operations"]) == 3
    assert plan["operations"][0] == {"type": "system"}
    assert "plan_hash" in plan
    assert validate_forensic_plan(plan) is True


def test_plan_compiler_tampered_plan():
    source = "module test { collect system }"
    ast = parse_jocky_source(source)
    plan = compile_plan_from_ast(ast)
    
    # Tamper with operations
    plan["operations"].append({"type": "processes"})
    assert validate_forensic_plan(plan) is False


def test_plan_compiler_forbidden_op():
    source = "module test { collect system }"
    ast = parse_jocky_source(source)
    # Inject bad op into AST
    ast.operations[0].op_type = "rm_rf"
    with pytest.raises(PlanCompilerError):
        compile_plan_from_ast(ast)
