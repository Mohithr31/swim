# JOCKY V5 Build and Operations

## Safe implementation scope
V5 is a DFIR framework. It performs read-only endpoint collection, evidence handling, security assessment, centralized job management, and compiler/build provenance. It does not operationalize security-control bypass, EDR disabling, kernel subversion, BYOVD exploitation, or process-injection evasion.

## Build

```bash
python tools/build_jocky.py examples/full_forensic.jky -o build/full_forensic --backend llvm --build-metadata
```

The output includes the native artifact and a JSON manifest containing the source, plan hash, target, artifact hash, and non-secret build identity.

## Agent authentication
Set `JOCKY_API_KEY` on the server and pass the same key to the agent with `--api-key` or through the environment.

## Multi-endpoint workflow
1. Register agents.
2. Create a case and session.
3. Compile a JOCKY forensic plan.
4. Submit one or more jobs.
5. Agents validate the plan hash before execution.
6. Evidence is archived, optionally encrypted, hashed, and uploaded.
7. The server records job status, audit events, and evidence metadata.

## Validation
Run the core test suite with `pytest`; CI installs the declared dependencies before running the complete suite.
