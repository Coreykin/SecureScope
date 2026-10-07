# SecureScope

SecureScope is a research prototype that scans Python web-application source files for security indicators and maps each finding to a STRIDE threat category. It produces JSON and HTML reports with evidence, severity, explanation, and mitigation guidance.

## Run the prototype

Requires Python 3.10 or newer and no third-party packages.

```bash
python securescope.py sample_app --json sample-report.json --html sample-report.html
```

Run the tests:

```bash
python -m unittest -v test_securescope.py
```

## Current rules

- Debug mode enabled
- Hard-coded secrets
- Weak Flask session-cookie settings
- Insecure HTTP endpoints
- Shell execution
- Dynamic code execution
- Broad cross-origin access
- Unbounded request-body reads

## Research use

The prototype supports a study comparing automated findings with a manual STRIDE review. Suggested measures include true positives, false positives, recall, precision, processing time, and coverage across STRIDE categories.

## Limitations

SecureScope uses pattern matching and does not understand full program behavior, data flow, deployment context, or exploitability. Findings require human review. A clean report does not prove that an application is secure.
