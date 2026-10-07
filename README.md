# SecureScope

SecureScope 0.2.0 is a research prototype that scans Python web-application source for security indicators and maps findings to STRIDE categories. It reads files without importing or executing the target application. Findings require human review.

Repository: https://github.com/Coreykin/SecureScope

## Download and run

On GitHub, select **Code > Download ZIP**, extract the archive, and open a terminal in the extracted SecureScope folder. Requires Python 3.10 or newer. No third-party packages are needed, including Flask: the demonstration application is read as source code only.

```bash
python securescope.py sample_app --json sample-report.json --html sample-report.html --csv sample-report.csv
```

On systems where Python is named `python3`, use `python3` instead. On Windows, `py` may be the installed launcher.

Open `sample-report.html` in a browser to review findings. JSON and CSV support analysis. Report destinations must be distinct and outside the scanned directory. Their parent folders are created automatically.

Run verification:

```bash
python -m unittest -v test_securescope.py
python securescope.py --version
```

## Changes in version 0.2.0

- Python syntax analysis recognizes indexed Flask settings, config.update calls, and multiline calls.
- Python comments and ordinary documentation strings no longer produce code-execution or configuration findings.
- Wildcard CORS routes with explicitly trusted origins are distinguished from wildcard origins.
- HTTP loopback exclusions use the exact hostname.
- Reports withhold raw source content for every finding to reduce credential leakage. Review the specified source file and line for evidence.
- Optional CSV export includes all finding fields and neutralizes spreadsheet formula prefixes.
- HTML includes rule identifiers, explanations, recommendations, and a clear empty-result message.
- Invalid Python syntax stops the scan with a file and line error, rather than silently generating an incomplete report.

## Current rules

| ID | Indicator | STRIDE category | Severity |
| --- | --- | --- | --- |
| SS001 | Debug mode enabled | Information Disclosure | High |
| SS002 | Literal secret in a recognized setting | Information Disclosure | Critical |
| SS003 | Disabled Secure or HttpOnly session-cookie setting | Spoofing | High |
| SS004 | Literal HTTP URL outside loopback hosts | Information Disclosure | Medium |
| SS005 | subprocess call with shell=True | Elevation of Privilege | High |
| SS006 | eval or exec call | Tampering | Critical |
| SS007 | Explicit wildcard CORS origins | Spoofing | Medium |
| SS008 | request.data or request.get_data | Denial of Service | Medium |

STRIDE labels and severity are preliminary rule mappings, not proof of exploitation. A request-body read may be safe when deployment limits exist; shell execution and dynamic execution need input/context review. Broad CORS does not by itself prove an authentication bypass.

## Verified demonstration

The included `sample_app/app.py` intentionally contains insecure settings. The reproduced scan generates **four findings**: one hard-coded secret, two disabled cookie protections, and one debug-mode finding. The sample reports are generated from this exact source. **All 24 automated tests pass**, covering each rule, safe configurations, multiline syntax, output formats, secret withholding, and error behavior. These checks establish bounded prototype behavior, not measured precision or recall on real projects.

## Research evaluation

Compare automated findings with a documented manual review at fixed repository commits. Record true positives, false positives, missed threats, scan time, and per-rule/STRIDE coverage. Report recall within supported rule scope separately from broader architectural-threat coverage.

## Limitations

Python analysis uses syntax trees, not dataflow or type analysis. It does not resolve imported aliases, variable-derived configuration values, indirect function calls, application trust boundaries, deployment settings, or exploitability. For example, `from subprocess import run` is not recognized by the current subprocess rule. The cookie rule reports explicit disabled settings, not missing settings. CORS coverage focuses on explicit wildcard forms. Secrets embedded in compound expressions or unrecognized key names may be missed.

Non-Python text/config files retain limited line-pattern matching. Unsupported extensions, unreadable/non-UTF-8 files, symlink files, and common dependency/build folders are skipped. Python syntax must be compatible with the interpreter running the scanner. Reports are not a complete file-coverage inventory. There is no Repudiation rule. A clean report does not prove that software is secure.

Do not scan sensitive repositories merely to publish their reports: filenames and target paths remain visible even though raw source is withheld.
