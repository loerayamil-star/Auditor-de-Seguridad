🇬🇧 English | 🇪🇸 [Español](README.md)

# Security Auditor

Python tool that audits a single code file for hardcoded secrets and static style/security issues, combining the results into one Markdown report.

---

## What it does

Given a `.py` file, `Auditor`:

- Scans for hardcoded secret patterns (`password`, `api_key`, `secret`, `token` assigned in double quotes) with a simple regex.
- Runs [Bandit](https://bandit.readthedocs.io/) on the file and counts the vulnerabilities found.
- Runs [flake8](https://flake8.pycqa.org/) on the file and counts the style findings.
- Combines all three results into a Markdown report with date, repository label, and a per-section summary.

**Current scope: one file per run**, not a full repository. The `repositorio` (repository) value passed to `Auditor` is just a label used in the report header and in the intermediate Bandit/flake8 reports — it does not trigger a recursive scan of the project.

---

## Why I built it

Practice project on a self-taught DevSecOps track: wiring static analysis tools (Bandit, flake8) and basic secret detection into a programmatic flow instead of running them manually. It also serves as a base for understanding subprocess handling, timeouts, and aggregating results from different sources into a single report.

---

## Stack

| Technology | Use |
|------------|-----|
| Python 3 | Base language |
| [Bandit](https://bandit.readthedocs.io/) | Static security analysis |
| [flake8](https://flake8.pycqa.org/) | Style linter (PEP8) |
| `subprocess` | Running Bandit and flake8 as external processes |
| `re` | Secret detection and parsing flake8 output |

---

## Requirements & installation

- Python 3.8 or higher
- `bandit` and `flake8` installed and available on `PATH`

```bash
git clone https://github.com/loerayamil-star/Auditor-de-Seguridad.git
cd Auditor-de-Seguridad
pip install bandit flake8
```

There's no `requirements.txt` yet — Bandit and flake8 are the only external dependencies, and they're invoked as command-line binaries (not imported as libraries).

---

## Basic usage

```python
from auditor import Auditor

auditor = Auditor("my-test-repo")
report = auditor.generar_reporte("archivo_prueba.py")
print(report)
```

`generar_reporte` internally calls `buscar_secretos`, `analizar_con_bandit`, and `analizar_con_flake8` on the same file, and returns Markdown text shaped like this:

```
# Reporte de Auditoría — [my-test-repo]
Fecha: 2026-08-11T22:00:00+00:00
## Secretos: 2
## Bandit: 0
## Flake8: 3
## Dependencias: 0
```

It can also be run directly:

```bash
python auditor.py
```

This runs the example in the `if __name__ == "__main__":` block, which audits `archivo_prueba.py` under the repository label `"mi-repo-de-prueba"`.

If you need the raw data instead of the report text, each internal method is accessible on its own and returns a dict (`analizar_con_bandit`, `analizar_con_flake8`) or leaves its result in `self.secretos` / `self.error_secretos` (`buscar_secretos`).

---

## Known limitations

- **Bandit B607 / B603 (low severity):** `analizar_con_bandit` and `analizar_con_flake8` invoke `bandit` and `flake8` by name (a partial path, resolved via `$PATH`) instead of an absolute path to the executable. Bandit flags this as low severity because, in theory, a compromised `$PATH` could cause a different binary than intended to run. This is an expected trade-off in any wrapper around external binaries, and there's no `shell=True` or string concatenation involved (arguments are passed as a list), so the classic command-injection vector doesn't apply here.
- **`FileNotFoundError` ambiguity:** in `analizar_con_bandit` and `analizar_con_flake8`, the same `except FileNotFoundError` block catches two different situations: (1) the file to audit doesn't exist (explicitly checked with `os.path.exists` before calling `subprocess.run`), and (2) the `bandit` or `flake8` binary isn't installed or isn't on `PATH` (which `subprocess.run` also raises as `FileNotFoundError`). The current report doesn't distinguish between the two — the resulting error message can be misleading when the tool itself is missing rather than the input file.
- **Unhandled `IsADirectoryError` in `buscar_secretos`:** if `ruta_archivo` points to a directory, `open()` raises `IsADirectoryError`, which isn't among the caught exceptions (`FileNotFoundError`, `PermissionError`, `UnicodeDecodeError`) and therefore isn't handled — execution stops with an unhandled traceback. This is inconsistent with `analizar_con_bandit` and `analizar_con_flake8`, which do tolerate a directory argument (both `bandit -r` and `flake8` accept directory paths).
- **`self.dependencias` not implemented:** the report always shows `## Dependencias: 0` because no method in the class populates that list yet. It's a declared but non-functional section — there's no vulnerable-dependency analysis implemented at this point.

---

## Project status

Actively in development, first hands-on experience with Bandit, flake8, and Python subprocess orchestration. The current goal is a correct single-file flow before scaling up to full-repository auditing.
