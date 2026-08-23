🇬🇧 English | 🇪🇸 [Español](README.md)

# Security Auditor

Python tool that audits a repository for hardcoded secrets and static style/security issues, combining the results into a structured report. It's exposed both as a library (`Auditor`) and as an HTTP API (`POST /auditoria`, built with FastAPI).

---

## What it does

Given a repository, `Auditor`:

- Scans for hardcoded secret patterns (`password`, `api_key`, `secret`, `token` assigned in double quotes) with a simple regex, walking every `.py` file.
- Runs [Bandit](https://bandit.readthedocs.io/) on the repository and counts the vulnerabilities found.
- Runs [flake8](https://flake8.pycqa.org/) on the repository and counts the style findings.
- Combines all three results into a report with date, repository, and a per-section summary.

The API (`main.py`) clones the repository received in `POST /auditoria` with `git clone --depth 1` into a temp folder, checks that it doesn't exceed 50 MB, runs `Auditor` on that copy, and translates bandit/flake8/secrets into a flat `hallazgos` (findings) list (`AuditoriaHallazgo`) in the JSON response.

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
| [FastAPI](https://fastapi.tiangolo.com/) | HTTP API (`POST /auditoria`) |
| [Pydantic](https://docs.pydantic.dev/) | Request/response validation (`models.py`) |
| [Uvicorn](https://www.uvicorn.org/) | ASGI server for running the API |
| `subprocess` | Running `git clone`, Bandit, and flake8 as external processes |
| `re` | Secret detection and parsing flake8 output |

---

## Requirements & installation

- Python 3.8 or higher
- `git`, `bandit`, and `flake8` installed and available on `PATH` (the API clones the repo with `git`, and `Auditor` resolves `bandit`/`flake8` via `shutil.which`)
- `fastapi`, `uvicorn`, and `pydantic` to run the API

```bash
git clone https://github.com/loerayamil-star/Auditor-de-Seguridad.git
cd Auditor-de-Seguridad
pip install bandit flake8 fastapi uvicorn
```

There's no `requirements.txt` yet. `git`, `bandit`, and `flake8` are invoked as command-line binaries (not imported as libraries); `fastapi`, `pydantic`, and `uvicorn` are regular Python dependencies.

---

## Basic usage

```python
from auditor import Auditor

auditor = Auditor("my-test-repo")
report = auditor.generar_reporte("archivo_prueba.py")
print(report)
```

`generar_reporte` internally calls `buscar_secretos`, `analizar_con_bandit`, and `analizar_con_flake8` on the same path, and returns Markdown text shaped like this:

```
# Reporte de Auditoría — [my-test-repo]
Fecha: 2026-08-23T23:45:43.116730+00:00
## Secretos: 0
## Bandit: 1
## Flake8: 1
## Dependencias: 0
```

`buscar_secretos` walks directories recursively (`os.walk`) looking for `.py` files, so passing it a single file (as in the example above, `archivo_prueba.py` directly) finds no secrets — hence `## Secretos: 0`. Bandit (`-r`) and flake8 both accept either a single file or a directory. To have all three tools analyze the same content, pass a directory (e.g. `"."`).

It can also be run directly:

```bash
python auditor.py
```

This runs the example in the `if __name__ == "__main__":` block, which audits `archivo_prueba.py` under the repository label `"mi-repo-de-prueba"`.

If you need the raw data instead of the report text, each internal method is accessible on its own and returns a dict (`analizar_con_bandit`, `analizar_con_flake8`) or leaves its result in `self.secretos` / `self.error_secretos` (`buscar_secretos`).

---

## HTTP API

Start the server:

```bash
uvicorn main:app --reload
```

### `POST /auditoria`

Clones the received `repo` (`git clone --depth 1`), checks that the clone doesn't exceed 50 MB, runs `Auditor` on it, and returns the combined findings from Bandit, flake8, and secret detection.

**Request**

```bash
curl -X POST http://127.0.0.1:8000/auditoria \
  -H "Content-Type: application/json" \
  -d '{"repo": "https://github.com/user/my-repo"}'
```

`repo` must be a valid `http`/`https` URL (Pydantic `HttpUrl`); cloning fails with `400` if `git clone` can't complete, and with `413` if the cloned repo exceeds 50 MB.

**Response** — `200 OK`

```json
{
    "repo": "https://github.com/user/my-repo",
    "fecha": "2026-08-23T23:43:07.429248Z",
    "hallazgos": [
        {
            "origen": "bandit",
            "severidad": "bajo",
            "mensaje": "Possible hardcoded password: '1234abcd'",
            "linea": 1
        },
        {
            "origen": "flake8",
            "severidad": "bajo",
            "mensaje": "no newline at end of file",
            "linea": 3
        },
        {
            "origen": "secretos",
            "severidad": "alto",
            "mensaje": "Se encontró un posible secreto: password = 1234abcd",
            "linea": 1
        },
        {
            "origen": "secretos",
            "severidad": "alto",
            "mensaje": "Se encontró un posible secreto: api_key = sk-test-12345",
            "linea": 2
        }
    ],
    "estado": "exitoso"
}
```

Each item in `hallazgos` is an `AuditoriaHallazgo`: `origen` (source — `"bandit"`, `"flake8"`, or `"secretos"`), `severidad` (severity — `"bajo"` / `"medio"` / `"alto"`, i.e. low/medium/high), `mensaje` (message), and `linea` (line). Field values stay in Spanish to match the rest of the API's response shape. `estado` is `"fallido"` (failed) if Bandit, flake8, or secret detection ended in error (e.g. tool not found on `PATH`); in that case whatever findings are available are still returned.

---

## Known limitations

- **Bandit B603 (low severity):** `analizar_con_bandit` and `analizar_con_flake8` in `auditor.py`, and the `git clone` call in `main.py`, all call `subprocess.run` — Bandit flags any `subprocess` use as low severity due to the generic risk of command injection. In all three cases the arguments are passed as a list (no `shell=True`), and the executables are resolved with `shutil.which` (not an implicit `$PATH` lookup or user input) or, for `git clone`, the URL is validated by Pydantic (`HttpUrl`, `http`/`https` only). Each mitigation is documented inline in the code, right next to the call it applies to.
- **`FileNotFoundError` ambiguity:** in `analizar_con_bandit` and `analizar_con_flake8`, the same `except FileNotFoundError` block catches two different situations: (1) the path to audit doesn't exist (explicitly checked with `os.path.exists` before calling `subprocess.run`), and (2) the `bandit` or `flake8` binary isn't installed or isn't on `PATH` (which `subprocess.run` also raises as `FileNotFoundError`). The current report doesn't distinguish between the two.
- **`self.dependencias` not implemented:** the report always shows `## Dependencias: 0` because no method in the class populates that list yet. It's a declared but non-functional section — there's no vulnerable-dependency analysis implemented at this point.
- **Fixed size cap:** `Auditor.validar_tamano` rejects any cloned repo over 50 MB (`413`); that limit is hardcoded and not yet configurable through the API.

---

## Project status

The end-to-end flow is functional: `POST /auditoria` clones the repo, runs Bandit/flake8/secret detection, and responds with structured findings (`AuditoriaResponse`). The known limitations above are still open; there's no vulnerable-dependency analysis or `requirements.txt` yet.
