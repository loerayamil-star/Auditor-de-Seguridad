🇪🇸 Español | 🇬🇧 [English](README.en.md)

# Auditor de Seguridad

Herramienta en Python que audita un repositorio en busca de secretos hardcodeados y problemas de estilo/seguridad estática, combinando los resultados en un reporte estructurado. Se expone tanto como librería (`Auditor`) como API HTTP (`POST /auditoria` con FastAPI).

---

## Qué hace

Dado un repositorio, `Auditor`:

- Busca patrones de secretos hardcodeados (`password`, `api_key`, `secret`, `token` asignados entre comillas dobles) con una expresión regular simple, recorriendo todos los archivos `.py`.
- Ejecuta [Bandit](https://bandit.readthedocs.io/) sobre el repositorio y cuenta las vulnerabilidades detectadas.
- Ejecuta [flake8](https://flake8.pycqa.org/) sobre el repositorio y cuenta los hallazgos de estilo.
- Combina los tres resultados en un reporte con fecha, repositorio y resumen por sección.

La API (`main.py`) clona el repositorio recibido en `POST /auditoria` con `git clone --depth 1` a una carpeta temporal, valida que no exceda 50 MB, corre `Auditor` sobre esa copia y traduce bandit/flake8/secretos a una lista plana de `hallazgos` (`AuditoriaHallazgo`) en la respuesta JSON.

---

## Por qué lo hice

Proyecto de práctica en la ruta DevSecOps: integrar herramientas de análisis estático (Bandit, flake8) y detección básica de secretos en un flujo programático, en lugar de correrlas manualmente. También sirve como base para entender manejo de subprocesos, timeouts, y agregación de resultados de distintas fuentes en un solo reporte.

---

## Stack

| Tecnología | Uso |
|------------|-----|
| Python 3 | Lenguaje base |
| [Bandit](https://bandit.readthedocs.io/) | Análisis estático de seguridad |
| [flake8](https://flake8.pycqa.org/) | Linter de estilo (PEP8) |
| [FastAPI](https://fastapi.tiangolo.com/) | API HTTP (`POST /auditoria`) |
| [Pydantic](https://docs.pydantic.dev/) | Validación de request/response (`models.py`) |
| [Uvicorn](https://www.uvicorn.org/) | Servidor ASGI para levantar la API |
| `subprocess` | Ejecución de `git clone`, Bandit y flake8 como procesos externos |
| `re` | Detección de secretos y parseo de la salida de flake8 |

---

## Requisitos e instalación

- Python 3.8 o superior
- `git`, `bandit` y `flake8` instalados y disponibles en el `PATH` (la API clona el repo con `git` y `Auditor` resuelve `bandit`/`flake8` vía `shutil.which`)
- `fastapi`, `uvicorn` y `pydantic` para levantar la API

```bash
git clone https://github.com/loerayamil-star/Auditor-de-Seguridad.git
cd Auditor-de-Seguridad
pip install bandit flake8 fastapi uvicorn
```

No hay un `requirements.txt` todavía. `git`, `bandit` y `flake8` se invocan como binarios de línea de comandos (no como librerías importadas); `fastapi`, `pydantic` y `uvicorn` sí son dependencias de Python normales.

---

## Uso básico

```python
from auditor import Auditor

auditor = Auditor("mi-repo-de-prueba")
reporte = auditor.generar_reporte("archivo_prueba.py")
print(reporte)
```

`generar_reporte` internamente llama a `buscar_secretos`, `analizar_con_bandit` y `analizar_con_flake8` sobre la misma ruta, y devuelve un texto Markdown con esta forma:

```
# Reporte de Auditoría — [mi-repo-de-prueba]
Fecha: 2026-08-23T23:45:43.116730+00:00
## Secretos: 0
## Bandit: 1
## Flake8: 1
## Dependencias: 0
```

`buscar_secretos` recorre directorios recursivamente (`os.walk`) buscando archivos `.py`, así que si le pasas un archivo individual (como en el ejemplo, `archivo_prueba.py` directamente) no encuentra secretos — de ahí el `## Secretos: 0`. Bandit (`-r`) y flake8 sí aceptan tanto un archivo suelto como una carpeta. Para que las tres herramientas analicen el mismo contenido, pasa una carpeta (por ejemplo `"."`).

También se puede ejecutar directamente:

```bash
python auditor.py
```

Esto corre el ejemplo del bloque `if __name__ == "__main__":`, que audita `archivo_prueba.py` bajo el nombre de repositorio `"mi-repo-de-prueba"`.

Si necesitas los datos crudos en vez del texto del reporte, cada método interno es accesible por separado y devuelve un diccionario (`analizar_con_bandit`, `analizar_con_flake8`) o deja el resultado en `self.secretos` / `self.error_secretos` (`buscar_secretos`).

---

## API HTTP

Levantar el servidor:

```bash
uvicorn main:app --reload
```

### `POST /auditoria`

Clona el `repo` recibido (`git clone --depth 1`), valida que la copia no supere 50 MB, corre `Auditor` sobre ella y devuelve los hallazgos combinados de Bandit, flake8 y detección de secretos.

**Request**

```bash
curl -X POST http://127.0.0.1:8000/auditoria \
  -H "Content-Type: application/json" \
  -d '{"repo": "https://github.com/usuario/mi-repo"}'
```

`repo` debe ser una URL `http`/`https` válida (Pydantic `HttpUrl`); el clonado falla con `400` si `git clone` no puede completarse, y con `413` si el repo clonado excede 50 MB.

**Response** — `200 OK`

```json
{
    "repo": "https://github.com/usuario/mi-repo",
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

Cada elemento de `hallazgos` es un `AuditoriaHallazgo`: `origen` (`"bandit"`, `"flake8"` o `"secretos"`), `severidad` (`"bajo"` / `"medio"` / `"alto"`), `mensaje` y `linea`. `estado` es `"fallido"` si Bandit, flake8 o la búsqueda de secretos terminaron en error (por ejemplo, herramienta no encontrada en el `PATH`); en ese caso los hallazgos disponibles igual se devuelven.

---

## Limitaciones conocidas

- **Bandit B603 (severidad baja):** `analizar_con_bandit` y `analizar_con_flake8` en `auditor.py`, y el `git clone` en `main.py`, llaman a `subprocess.run` — Bandit marca cualquier uso de `subprocess` como hallazgo de baja severidad por el riesgo genérico de inyección de comandos. En los tres casos los argumentos van en lista (sin `shell=True`), y los ejecutables se resuelven con `shutil.which` (no por `$PATH` implícito ni entrada de usuario) o, en el caso de `git clone`, la URL viene validada por Pydantic (`HttpUrl`, solo `http`/`https`). El detalle de cada mitigación está documentado en el propio código, junto a cada llamada.
- **Ambigüedad en `FileNotFoundError`:** en `analizar_con_bandit` y `analizar_con_flake8`, el mismo bloque `except FileNotFoundError` captura dos situaciones distintas: (1) la ruta que se quiere auditar no existe (verificado explícitamente con `os.path.exists` antes de llamar a `subprocess.run`), y (2) el binario `bandit` o `flake8` no está instalado o no está en el `PATH` (que `subprocess.run` también señaliza con `FileNotFoundError`). El reporte actual no distingue entre ambos casos.
- **`self.dependencias` sin implementar:** el reporte siempre muestra `## Dependencias: 0` porque ningún método de la clase pobla esa lista todavía. Es una sección declarada pero no funcional — no hay análisis de dependencias vulnerables implementado por ahora.
- **Tamaño máximo fijo:** `Auditor.validar_tamano` rechaza cualquier repo clonado que exceda 50 MB (`413`); ese límite está hardcodeado y no es configurable vía la API todavía.

---

## Estado del proyecto

El flujo de punta a punta está funcional: `POST /auditoria` clona el repo, corre Bandit/flake8/detección de secretos y responde con hallazgos estructurados (`AuditoriaResponse`). Las limitaciones conocidas de arriba siguen abiertas; no hay análisis de dependencias vulnerables ni `requirements.txt` todavía.
