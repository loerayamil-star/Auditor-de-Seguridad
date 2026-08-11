🇪🇸 Español | 🇬🇧 [English](README.en.md)

# Auditor de Seguridad

Herramienta en Python que audita un archivo de código en busca de secretos hardcodeados y problemas de estilo/seguridad estática, combinando los resultados en un solo reporte en Markdown.

---

## Qué hace

Dado un archivo `.py`, `Auditor`:

- Busca patrones de secretos hardcodeados (`password`, `api_key`, `secret`, `token` asignados entre comillas dobles) con una expresión regular simple.
- Ejecuta [Bandit](https://bandit.readthedocs.io/) sobre el archivo y cuenta las vulnerabilidades detectadas.
- Ejecuta [flake8](https://flake8.pycqa.org/) sobre el archivo y cuenta los hallazgos de estilo.
- Combina los tres resultados en un reporte Markdown con fecha, repositorio y resumen por sección.

**Alcance actual: un solo archivo por corrida**, no un repositorio completo. El nombre `repositorio` que recibe `Auditor` es solo una etiqueta para el reporte (aparece en el encabezado y en los reportes intermedios de Bandit/flake8) — no dispara un escaneo recursivo del proyecto.

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
| `subprocess` | Ejecución de Bandit y flake8 como procesos externos |
| `re` | Detección de secretos y parseo de la salida de flake8 |

---

## Requisitos e instalación

- Python 3.8 o superior
- `bandit` y `flake8` instalados y disponibles en el `PATH`

```bash
git clone https://github.com/loerayamil-star/Auditor-de-Seguridad.git
cd Auditor-de-Seguridad
pip install bandit flake8
```

No hay un `requirements.txt` todavía — Bandit y flake8 son las únicas dependencias externas, y se invocan como binarios de línea de comandos (no como librerías importadas).

---

## Uso básico

```python
from auditor import Auditor

auditor = Auditor("mi-repo-de-prueba")
reporte = auditor.generar_reporte("archivo_prueba.py")
print(reporte)
```

`generar_reporte` internamente llama a `buscar_secretos`, `analizar_con_bandit` y `analizar_con_flake8` sobre el mismo archivo, y devuelve un texto Markdown con esta forma:

```
# Reporte de Auditoría — [mi-repo-de-prueba]
Fecha: 2026-08-11T22:00:00+00:00
## Secretos: 2
## Bandit: 0
## Flake8: 3
## Dependencias: 0
```

También se puede ejecutar directamente:

```bash
python auditor.py
```

Esto corre el ejemplo del bloque `if __name__ == "__main__":`, que audita `archivo_prueba.py` bajo el nombre de repositorio `"mi-repo-de-prueba"`.

Si necesitas los datos crudos en vez del texto del reporte, cada método interno es accesible por separado y devuelve un diccionario (`analizar_con_bandit`, `analizar_con_flake8`) o deja el resultado en `self.secretos` / `self.error_secretos` (`buscar_secretos`).

---

## Limitaciones conocidas

- **Bandit B607 / B603 (severidad baja):** `analizar_con_bandit` y `analizar_con_flake8` invocan `bandit` y `flake8` por nombre (ruta parcial, resuelta vía `$PATH`) en lugar de una ruta absoluta al ejecutable. Bandit lo marca como hallazgo de baja severidad porque, en teoría, un `$PATH` comprometido podría hacer que se ejecute un binario distinto al esperado. Es un riesgo esperable en cualquier wrapper que invoca binarios externos, y aquí no hay `shell=True` ni concatenación de strings de por medio (los argumentos van en lista), así que el vector de inyección de comandos clásico no aplica.
- **Ambigüedad en `FileNotFoundError`:** en `analizar_con_bandit` y `analizar_con_flake8`, el mismo bloque `except FileNotFoundError` captura dos situaciones distintas: (1) el archivo que se quiere auditar no existe (verificado explícitamente con `os.path.exists` antes de llamar a `subprocess.run`), y (2) el binario `bandit` o `flake8` no está instalado o no está en el `PATH` (que `subprocess.run` también señaliza con `FileNotFoundError`). El reporte actual no distingue entre ambos casos — el mensaje de error resultante puede ser engañoso si lo que falta es la herramienta y no el archivo.
- **`IsADirectoryError` no manejado en `buscar_secretos`:** si `ruta_archivo` apunta a un directorio, `open()` lanza `IsADirectoryError`, que no está entre las excepciones capturadas (`FileNotFoundError`, `PermissionError`, `UnicodeDecodeError`) y por lo tanto no se maneja — la ejecución se interrumpe con una traza sin controlar. Esto es inconsistente con `analizar_con_bandit` y `analizar_con_flake8`, que sí toleran un directorio como argumento (tanto `bandit -r` como `flake8` aceptan rutas de directorio).
- **`self.dependencias` sin implementar:** el reporte siempre muestra `## Dependencias: 0` porque ningún método de la clase pobla esa lista todavía. Es una sección declarada pero no funcional — no hay análisis de dependencias vulnerables implementado por ahora.

---

## Estado del proyecto

En desarrollo activo, primer contacto con Bandit, flake8 y orquestación de subprocesos en Python. El objetivo por ahora es tener un flujo correcto para un archivo individual antes de escalar a auditoría de repositorio completo.
