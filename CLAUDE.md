# CLAUDE.md — Auditor-de-Seguridad

Instrucciones para Claude Code en este repositorio. Es un proyecto educativo de Yamil (estudiante de prepa, ruta DevSecOps). El objetivo no es solo que funcione, sino que Yamil entienda y pueda defender cada decisión en una entrevista.

## Qué es

Herramienta en Python que audita un repositorio: busca secretos hardcodeados (regex), corre Bandit y flake8 como procesos externos, y combina todo en un reporte. Se usa como librería (`auditor.py`, clase `Auditor`) y como API (`main.py`, `POST /auditoria` con FastAPI; modelos Pydantic en `models.py`).

## Estado real (verificado, no asumir más)

- No hay tests ni CI todavía (no existe `tests/` ni `.github/`).
- `requirements.txt` existe pero no incluye `bandit` ni `flake8`, que el código invoca como binarios vía `shutil.which`. El README todavía dice "No hay un requirements.txt". Son pendientes conocidos, no los "arregles" por tu cuenta: avisa y propón.
- El detector de secretos es heurístico y educativo: solo `.py`, solo comillas dobles. No lo presentes como secret scanning completo.
- `self.dependencias` no está implementado (el reporte siempre dice 0).
- El campo `parametros` de `AuditoriaRequest` no se usa en `main.py`.

## Comandos

```bash
pip install -r requirements.txt   # más bandit y flake8 en el PATH
uvicorn main:app --reload         # levantar la API
python auditor.py                 # ejemplo local sobre archivo_prueba.py
ruff check .                      # lint (ruff está en requirements.txt)
```

Antes de proponer cualquier cambio de código, corre `ruff check .` y confirma que no empeora. No inventes comandos de tests: todavía no hay.

## Reglas duras

1. **Commits y PRs sin atribución de IA.** No añadas `Co-Authored-By`, ni "Generated with Claude Code", ni enlaces de sesión en commits, descripciones de PR o archivos.
2. **Nunca** pongas IPs reales, tokens, contraseñas ni datos del homelab en el repo, en commits ni en la salida. Para ejemplos usa `192.0.2.0/24` y valores falsos evidentes.
3. **Nunca imprimas un secreto completo.** El reporte debe mostrar solo el nombre y un prefijo corto (como hace hoy `main.py`), y la documentación tampoco debe mostrar valores reales.
4. **No empujes a `main`.** Trabaja en una rama y abre un PR; Yamil revisa y hace el merge.
5. **Un commit = una intención.** Formato `tipo(alcance): descripción`, todo en español y con el verbo en presente ("agrega", "corrige"). Tipos: feat, fix, docs, test, ci, refactor, security, chore. Ejemplo: `ci(auditor): agrega workflow de ruff y bandit`. Títulos y descripciones de PR, y mensajes de merge, también en español.
6. **No mezcles** traducción, refactor y cambios de seguridad en el mismo PR.
7. **Dependencias nuevas** solo con versión fijada y avisando por qué. Acciones de GitHub fijadas a un SHA completo y `permissions: contents: read` al inicio del workflow.

## Qué puede hacer Claude y qué no

Automatizable (hazlo por PR): archivos de plantilla y configuración (`.gitignore`, `SECURITY.md`, `CONTRIBUTING.md`, `dependabot.yml`), un workflow de CI pequeño una vez que Yamil defina los checks, corregir enlaces y traducciones de un README ya estable.

Lo decide y lo escribe Yamil (explica, haz preguntas guiadas, revisa lo que él escriba, pero no escribas la solución): alcance del detector de secretos, qué amenazas cubre el Auditor y qué severidad se asigna, diseño de los tests, controles del endpoint de clonado, qué cuenta como "workflow exitoso", y si un fallo de dependencia bloquea el CI. Si la tarea responde a "¿qué comportamiento debe tener y por qué?", es de él.

## Zonas que no se tocan sin preguntar primero

- El clonado en `main.py` (`git clone`, timeout, validación de URL, límite de 50 MB).
- La lógica de `buscar_secretos` y el mapa de severidades.
- Las llamadas a `subprocess` (argumentos siempre en lista, nunca `shell=True`, ejecutables vía `shutil.which`).
- Los comentarios `bandit B404/B603`: documentan decisiones, no los borres.

## Estilo

Código y comentarios en español, nombres como ya están en el repo. Comentarios solo para decisiones no obvias (por qué, no qué). Respuestas y explicaciones en español, directas y sin relleno.
