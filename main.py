import subprocess
import tempfile

from fastapi import FastAPI, HTTPException

from auditor import Auditor
from models import AuditoriaHallazgo, AuditoriaRequest

app = FastAPI()


def traducir_a_hallazgos(
    bandit_data, flake8_data, secretos_data
) -> list[AuditoriaHallazgo]:
    hallazgos = []
    return hallazgos


@app.post("/auditoria")
def crear_auditoria(request: AuditoriaRequest):
    carpeta_destino = tempfile.mkdtemp()
    # request.repo es un HttpUrl validado por Pydantic (solo http/https),
    # y subprocess.run recibe la URL como un elemento de lista completo
    # (no usa shell=True), así que no puede inyectar flags ni comandos.
    comando = [
        "git", "clone", "--depth", "1", str(request.repo), carpeta_destino
    ]
    captura_comando = subprocess.run(
        comando, capture_output=True, text=True, check=False, timeout=60
    )
    if captura_comando.returncode != 0:
        raise HTTPException(
            status_code=400,
            detail=f"Error al clonar el repositorio: {captura_comando.stderr}",
        )

    es_valido, mensaje_error = Auditor.validar_tamano(carpeta_destino)

    if not es_valido:
        raise HTTPException(status_code=413, detail=mensaje_error)

    auditor = Auditor(str(request.repo))
    reporte = auditor.generar_reporte(carpeta_destino)
    return reporte
