# bandit B404: subprocess se usa deliberadamente para invocar git/bandit/
# flake8; todas las llamadas van con lista de argumentos (sin shell=True).
import subprocess
import tempfile

from fastapi import FastAPI, HTTPException

from auditor import Auditor
from models import AuditoriaHallazgo, AuditoriaRequest, AuditoriaResponse

app = FastAPI()


def traducir_a_hallazgos(
    bandit_data, flake8_data, secretos_data
) -> list[AuditoriaHallazgo]:
    hallazgos = []
    mapa_severidad_bandit = {"LOW": "bajo", "MEDIUM": "medio", "HIGH": "alto"}
    mapa_severidad_flake8 = {
        "E": "medio", "W": "bajo", "F": "alto", "C": "medio"
    }

    if "bandit" in bandit_data:
        for resultado in bandit_data["bandit"]["results"]:
            hallazgos.append(AuditoriaHallazgo(
                origen="bandit",
                severidad=mapa_severidad_bandit[resultado["issue_severity"]],
                mensaje=resultado["issue_text"],
                linea=resultado["line_number"]
            ))

    if "flake8" in flake8_data:
        for resultado in flake8_data["flake8"]:
            hallazgos.append(AuditoriaHallazgo(
                origen="flake8",
                severidad=mapa_severidad_flake8[resultado[3][0:1]],
                mensaje=resultado[4],
                linea=int(resultado[1]),
            ))

    for resultado in secretos_data:
        hallazgos.append(AuditoriaHallazgo(
            origen="secretos",
            severidad="alto",
            mensaje=(
                f"Se encontró un posible secreto: {resultado[2]} = {resultado[3][0:4]}..."
            ),
            linea=resultado[1],
        ))

    return hallazgos


@app.post("/auditoria")
def crear_auditoria(request: AuditoriaRequest):
    with tempfile.TemporaryDirectory() as carpeta_destino:
        
    
        # bandit B603: request.repo es un HttpUrl validado por Pydantic (solo
        # http/https), y subprocess.run recibe la URL como un elemento de lista
        # completo (no usa shell=True), así que no puede inyectar flags ni
        # comandos.
        comando = [
            "git", "clone", "--depth", "1", str(request.repo), carpeta_destino
        ]
        try:
            captura_comando = subprocess.run(
                comando, capture_output=True, text=True, check=False, timeout=60
            )
        except subprocess.TimeoutExpired as t:
            raise HTTPException(
                status_code=504,
                detail=f"Error debido a tiempo de espera: {t}",
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
        auditor.generar_reporte(carpeta_destino)

        if (
            auditor.error_secretos is not None
            or "error" in auditor.bandit
            or "error" in auditor.flake8
        ):
            estado = "fallido"
        else:
            estado = "exitoso"

        hallazgos = traducir_a_hallazgos(
            auditor.bandit, auditor.flake8, auditor.secretos
        )

    return AuditoriaResponse(
        repo=request.repo,
        fecha=auditor.fecha,
        hallazgos=hallazgos,
        estado=estado,
    )
