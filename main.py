# bandit B404: subprocess se usa deliberadamente para invocar git/bandit/
# flake8; todas las llamadas van con lista de argumentos (sin shell=True).
import logging
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit

from fastapi import FastAPI, HTTPException

from auditor import Auditor
from models import AuditoriaHallazgo, AuditoriaRequest, AuditoriaResponse

logger = logging.getLogger(__name__)

app = FastAPI()


def sanear_url(url: str) -> str:
    # query y fragmento tambien pueden llevar tokens
    # si la url no se puede leer se devuelve un marcador y nunca la original
    try:
        partes = urlsplit(url)
        host = partes.hostname
        puerto = partes.port
    except ValueError:
        return "<url-invalida>"
    if not partes.scheme or not host:
        return "<url-invalida>"
    if ":" in host:
        host = f"[{host}]"
    if puerto is not None:
        host = f"{host}:{puerto}"
    return f"{partes.scheme}://{host}{partes.path}"


def ocultar_secretos(texto: str, url: str) -> str:
    # solo atrapa el texto exacto del token asi que se registra lo minimo
    try:
        partes = urlsplit(url)
        credenciales = (partes.username, partes.password)
    except ValueError:
        return "<stderr-omitido>"
    fragmentos = set()
    for credencial in credenciales:
        if credencial:
            fragmentos.add(credencial)
            fragmentos.add(unquote(credencial))
    # primero los mas largos para no dejar restos
    for fragmento in sorted(fragmentos, key=len, reverse=True):
        texto = texto.replace(fragmento, "<secret>")
    return texto


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
            logger.error(
                "Timeout al clonar %s tras %s s",
                sanear_url(str(request.repo)), t.timeout
            )
            raise HTTPException(
            status_code=504,
            detail="Error debido a tiempo de espera",
            )

        if captura_comando.returncode != 0:
            logger.warning(
                "Fallo al clonar: %s",
                ocultar_secretos(captura_comando.stderr, str(request.repo))
            )
            raise HTTPException(
            status_code=400,
            detail="Error al clonar el repositorio",
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
