import datetime
import json
import os
import re
import shutil
import subprocess
import textwrap
from typing import Literal

from pydantic import BaseModel, HttpUrl


class Auditor:
    def __init__(self, repo):
        self.repo = repo
        self.fecha = datetime.datetime.now(datetime.timezone.utc)
        self.secretos = []
        self.bandit = {}
        self.flake8 = {}
        self.dependencias = []
        self.error_secretos = None
        self.ruta_bandit = shutil.which("bandit")
        self.ruta_flake8 = shutil.which("flake8")

    def buscar_secretos(self, ruta_archivo):
        self.secretos = []
        self.error_secretos = None
        patron = r'(password|api_key|secret|token)\s*=\s*"([^"]+)"'
        try:
            with open(ruta_archivo, "r") as f:
                for numero_linea, linea in enumerate(f, start=1):
                    resultado = re.search(patron, linea)
                    if resultado:
                        self.secretos.append(
                            (numero_linea, resultado.group(1),
                             resultado.group(2))
                        )
        except FileNotFoundError:
            self.error_secretos = (
                f"Error: el archivo {ruta_archivo} no existe."
            )
            return
        except PermissionError:
            self.error_secretos = (
                f"Error: no se tiene permiso para leer el archivo "
                f"{ruta_archivo}."
            )
            return
        except UnicodeDecodeError:
            self.error_secretos = (
                f"Error al leer el archivo {ruta_archivo}: no se puede "
                f"decodificar como UTF-8."
            )
            return

    def analizar_con_bandit(self, ruta_archivo):
        reporte_general = {}
        try:
            if self.ruta_bandit is None:
                return {
                    "repositorio": self.repo,
                    "fecha": self.fecha.isoformat(),
                    "error": (
                        "Bandit no está instalado o no se encontró "
                        "en el PATH."
                    ),
                    "vulnerabilidades": None,
                    "secretos": None,
                    "return_code": 1
                }

            if not os.path.exists(ruta_archivo):
                raise FileNotFoundError(
                    f"El archivo {ruta_archivo} no existe."
                )
            captura = subprocess.run(
                [self.ruta_bandit, "-r", ruta_archivo, "-f", "json"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30
            )
            reporte_general = json.loads(captura.stdout)
            reporte_general = {
                "repositorio": self.repo,
                "fecha": self.fecha.isoformat(),
                "bandit": reporte_general,
                "vulnerabilidades": len(reporte_general.get("results", [])),
                "secretos": len(self.secretos),
                "return_code": captura.returncode
            }
            return reporte_general
        except FileNotFoundError as f:
            return {
                "repositorio": self.repo,
                "fecha": self.fecha.isoformat(),
                "error": f"Error al ejecutar Bandit: {f}",
                "vulnerabilidades": None,
                "secretos": None,
                "return_code": 1
            }
        except json.JSONDecodeError as j:
            return {
                "repositorio": self.repo,
                "fecha": self.fecha.isoformat(),
                "error": f"Error al ejecutar Bandit: {j}",
                "vulnerabilidades": None,
                "secretos": None,
                "return_code": 1
            }
        except subprocess.TimeoutExpired as t:
            return {
                "repositorio": self.repo,
                "fecha": self.fecha.isoformat(),
                "error": f"Error al ejecutar Bandit: {t}",
                "vulnerabilidades": None,
                "secretos": None,
                "return_code": 1
            }

    def analizar_con_flake8(self, ruta_archivo):
        error_flake = r"([^:]+):(\d+):(\d+): ([A-Z]\d+) (.*)"
        try:
            if self.ruta_flake8 is None:
                return {
                    "repositorio": self.repo,
                    "fecha": self.fecha.isoformat(),
                    "error": (
                        "Flake8 no está instalado o no se encontró "
                        "en el PATH."
                    ),
                    "flake8": None,
                    "errores": None,
                    "return_code": 1
                }

            if not os.path.exists(ruta_archivo):
                raise FileNotFoundError(
                    f"El archivo {ruta_archivo} no existe."
                )
            captura = subprocess.run(
                [self.ruta_flake8, ruta_archivo],
                capture_output=True,
                text=True,
                check=False,
                timeout=30
            )
            hallazgos = re.findall(error_flake, captura.stdout)
            return {
                    "repositorio": self.repo,
                    "fecha": self.fecha.isoformat(),
                    "flake8": hallazgos,
                    "errores": len(hallazgos),
                    "return_code": captura.returncode
                }
        except FileNotFoundError as f:
            return {
                "repositorio": self.repo,
                "fecha": self.fecha.isoformat(),
                "error": f"Error al ejecutar Flake8: {f}",
                "errores": None,
                "return_code": 1
            }
        except subprocess.TimeoutExpired as t:
            return {
                "repositorio": self.repo,
                "fecha": self.fecha.isoformat(),
                "error": f"Error al ejecutar Flake8: {t}",
                "errores": None,
                "return_code": 1
            }

    def generar_reporte(self, ruta_archivo):
        self.buscar_secretos(ruta_archivo)
        self.bandit = self.analizar_con_bandit(ruta_archivo)
        self.flake8 = self.analizar_con_flake8(ruta_archivo)

        if "error" in self.bandit:
            bandit_resumen = "ERROR - [" + self.bandit.get("error") + "]"
        else:
            bandit_resumen = self.bandit.get("vulnerabilidades", 0) or 0
        if "error" in self.flake8:
            flake8_resumen = "ERROR - [" + self.flake8.get("error") + "]"
        else:
            flake8_resumen = self.flake8.get("errores", 0) or 0
        if self.error_secretos is not None:
            secretos_resumen = "ERROR - [" + self.error_secretos + "]"
        else:
            secretos_resumen = len(self.secretos)

        return textwrap.dedent(f"""\
            # Reporte de Auditoría — [{self.repo}]
            Fecha: {self.fecha.isoformat()}
            ## Secretos: {secretos_resumen}
            ## Bandit: {bandit_resumen}
            ## Flake8: {flake8_resumen}
            ## Dependencias: {len(self.dependencias)}""")


class AuditoriaRequest(BaseModel):
    repo: HttpUrl
    parametros: list[str] = ["bandit", "flake8", "secretos"]


class AuditoriaHallazgo(BaseModel):
    origen: str
    severidad: Literal["bajo", "medio", "alto"]
    mensaje: str
    linea: int


class AuditoriaResponse(BaseModel):
    repo: HttpUrl
    fecha: datetime.datetime
    hallazgos: list[AuditoriaHallazgo]
    estado: Literal["exitoso", "fallido"]


if __name__ == "__main__":
    auditor = Auditor("mi-repo-de-prueba")
    print(auditor.generar_reporte("archivo_prueba.py"))
