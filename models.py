import datetime
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


class AuditoriaRequest(BaseModel):
    repo: HttpUrl
    parametros: list[str] = Field(default_factory=lambda: ["bandit", "flake8", "secretos"])


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
