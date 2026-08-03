import datetime
import re


class Auditor:
    def __init__(self, repo):
        self.repo = repo
        self.fecha = datetime.datetime.now(datetime.timezone.utc)
        self.secretos = []
        self.bandit = []
        self.flake8 = []
        self.dependencias = []

    def buscar_secretos(self, ruta_archivo):
        with open(ruta_archivo, "r") as f:
            contenido = f.read()
            secretos_encontrados = re.findall(r'(password|api_key|secret|token)\s*=\s*"([^"]+)"', contenido)
            self.secretos.extend(secretos_encontrados)