# Política de seguridad

Auditor-de-Seguridad es un proyecto **educativo** y personal. No está pensado para producción y no ofrece garantías de seguridad. Aun así, si encuentras un problema real, quiero enterarme.

## Versiones con soporte

Solo la rama `main`. No hay versiones publicadas ni ramas antiguas que reciban correcciones.

## Cómo reportar una vulnerabilidad

Usa los **avisos privados de seguridad de GitHub**:

1. Entra a la pestaña **Security** del repositorio.
2. Pulsa **Report a vulnerability**.
3. Describe qué pasa, cómo reproducirlo y qué impacto tiene.

**No abras un issue público** para una vulnerabilidad: así la información queda visible antes de que exista una corrección.

## Qué puedes esperar

- Acuse de recibo en un máximo de **3 días**.
- Después te cuento si lo considero una vulnerabilidad válida y qué planeo hacer. Por ser un proyecto personal no prometo un plazo fijo de corrección.

## Qué sí está en alcance

- Formas de que `POST /auditoria` ejecute comandos o lea archivos fuera del repositorio clonado.
- Fugas de secretos completos en las respuestas o en los reportes.
- Evasión del timeout o del límite de tamaño de 50 MB que permita agotar recursos.

## Fuera de alcance (ya documentado como limitación)

- Que el detector de secretos sea heurístico: solo revisa archivos `.py` y solo comillas dobles. Ver "Limitaciones conocidas" en el [README](README.md).
- Los avisos de Bandit B603/B404 sobre `subprocess`, ya explicados en el README y en el código.
- Problemas que solo aparecen si alguien expone la API públicamente sin autenticación ni límites propios; no está diseñada para eso.
- Vulnerabilidades en dependencias de terceros sin un impacto demostrable en este proyecto.
