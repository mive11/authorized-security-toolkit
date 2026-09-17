# Guía para presentar el proyecto en tu CV

## Qué has construido

Este repositorio contiene cuatro herramientas pequeñas y terminadas para trabajo de seguridad autorizado. Juntas demuestran algo más útil en una entrevista que una colección de scripts sin pruebas: control de alcance, inventario pasivo, validación de telemetría y creación reproducible de informes.

La demo es completamente sintética y no necesita red:

```bash
python3 scripts/test_all.py
python3 scripts/portfolio_demo.py
```

## Texto listo para el CV

### Versión corta en español

> Desarrollé una suite de seguridad autorizada en Python y Bash con control de alcance *fail closed*, inventario pasivo mediante CT/archivos/RDAP, validación de telemetría Windows mapeada a MITRE ATT&CK e informes deterministas Markdown/SARIF. Incluí fixtures sintéticas, redacción de secretos, trazabilidad de evidencia y pruebas automatizadas de límites y fallos.

### Short English version

> Built a Python/Bash authorized-security toolkit covering fail-closed target scoping, passive CT/archive/RDAP asset inventory, ATT&CK-mapped Windows telemetry validation, and deterministic Markdown/SARIF reporting. Added synthetic fixtures, secret redaction, evidence provenance, and automated boundary/failure tests.

No pongas «FUD», «indetectable» ni porcentajes de evasión. Son afirmaciones difíciles de demostrar y hacen que el proyecto parezca menos riguroso. Enseña en su lugar una amenaza concreta, el control implementado y una prueba reproducible.

## Cómo enseñarlo en GitHub o LinkedIn

Un buen vídeo o carrusel puede seguir este orden:

1. Ejecuta `python3 scripts/test_all.py` y muestra el total de pruebas.
2. Ejecuta `python3 scripts/portfolio_demo.py` con los datos sintéticos.
3. Abre una decisión permitida y otra denegada de ScopeGuard.
4. Enseña cómo Telemetry Validator marca una señal ausente sin afirmar que hubo un bypass.
5. Abre el Markdown y el SARIF generados por ReportForge.
6. Explica un límite real: los datos pasivos son incompletos y la presencia de eventos no prueba por sí sola que una detección sea eficaz.

Texto sugerido para una publicación:

> I built an authorized security portfolio toolkit around four controls that are easy to overlook: scope enforcement, passive evidence collection, telemetry validation, and reproducible reporting. The repository includes synthetic fixtures and automated tests, so the demo is repeatable without targeting a live system. My main design choice was to preserve uncertainty: a provider failure is never reported as zero assets, and a missing event is evidence of a collection gap, not proof of an EDR bypass.

## Preguntas que podrás responder en una entrevista

- ¿Por qué una regla `deny` debe tener prioridad sobre una regla `allow`?
- ¿Cómo impides que `example.com.attacker.test` pase un control de sufijo?
- ¿Qué diferencia hay entre observar un nombre en Certificate Transparency y confirmar un host activo?
- ¿Cómo distingues una señal ausente de un archivo de eventos inválido o incompleto?
- ¿Cómo evitas filtrar tokens dentro de URLs o evidencias?
- ¿Por qué un informe determinista facilita la revisión y la integración continua?
- ¿Qué puede y qué no puede demostrar una cadena hash local de auditoría?

## Próximas ampliaciones con valor profesional

El orden recomendado está en [PORTFOLIO.md](PORTFOLIO.md). Las tres siguientes con mejor equilibrio entre valor y esfuerzo son: un linter de reglas Sigma, un analizador offline de PCAP para exposición de protocolos y un correlador local de SBOM con vulnerabilidades. Cada una debería conservar el mismo estándar: contrato de entrada estricto, datos sintéticos, límites de recursos, salidas privadas y pruebas de error.
