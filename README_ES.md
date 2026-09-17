# Authorized Security Toolkit

Suite pública de cuatro herramientas para evaluaciones de seguridad autorizadas, centrada en controles que suelen faltar en scripts aislados: alcance, procedencia de evidencia, validación de telemetría y generación reproducible de informes.

[English README](README.md) · [Texto para CV](CV_TEXT_ES_EN.md) · [Arquitectura](ARCHITECTURE.md)

## Proyectos incluidos

| Proyecto | Qué demuestra | Red |
|---|---|---|
| [Passive Domain Inventory](tools/passive-domain-inventory/) | Inventario a partir de Certificate Transparency, índices web y RDAP con límites, procedencia y fallos visibles | Consulta únicamente proveedores públicos; no contacta ni resuelve el objetivo |
| [ScopeGuard](tools/scopeguard/) | Autorización *fail closed*, normalización de objetivos, prioridad de `deny` y auditoría encadenada | Sin red |
| [Telemetry Validator](tools/telemetry-validator/) | Salud de telemetría Windows/Sysmon/PowerShell/Defender frente a expectativas mapeadas a MITRE ATT&CK | Sin red; analiza JSONL exportado |
| [ReportForge](tools/reportforge/) | Validación estricta de hallazgos, redacción de secretos e informes Markdown y SARIF 2.1.0 | Sin red |

## Validación rápida

```bash
python3 scripts/test_all.py
python3 scripts/portfolio_demo.py
```

La suite supera 99 pruebas offline: 23 de inventario pasivo, 50 de ScopeGuard, 17 de telemetría y 9 de ReportForge. El runner también ejecuta una demo integrada con fixtures sintéticas y sin acceder a objetivos reales.

## Decisiones de ingeniería

- una regla `deny` siempre prevalece sobre `allow`;
- los fallos de proveedores se muestran como cobertura incompleta, nunca como cero activos;
- los eventos ausentes se distinguen de archivos inválidos o incompletos;
- el mismo modelo validado genera informes humanos y SARIF;
- credenciales, tokens y marcado inseguro se eliminan antes de producir salidas compartibles;
- las fixtures permiten reproducir límites y errores sin depender de un sistema externo.

## Uso profesional

El repositorio sirve para explicar en una entrevista cómo se implementa un control de scope, cómo se conserva la incertidumbre de fuentes pasivas, cómo se valida la observabilidad defensiva y cómo se genera un informe determinista desde evidencia estructurada.

Todo el código utiliza Python/Bash y no requiere paquetes Python de terceros. La suite completa se verifica en Linux y GitHub Actions.

## Uso autorizado

Utiliza estas herramientas únicamente sobre sistemas propios o con autorización explícita. La suite no incluye generación de payloads, persistencia, robo de credenciales, bypass de controles ni funciones de sigilo.

## Licencia

MIT. Consulta [LICENSE](LICENSE).
