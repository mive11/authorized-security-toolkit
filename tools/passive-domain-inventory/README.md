# Recon pasiva de dominio — 2.0

Entrada: `recon.sh`. Es un único fichero autocontenido que utiliza Bash y Python 3.9 o posterior, sin instalar paquetes. Diseñado para Linux, incluido Kali.

## Uso

```bash
# Ver opciones, sin conectar:
bash recon.sh --help

# Revisar el plan, sin conectar ni crear informes:
bash recon.sh example.com --dry-run

# Consultar las cuatro fuentes externas:
bash recon.sh example.com

# Elegir fuentes y carpeta de resultados:
bash recon.sh example.com --sources crtsh,wayback --output ./mis-informes

# Ampliar la muestra histórica a tres índices recientes de Common Crawl:
bash recon.sh example.com --cc-indexes 3 --limit 5000

# Exportación opcional de rutas históricas; revisarlas antes de compartir:
bash recon.sh example.com --include-paths
```

Sustituye `example.com` por tu dominio. Usa únicamente el nombre, sin `https://`, puertos, rutas ni comodines. Se admiten mayúsculas, un punto DNS final y dominios internacionalizados mediante IDNA de Python. Las conversiones ambiguas, como `faß.de` a `fass.de`, se rechazan: usa el nombre ASCII/Punycode exacto. Una IP no es un dominio. Los dominios privados del laboratorio, como `.htb`, pueden no tener registros en estas fuentes.

La ruta de salida predeterminada es `Recon_Fase_Pasiva` dentro de la carpeta desde la que ejecutas el comando. Cada ejecución crea un subdirectorio con dominio, fecha UTC y sufijo aleatorio. No necesitas `sudo`.

## Qué consulta

| Fuente | Datos utilizados | Límites de interpretación |
|---|---|---|
| crt.sh | Nombres en certificados, identificador y fechas del certificado | Un wildcard no acredita un host concreto; un certificado no acredita disponibilidad actual. Se consulta el nombre exacto y su sufijo. |
| Wayback CDX | Nombres y fechas/estado/mimetype de URL previamente archivadas | Se consulta el índice; no se descarga ni reproduce ninguna página. Muestra acotada de URL únicas. |
| Common Crawl | Nombres y metadatos de URL del índice | Primera página de 1–3 índices recientes, no todo su histórico. |
| RDAP/IANA | Registro del dominio, estados, fechas, servidores de nombres y estado DNSSEC declarado | Consulta el nombre exacto. Para un subdominio puede no existir un objeto RDAP; no cambia automáticamente al dominio padre. |

Los servidores de nombres externos se conservan como metadatos de registro y no se añaden al inventario del dominio. Los nombres de CT y archivos se filtran por coincidencia exacta o sufijo con punto: `a.example.com` pertenece a `example.com`; `evil-example.com` y `example.com.evil` no.

## Qué significa «pasiva» aquí

El script envía HTTPS exclusivamente a proveedores externos de información existente. No envía HTTP, conexiones de servicios ni consultas DNS para nombres del objetivo. Sí resuelve los nombres de los proveedores para conectarse con ellos y estos reciben el dominio consultado: pasivo respecto al objetivo no significa anónimo.

La lista de endpoints es cerrada, salvo el registro RDAP identificado por el bootstrap HTTPS de IANA. Se rechazan esquemas distintos de HTTPS, destinos privados, redirecciones y proveedores cuyo nombre esté dentro del dominio objetivo. La conexión usa las direcciones públicas resueltas para ese proveedor, con comprobación de certificado TLS y nombre. No usa proxies de variables de entorno, referencias RDAP, enlaces de respuestas ni URLs de archivo para generar nuevas conexiones.

Se han eliminado del flujo anterior las comprobaciones de WAF, WhatWeb y dnsx, porque generan tráfico activo. También se ha sustituido la búsqueda de empleados y contactos por metadatos del dominio. No hay modo activo oculto ni invocación de escáneres externos.

## Resultados

- `informe.md`: resumen legible, cobertura, límites y errores.
- `report.json`: inventario estructurado con procedencia y evidencia histórica por nombre.
- `fuentes.json`: estados y registro de consultas a proveedores, incluidos hashes de respuestas, sin guardar sus cuerpos.
- `subdominios_totales.txt`: nombres exactos observados, únicos y ordenados; puede incluir el dominio raíz. El nombre del fichero se conserva por compatibilidad y **no significa cobertura total**.
- `comodines.txt`: patrones como `*.example.com`, separados de los nombres concretos.
- `urls_historicas.txt`: solo con `--include-paths`; elimina parámetros de consulta y fragmentos y descarta URLs con credenciales. Las rutas también pueden contener datos sensibles; esta opción no garantiza anonimización.

Por defecto no se guardan rutas, parámetros, contraseñas, contactos RDAP, cuerpos de respuesta ni datos de empleados. Los informes son privados (`0600`), dentro de un directorio privado (`0700`). Los permisos de una carpeta de salida preexistente no se modifican.

Una ejecución interrumpida antes de finalizar conserva `EJECUCION_INCOMPLETA.txt`. Si se pulsa Ctrl+C durante una consulta, se intenta guardar lo conseguido y se marca la interrupción en JSON.

## Límites y códigos de salida

Valores predeterminados: 2000 activos y registros por consulta, 4 MiB por respuesta, 45 segundos totales por fuente, 12 intentos de petición globales, un reintento ante errores transitorios, separación mínima de un segundo entre solicitudes. Se comprueba el tamaño antes de analizar cada respuesta. Un `Retry-After` superior a 5 segundos o expresado como fecha se respeta omitiendo el reintento en esa ejecución.
El límite de registros también se aplica por separado a los servidores de nombres, eventos y estados que aparezcan en RDAP; cualquier truncado deja la fuente como `partial`.

- `0`: todas las fuentes seleccionadas respondieron con datos válidos o vacíos. No garantiza un inventario completo.
- `2`: argumentos o archivos locales inválidos.
- `3`: alguna fuente falló, se omitió o alcanzó un límite; se conservan los resultados válidos.
- `130`: interrupción del usuario durante la recopilación.

Los estados por fuente son `ok`, `empty`, `partial`, `error` y `skipped`. Los límites, el bloqueo de proveedores o una respuesta JSON malformada no se presentan como «no hay activos». Common Crawl se etiqueta siempre como muestra. No se puede confirmar que un host esté vivo, su IP actual, su WAF o sus vulnerabilidades a partir de este inventario.

## Pruebas offline

Desde la carpeta `tools/passive-domain-inventory` del proyecto:

```bash
python3 -m unittest discover -s . -p 'test_*.py' -v
bash recon.sh example.com --offline fixtures --output /tmp/recon-demo
```

Las fixtures incluidas son sintéticas; no contienen datos de un objetivo real. El modo offline no hace fallback a Internet si falta una fixture. Las pruebas bloquean las llamadas de red, comprueban alcance, privacidad, fallos parciales, límites y controles del transporte.

Los ficheros esperados son `crtsh-apex.json`, `crtsh-subdomains.json`, `wayback.json`, `commoncrawl-catalog.json`, `commoncrawl-0.jsonl`, `rdap-bootstrap.json` y `rdap.json`. Para más índices se usa `commoncrawl-1.jsonl` y `commoncrawl-2.jsonl`.

## Fuentes técnicas

- [crt.sh: salida JSON](https://github.com/crtsh/certwatch_db/issues/56).
- [Internet Archive: API CDX, campos, límites y coincidencia de dominio](https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md).
- [Common Crawl: servidor de índices](https://index.commoncrawl.org/).
- [IANA: registro bootstrap de RDAP](https://www.iana.org/assignments/rdap-dns).

Las APIs públicas pueden cambiar, limitar peticiones o dejar de responder. En ese caso se informa del fallo y se conserva el trabajo del resto de fuentes.
