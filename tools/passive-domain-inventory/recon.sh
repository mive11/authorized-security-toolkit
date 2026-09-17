#!/usr/bin/env bash
# Inventario pasivo: solo metadatos de terceros. Requiere Bash y Python >= 3.9.
set -euo pipefail
command -v python3 >/dev/null 2>&1 || { printf 'Falta python3.\n' >&2; exit 2; }
exec python3 -I - "$@" <<'PY_RECON'
import argparse
import contextlib
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import sys
import tempfile
import time
import unicodedata
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

VERSION = '2.0.0'
SOURCE_NAMES = ('crtsh', 'wayback', 'commoncrawl', 'rdap')
FIXED_ENDPOINTS = {
    'crtsh': ('crt.sh', '/'),
    'wayback': ('web.archive.org', '/cdx/search/cdx'),
    'cc_catalog': ('index.commoncrawl.org', '/collinfo.json'),
    'rdap_bootstrap': ('data.iana.org', '/rdap/dns.json'),
}


def normalize_domain(value):
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError('Introduce un dominio sin espacios, URL ni ruta.')
    if any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError('El dominio contiene espacios o caracteres de control.')
    value = value[:-1] if value.endswith('.') else value
    original = unicodedata.normalize('NFC', value).lower()
    try:
        value = value.encode('idna').decode('ascii').lower()
        for label in value.split('.'):
            if not label.startswith('xn--'):
                continue
            payload = label[4:]
            decoded_label = payload.encode('ascii').decode('punycode')
            if (not payload or not decoded_label or not any(ord(c) > 127 for c in decoded_label)
                    or unicodedata.normalize('NFC', decoded_label) != decoded_label
                    or unicodedata.combining(decoded_label[0])
                    or any(unicodedata.category(c)[0] in ('C', 'Z') or c == '.'
                           for c in decoded_label)
                    or decoded_label.encode('punycode').decode('ascii').lower() != payload):
                raise ValueError('Dominio Punycode no canónico.')
        if any(ord(c) > 127 for c in original):
            decoded = value.encode('ascii').decode('idna')
            if unicodedata.normalize('NFC', decoded).lower() != original:
                raise ValueError('Conversión IDNA ambigua: introduce el dominio en ASCII/Punycode.')
    except UnicodeError:
        raise ValueError('Dominio IDNA no válido.') from None
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x)
        for x in labels
    ) or labels[-1].isdigit():
        raise ValueError('Usa un dominio válido, por ejemplo example.com; no una IP.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Se necesita un dominio, no una IP.')


def in_scope(host, target):
    return host == target or host.endswith('.' + target)


def clean_text(value, length=160):
    if not isinstance(value, str):
        return ''
    return ''.join(c for c in value[:length] if ord(c) >= 32 and ord(c) != 127)


class SourceError(Exception):
    pass


class SourceSkipped(SourceError):
    pass


class DeadlineExceeded(SourceError):
    pass


@contextlib.contextmanager
def deadline(seconds):
    # Linux: SIGALRM bounds DNS, TLS, slow bodies and JSON parsing together.
    def expired(signum, frame):
        raise DeadlineExceeded('Se agotó el tiempo total de esta fuente.')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class ProviderHTTPS(http.client.HTTPSConnection):
    def connect(self):
        # Resolve ONLY a vetted provider, reject private addresses, and pin the
        # connection to those exact answers while keeping hostname TLS checks.
        answers = socket.getaddrinfo(self.host, 443, type=socket.SOCK_STREAM)
        if not answers or any(not ipaddress.ip_address(x[4][0]).is_global for x in answers):
            raise SourceError('El proveedor resuelve a una dirección no pública.')
        last_error = None
        for family, kind, proto, _, address in answers[:4]:
            sock = socket.socket(family, kind, proto)
            try:
                sock.settimeout(self.timeout)
                sock.connect(address)
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
                return
            except OSError as exc:
                sock.close()
                last_error = exc
            except BaseException:
                sock.close()
                raise
        raise SourceError('No se pudo conectar por TLS al proveedor.') from last_error


class Transport:
    def __init__(self, args, target):
        self.args = args
        self.target = target
        self.requests = []
        self.used = 0
        self.last_request = 0.0
        self.rdap_endpoint = None

    def validate(self, kind, url):
        try:
            parsed = urlsplit(url)
            host = normalize_domain(parsed.hostname or '')
            if (parsed.scheme != 'https' or parsed.username is not None
                    or parsed.password is not None or parsed.port not in (None, 443)
                    or parsed.fragment or any(ord(c) < 33 for c in url)):
                raise ValueError()
        except ValueError:
            raise SourceError('Endpoint de proveedor no válido.') from None
        if in_scope(host, self.target):
            raise SourceSkipped('El proveedor pertenece al dominio objetivo; consulta omitida.')
        if kind in FIXED_ENDPOINTS:
            allowed = (host, parsed.path) == FIXED_ENDPOINTS[kind]
        elif kind == 'cc_index':
            allowed = host == 'index.commoncrawl.org' and bool(
                re.fullmatch(r'/CC-MAIN-\d{4}-\d{2}-index', parsed.path))
        elif kind == 'rdap':
            allowed = url == self.rdap_endpoint
        else:
            allowed = False
        if not allowed:
            raise SourceError('Endpoint fuera de la lista de proveedores permitidos.')
        return parsed, host

    def get(self, kind, url, fixture):
        parsed, host = self.validate(kind, url)
        cap = self.args.max_bytes
        if self.args.offline:
            try:
                with (self.args.offline / fixture).open('rb') as handle:
                    data = handle.read(cap + 1)
            except OSError:
                raise SourceError('Fixture ausente o ilegible: ' + fixture) from None
            if len(data) > cap:
                raise SourceError('Fixture supera el límite de bytes: ' + fixture)
            self.requests.append({'provider': host, 'fixture': fixture, 'mode': 'offline',
                                  'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            return data
        for attempt in range(self.args.retries + 1):
            if self.used >= self.args.request_budget:
                raise SourceError('Presupuesto global de peticiones agotado.')
            time.sleep(max(0, 1.0 - (time.monotonic() - self.last_request)))
            self.used += 1
            self.last_request = time.monotonic()
            event = {'provider': host, 'kind': kind, 'attempt': attempt + 1,
                     'mode': 'online', 'status': 'started'}
            self.requests.append(event)
            conn = ProviderHTTPS(host, timeout=min(15, self.args.source_timeout),
                                 context=ssl.create_default_context())
            retry_delay = 1
            try:
                path = parsed.path + ('?' + parsed.query if parsed.query else '')
                conn.request('GET', path, headers={
                    'User-Agent': 'PassiveDomainInventory/' + VERSION,
                    'Accept': 'application/json, application/rdap+json, text/plain',
                    'Accept-Encoding': 'identity',
                })
                response = conn.getresponse()
                event['http_status'] = response.status
                if 300 <= response.status < 400:
                    raise SourceError('Redirección bloqueada; no se sigue Location.')
                if response.status != 200:
                    event['status'] = 'http_error'
                    transient = response.status in (429, 500, 502, 503, 504)
                    retry_after = response.getheader('Retry-After')
                    if retry_after is not None:
                        # Long or date-form delays are not retried in this bounded run.
                        transient = transient and retry_after.isdigit() and int(retry_after) <= 5
                        if transient:
                            retry_delay = max(1, int(retry_after))
                    if not transient or attempt == self.args.retries:
                        raise SourceError('HTTP ' + str(response.status) + ' del proveedor.')
                    conn.close()
                    time.sleep(retry_delay)
                    continue
                if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
                    raise SourceError('Contenido comprimido no admitido; límite de bytes protegido.')
                length = response.getheader('Content-Length')
                if length and length.isdigit() and int(length) > cap:
                    raise SourceError('Respuesta supera el límite de bytes.')
                data = response.read(cap + 1)
                if len(data) > cap:
                    raise SourceError('Respuesta supera el límite de bytes.')
                event.update(status='ok', bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                return data
            except DeadlineExceeded:
                event['status'] = 'timeout'
                raise
            except SourceError:
                if event['status'] == 'started':
                    event['status'] = 'blocked_or_invalid'
                raise
            except (OSError, http.client.HTTPException) as exc:
                event['status'] = 'network_error'
                # Never persist response bodies, cookies, Location or exception messages.
                if attempt == self.args.retries:
                    raise SourceError('Error de conexión al proveedor (' + type(exc).__name__ + ').') from None
            finally:
                conn.close()
        raise SourceError('Consulta no completada.')

    def get_json(self, kind, url, fixture):
        try:
            return json.loads(self.get(kind, url, fixture))
        except (ValueError, UnicodeError, RecursionError):
            raise SourceError('Respuesta JSON no válida; no equivale a cero resultados.') from None


class Inventory:
    def __init__(self, target, args):
        self.target = target
        self.args = args
        self.hosts = {}
        self.wildcards = {}
        self.urls = {}
        self.registration = None
        self.asset_limit_hit = False

    def add_name(self, name, source, evidence):
        if not isinstance(name, str):
            return False
        wildcard = name.startswith('*.')
        try:
            host = normalize_domain(name[2:] if wildcard else name)
        except ValueError:
            return False
        if not in_scope(host, self.target):
            return False
        key = '*.' + host if wildcard else host
        dest = self.wildcards if wildcard else self.hosts
        if key not in dest:
            if len(self.hosts) + len(self.wildcards) >= self.args.limit:
                self.asset_limit_hit = True
                return False
            dest[key] = {'name': key, 'sources': [], 'evidence': []}
        record = dest[key]
        if source not in record['sources']:
            record['sources'].append(source)
        item = dict(evidence, source=source)
        if item not in record['evidence'] and len(record['evidence']) < 12:
            record['evidence'].append(item)
        return True

    def add_url(self, raw, source, evidence):
        if not isinstance(raw, str) or len(raw) > 8192 or any(ord(c) < 32 for c in raw):
            return False
        try:
            parsed = urlsplit(raw)
            if (parsed.scheme not in ('http', 'https') or parsed.username is not None
                    or parsed.password is not None or '\\' in parsed.netloc):
                return False
            host = normalize_domain(parsed.hostname or '')
            port = parsed.port
            if not in_scope(host, self.target) or (port is not None and not 1 <= port <= 65535):
                return False
        except ValueError:
            return False
        accepted = self.add_name(host, source, evidence)
        if not accepted or not self.args.include_paths:
            return accepted
        # Opt-in only: paths may themselves contain personal or secret data.
        authority = host + (':' + str(port) if port else '')
        path = quote(parsed.path or '/', safe="/%:@!$&'()*+,;=-._~")
        safe_url = urlunsplit((parsed.scheme, authority, path, '', ''))
        if safe_url not in self.urls and len(self.urls) >= self.args.limit:
            self.asset_limit_hit = True
            return True
        row = self.urls.setdefault(safe_url, {'url': safe_url, 'sources': []})
        if source not in row['sources']:
            row['sources'].append(source)
        return True


def query(host, path, params):
    return 'https://' + host + path + '?' + urlencode(params)


def limited(rows, state, limit):
    if not isinstance(rows, list):
        raise SourceError('Formato inesperado: se esperaba una lista.')
    if len(rows) > limit:
        state['warnings'].append('Límite de registros alcanzado; resultados parciales.')
    return rows[:limit]


def parse_ct(rows, inv, state):
    for row in limited(rows, state, inv.args.limit):
        if not isinstance(row, dict) or not isinstance(row.get('name_value'), str):
            state['invalid_rows'] += 1
            continue
        state['records'] += 1
        ev = {'kind': 'certificate_name'}
        if str(row.get('id', '')).isdigit():
            ev['certificate_id'] = str(row['id'])[:30]
        for field in ('not_before', 'not_after'):
            if re.fullmatch(r'[0-9T: .Z+-]{10,40}', str(row.get(field, ''))):
                ev['certificate_' + field] = row[field]
        for name in row['name_value'].splitlines():
            inv.add_name(name.strip(), 'crtsh', ev)


def collect_crtsh(tx, inv, state):
    successes = 0
    for label, pattern in (('apex', inv.target), ('subdomains', '%.' + inv.target)):
        try:
            rows = tx.get_json('crtsh', query('crt.sh', '/', {'q': pattern, 'output': 'json'}),
                               'crtsh-' + label + '.json')
            parse_ct(rows, inv, state)
            successes += 1
        except (DeadlineExceeded, SourceSkipped):
            raise
        except SourceError as exc:
            state['warnings'].append(label + ': ' + str(exc))
    if successes == 0:
        raise SourceError('Fallaron las dos consultas de certificados.')


def archive_evidence(row, timestamp_key, status_key, mime_key):
    ev = {'kind': 'archive_index'}
    stamp = str(row.get(timestamp_key, ''))
    if re.fullmatch(r'\d{14}', stamp):
        ev['capture_timestamp'] = stamp
    status = str(row.get(status_key, ''))
    if re.fullmatch(r'\d{3}', status):
        ev['historical_http_status'] = status
    mime = row.get(mime_key, '')
    if isinstance(mime, str) and re.fullmatch(r'[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_-]+', mime):
        ev['historical_mime'] = mime[:100]
    return ev


def collect_wayback(tx, inv, state):
    url = query('web.archive.org', '/cdx/search/cdx', {
        'url': inv.target, 'matchType': 'domain', 'output': 'json',
        'fl': 'original,timestamp,statuscode,mimetype', 'collapse': 'urlkey',
        'limit': inv.args.limit + 1, 'gzip': 'false',
    })
    rows = tx.get_json('wayback', url, 'wayback.json')
    if rows == []:
        return
    if not isinstance(rows, list) or not isinstance(rows[0], list):
        raise SourceError('Cabecera CDX ausente o inválida.')
    header = rows[0]
    if (not all(isinstance(x, str) for x in header) or len(set(header)) != len(header)
            or not {'original', 'timestamp', 'statuscode', 'mimetype'}.issubset(header)):
        raise SourceError('Cabecera CDX inesperada.')
    for values in limited(rows[1:], state, inv.args.limit):
        if not isinstance(values, list) or len(values) != len(header):
            state['invalid_rows'] += 1
            continue
        row = dict(zip(header, values))
        state['records'] += 1
        if not inv.add_url(row['original'], 'wayback', archive_evidence(
                row, 'timestamp', 'statuscode', 'mimetype')):
            state['discarded_rows'] += 1


def collect_commoncrawl(tx, inv, state):
    catalog = tx.get_json('cc_catalog', 'https://index.commoncrawl.org/collinfo.json',
                          'commoncrawl-catalog.json')
    if not isinstance(catalog, list):
        raise SourceError('Catálogo Common Crawl inesperado.')
    ids = sorted({x['id'] for x in catalog if isinstance(x, dict)
                  and isinstance(x.get('id'), str)
                  and re.fullmatch(r'CC-MAIN-\d{4}-\d{2}', x['id'])}, reverse=True)
    if not ids:
        raise SourceError('El catálogo no contiene índices válidos.')
    state['selected_indexes'] = ids[:inv.args.cc_indexes]
    successes = 0
    for index, collection in enumerate(state['selected_indexes']):
        try:
            url = query('index.commoncrawl.org', '/' + collection + '-index', {
                'url': inv.target, 'matchType': 'domain', 'output': 'json',
                'fl': 'url,timestamp,status,mime', 'limit': inv.args.limit + 1,
                'pageSize': '1', 'page': '0',
            })
            data = tx.get('cc_index', url, 'commoncrawl-' + str(index) + '.jsonl')
            try:
                lines = data.decode('utf-8').splitlines()
            except UnicodeError:
                raise SourceError('Índice Common Crawl no es UTF-8.') from None
            for line in limited([x for x in lines if x.strip()], state, inv.args.limit):
                try:
                    row = json.loads(line)
                except (ValueError, RecursionError):
                    state['invalid_rows'] += 1
                    continue
                if not isinstance(row, dict) or not isinstance(row.get('url'), str):
                    state['invalid_rows'] += 1
                    continue
                state['records'] += 1
                ev = archive_evidence(row, 'timestamp', 'status', 'mime')
                ev['collection'] = collection
                if not inv.add_url(row['url'], 'commoncrawl', ev):
                    state['discarded_rows'] += 1
            successes += 1
        except (DeadlineExceeded, SourceSkipped):
            raise
        except SourceError as exc:
            state['warnings'].append(collection + ': ' + str(exc))
    state['coverage_note'] = 'Muestra acotada: primera página de los índices seleccionados; no todo el archivo.'
    if successes == 0:
        raise SourceError('Ningún índice Common Crawl se pudo consultar.')


def rdap_url(bootstrap, target):
    if not isinstance(bootstrap, dict) or not isinstance(bootstrap.get('services'), list):
        raise SourceError('Bootstrap IANA inválido.')
    matches = []
    for service in bootstrap['services']:
        if not isinstance(service, list) or len(service) != 2:
            continue
        suffixes, endpoints = service
        if not isinstance(suffixes, list) or not isinstance(endpoints, list):
            continue
        for suffix in suffixes:
            if isinstance(suffix, str) and (target == suffix or target.endswith('.' + suffix)):
                for base in endpoints:
                    if isinstance(base, str):
                        matches.append((len(suffix), base))
    for _, base in sorted(matches, key=lambda x: -x[0]):
        try:
            p = urlsplit(base)
            host = normalize_domain(p.hostname or '')
            if (p.scheme != 'https' or p.username is not None or p.password is not None
                    or p.port not in (None, 443) or p.query or p.fragment
                    or not re.fullmatch(r'/[a-zA-Z0-9_./-]*', p.path or '/')
                    or any(x in ('.', '..') for x in p.path.split('/'))):
                continue
            if in_scope(host, target):
                continue
            return 'https://' + host + (p.path or '/').rstrip('/') + '/domain/' + target
        except ValueError:
            continue
    raise SourceSkipped('IANA no ofrece un endpoint HTTPS externo válido para este sufijo.')


def collect_rdap(tx, inv, state):
    bootstrap = tx.get_json('rdap_bootstrap', 'https://data.iana.org/rdap/dns.json',
                            'rdap-bootstrap.json')
    tx.rdap_endpoint = rdap_url(bootstrap, inv.target)
    row = tx.get_json('rdap', tx.rdap_endpoint, 'rdap.json')
    if not isinstance(row, dict) or row.get('objectClassName') != 'domain':
        raise SourceError('Respuesta RDAP no es un objeto de dominio.')
    try:
        domain = normalize_domain(row.get('ldhName', ''))
    except ValueError:
        raise SourceError('RDAP no identifica el dominio solicitado.') from None
    if domain != inv.target:
        raise SourceError('RDAP devolvió otro dominio; registro descartado.')
    nameservers = []
    raw_nameservers = row.get('nameservers', []) if isinstance(row.get('nameservers'), list) else []
    for ns in limited(raw_nameservers, state, inv.args.limit):
        if isinstance(ns, dict):
            try:
                name = normalize_domain(ns.get('ldhName', ''))
            except ValueError:
                continue
            nameservers.append(name)
            inv.add_name(name, 'rdap', {'kind': 'registered_nameserver'})
    events = []
    raw_events = row.get('events', []) if isinstance(row.get('events'), list) else []
    for event in limited(raw_events, state, inv.args.limit):
        if not isinstance(event, dict):
            continue
        action = event.get('eventAction')
        date = event.get('eventDate')
        if (action in ('registration', 'expiration', 'last changed', 'transfer',
                       'last update of RDAP database') and isinstance(date, str)
                and re.fullmatch(r'[0-9T: .Z+-]{10,40}', date)):
            events.append({'action': action, 'date': date})
    raw_statuses = row.get('status') if isinstance(row.get('status'), list) else []
    statuses = limited(raw_statuses, state, inv.args.limit)
    inv.registration = {'domain': domain, 'nameservers': sorted(set(nameservers)),
                        'events': events, 'status': [clean_text(x, 80) for x in statuses
                          if isinstance(x, str)],
                        'dnssec_signed': row.get('secureDNS', {}).get('delegationSigned')
                          if isinstance(row.get('secureDNS'), dict) else None}
    if not isinstance(inv.registration['dnssec_signed'], bool):
        inv.registration['dnssec_signed'] = None
    inv.add_name(domain, 'rdap', {'kind': 'domain_registration'})
    state['records'] = 1
    state['coverage_note'] = 'Registro del nombre exacto; no se siguen referencias ni se consultan contactos.'


COLLECTORS = {'crtsh': collect_crtsh, 'wayback': collect_wayback,
              'commoncrawl': collect_commoncrawl, 'rdap': collect_rdap}


def bounded_int(low, high):
    def parse(value):
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError('Se necesita un número entero.') from None
        if not low <= number <= high:
            raise argparse.ArgumentTypeError('El valor debe estar entre %d y %d.' % (low, high))
        return number
    return parse


def arguments(argv):
    parser = argparse.ArgumentParser(prog='recon.sh', description=(
        'Inventario pasivo de dominio: CT, índices de archivos web y RDAP. '
        'No contacta ni resuelve nombres del objetivo. Los proveedores conocen la consulta. '
        'Los resultados no confirman hosts vivos ni vulnerabilidades.'))
    parser.add_argument('domain', help='Dominio exacto, sin https:// ni ruta')
    parser.add_argument('--output', type=Path, default=Path.cwd() / 'Recon_Fase_Pasiva',
                        help='Carpeta base; cada ejecución crea una subcarpeta nueva')
    parser.add_argument('--sources', default=','.join(SOURCE_NAMES), help='Fuentes separadas por comas')
    parser.add_argument('--limit', type=bounded_int(1, 10000), default=2000,
                        help='Máximo de registros por consulta y de activos guardados (2000)')
    parser.add_argument('--cc-indexes', type=bounded_int(1, 3), default=1,
                        help='Índices recientes de Common Crawl (1 a 3; muestra de cada uno)')
    parser.add_argument('--source-timeout', type=bounded_int(5, 120), default=45,
                        help='Límite total de segundos por fuente (45)')
    parser.add_argument('--max-bytes', type=bounded_int(1024, 16777216), default=4194304,
                        help='Máximo de bytes por respuesta (4194304)')
    parser.add_argument('--request-budget', type=bounded_int(1, 30), default=12,
                        help='Máximo de peticiones de red, incluidos reintentos (12)')
    parser.add_argument('--retries', type=bounded_int(0, 1), default=1,
                        help='Reintentos por errores transitorios (0 o 1)')
    parser.add_argument('--include-paths', action='store_true',
                        help='Guardar rutas históricas (pueden contener datos sensibles); elimina query y fragmento')
    parser.add_argument('--offline', type=Path, metavar='FIXTURES',
                        help='Usar solo fixtures locales; nunca hace fallback a red')
    parser.add_argument('--dry-run', action='store_true', help='Mostrar el plan sin red ni crear archivos')
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args(argv)
    try:
        args.domain = normalize_domain(args.domain)
    except ValueError as exc:
        parser.error(str(exc))
    selected = args.sources.split(',')
    if not selected or any(x not in SOURCE_NAMES for x in selected):
        parser.error('Fuentes válidas: ' + ','.join(SOURCE_NAMES))
    args.sources = list(dict.fromkeys(selected))
    if args.offline and not args.offline.is_dir():
        parser.error('--offline debe señalar una carpeta existente.')
    return args


def private_write(path, content):
    # Exclusive creation, even if a previous run exists; no reports overwritten.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(content)


def save_reports(directory, report):
    def dump(name, data):
        private_write(directory / name, json.dumps(data, ensure_ascii=True, indent=2) + '\n')
    dump('report.json', report)
    dump('fuentes.json', {'sources': report['sources'], 'requests': report['requests']})
    for file, records, key in (('subdominios_totales.txt', report['hosts'], 'name'),
                               ('comodines.txt', report['wildcards'], 'name')):
        private_write(directory / file, ''.join(x[key] + '\n' for x in records))
    if report['include_paths']:
        private_write(directory / 'urls_historicas.txt', ''.join(x['url'] + '\n' for x in report['urls']))
    lines = ['# Inventario pasivo: ' + report['target'], '',
             '- Fecha UTC: ' + report['started_at'], '- Modo: ' + report['mode'],
             '- Nombres observados: ' + str(len(report['hosts'])),
             '- Patrones wildcard: ' + str(len(report['wildcards'])),
             '- Peticiones de red realizadas: ' + str(report['network_requests']), '',
             'Los datos son históricos o de registro: no confirman disponibilidad, propiedad actual ni vulnerabilidades.',
             'No se envían peticiones HTTP ni consultas DNS a nombres del objetivo. Se resuelven los proveedores.', '',
             '## Estado de las fuentes', '', '| Fuente | Estado | Registros |', '|---|---|---:|']
    for source in report['sources']:
        lines.append('| %s | %s | %d |' % (source['name'], source['status'], source['records']))
    lines.extend(['', '## Cobertura y límites', '',
                  'CT puede omitir certificados o devolver solo parte de su índice. '
                  'Wayback es una muestra de URL únicas. Common Crawl consulta una página de los índices elegidos. '
                  'RDAP corresponde al nombre exacto y puede no existir para subdominios.',
                  'Cada resultado incluye procedencia en report.json. Los errores nunca significan ausencia de activos.',
                  'Los patrones *.example.com no se convierten en hosts concretos.',
                  'Los proveedores públicos reciben el dominio consultado. No se siguen redirecciones, referencias RDAP ni páginas archivadas.', ''])
    for source in report['sources']:
        for message in source['warnings'] + ([source['error']] if source['error'] else []):
            # Messages are generated internally, never copied from response bodies.
            lines.append('- ' + source['name'] + ': ' + message)
        if source.get('coverage_note'):
            lines.append('- ' + source['name'] + ': ' + source['coverage_note'])
    lines.extend(['', '## Nombres observados', ''])
    lines.extend('- `' + x['name'] + '` — ' + ', '.join(x['sources']) for x in report['hosts'][:200])
    if len(report['hosts']) > 200:
        lines.append('Lista completa en subdominios_totales.txt y report.json.')
    if report['include_paths']:
        lines.extend(['', 'Exportación de rutas activada expresamente. Las rutas pueden contener datos sensibles; '
                      'se han retirado query, fragmentos y URLs con credenciales.'])
    private_write(directory / 'informe.md', '\n'.join(lines) + '\n')


def main(argv=None):
    args = arguments(argv)
    plan = {'target': args.domain, 'sources': args.sources, 'target_requests': False,
            'target_dns': False, 'redirects': False, 'proxy_environment_used': False,
            'offline': bool(args.offline), 'request_budget': args.request_budget,
            'source_timeout_seconds': args.source_timeout,
            'providers': ['crt.sh', 'web.archive.org', 'index.commoncrawl.org',
                          'data.iana.org', 'Registro RDAP HTTPS identificado por IANA'],
            'note': 'Los proveedores reciben la consulta. Fuentes que pertenezcan al objetivo se omiten.'}
    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0
    started = dt.datetime.now(dt.timezone.utc)
    old_umask = os.umask(0o077)
    directory = None
    try:
        args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix=args.domain + '-' + started.strftime('%Y%m%dT%H%M%SZ-'),
                                          dir=args.output))
        private_write(directory / 'EJECUCION_INCOMPLETA.txt',
                      'Si este fichero permanece, la ejecución no completó el informe.\n')
        tx = Transport(args, args.domain)
        inv = Inventory(args.domain, args)
        states = []
        interrupted = False
        print('[*] Dominio: ' + args.domain + ' | Solo fuentes externas' + (' | OFFLINE' if args.offline else ''))
        print('[*] Salida: ' + str(directory.resolve()))
        for name in args.sources:
            state = {'name': name, 'status': 'running', 'records': 0, 'invalid_rows': 0,
                     'discarded_rows': 0, 'warnings': [], 'error': None}
            states.append(state)
            before = time.monotonic()
            print('[*] Consultando ' + name + '…', flush=True)
            try:
                with deadline(args.source_timeout):
                    COLLECTORS[name](tx, inv, state)
                if state['invalid_rows']:
                    state['warnings'].append('Hay filas malformadas descartadas.')
                if inv.asset_limit_hit:
                    state['warnings'].append('Se alcanzó el límite global de activos o rutas.')
                state['status'] = 'partial' if state['warnings'] else ('ok' if state['records'] else 'empty')
            except SourceSkipped as exc:
                state.update(status='skipped', error=str(exc))
            except SourceError as exc:
                state.update(status='partial' if state['records'] else 'error', error=str(exc))
            except KeyboardInterrupt:
                state.update(status='partial' if state['records'] else 'error', error='Interrumpido por el usuario.')
                interrupted = True
            except (ValueError, TypeError, KeyError, RecursionError) as exc:
                state.update(status='partial' if state['records'] else 'error',
                             error='Formato inesperado del proveedor (' + type(exc).__name__ + ').')
            state['elapsed_seconds'] = round(time.monotonic() - before, 3)
            print('[%s] %s: %d registros' % (state['status'], name, state['records']), flush=True)
            if interrupted:
                break
        report = {'version': VERSION, 'target': args.domain,
                  'mode': 'offline' if args.offline else 'passive',
                  'started_at': started.isoformat(), 'finished_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                  'include_paths': args.include_paths, 'interrupted': interrupted,
                  'coverage': 'bounded_historical_inventory_not_exhaustive',
                  'selected_sources': args.sources, 'sources': states, 'requests': tx.requests,
                  'network_requests': tx.used, 'limits': {'records': args.limit, 'bytes_per_response': args.max_bytes,
                    'request_budget': args.request_budget, 'source_seconds': args.source_timeout,
                    'evidence_per_asset': 12},
                  'hosts': [inv.hosts[x] for x in sorted(inv.hosts)],
                  'wildcards': [inv.wildcards[x] for x in sorted(inv.wildcards)],
                  'urls': [inv.urls[x] for x in sorted(inv.urls)], 'registration': inv.registration}
        save_reports(directory, report)
        (directory / 'EJECUCION_INCOMPLETA.txt').unlink()
        incomplete = any(x['status'] not in ('ok', 'empty') for x in states)
        print('[*] Informe: ' + str((directory / 'informe.md').resolve()))
        print('[*] %d nombres y %d comodines; disponibilidad no comprobada.' % (len(inv.hosts), len(inv.wildcards)))
        if incomplete:
            print('[!] Cobertura parcial: revisa el estado y los errores de cada fuente.')
        return 130 if interrupted else (3 if incomplete else 0)
    except OSError as exc:
        print('Error local de archivos (' + type(exc).__name__ + ').', file=sys.stderr)
        if directory:
            print('Ejecución incompleta: ' + str(directory), file=sys.stderr)
        return 2
    finally:
        os.umask(old_umask)


if __name__ == '__main__':
    sys.exit(main())
PY_RECON
