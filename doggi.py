#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import urllib3  # Для подавления insecure warnings
from typing import List, Tuple, Dict, Set
from urllib.parse import urlparse, urlunparse, ParseResult
import ipaddress
import socket
import subprocess
import json

# Подавляем InsecureRequestWarning (только для verify=False в DoH fallback)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import dns.message
import dns.rdatatype
import dns.resolver
import dns.query
import dns.exception
import requests

# --- Config / constants ---
# DEFAULT_SERVER = "tls://1.1.1.1"  # DoT по умолчанию
DEFAULT_SERVER = "1.1.1.1"
DNS_PORT_DEFAULT = 53
DOT_PORT_DEFAULT = 853
DOH_PORT_DEFAULT = 443

# Захардкоженные токены (используйте env vars в production!)
IPGEO_TOKEN = '1eba00f291294ab68db898036ef174df'
IPINFO_TOKEN = 'b63c7feb723794'

# Ширины колонок для форматирования
COL_WIDTHS = {
    'TTL': 5,
    'IP': 17,
    'Country': 25,
    'ASN': 50,
    'City': 20,  # Город остаётся последним столбцом
}


def country_to_flag(code: str) -> str:
    """
    Генерирует флаг эмодзи из ISO 3166-1 alpha-2 кода (например, 'RU' -> '🇷🇺').
    """
    if not code or code == 'N/A' or len(code) != 2:
        return ''
    code = code.upper()
    flag = ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code)
    return flag


class ServerSpec:
    def __init__(self, protocol: str, host: str = "", port: int = 0, url: str = ""):
        # protocol: "udp" | "dot" | "doh"
        self.protocol = protocol
        self.host = host
        self.port = port
        self.url = url  # только для DoH


def is_special_ip(ip: str) -> bool:
    """Возвращает True для приватных, локальных, зарезервированных и прочих служебных IP, для которых не имеет смысла делать geo lookup."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # Невалидный IP считаем специальным, чтобы не дёргать API
        return True
    if addr.is_private:
        return True
    if addr.is_loopback:
        return True
    if addr.is_link_local:
        return True
    if addr.is_multicast:
        return True
    if addr.is_reserved:
        return True
    if addr.is_unspecified:
        return True
    return False


def parse_udp_hostport(s: str) -> Tuple[str, int]:
    """
    Парсит UDP host:port, включая IPv6 [addr]:port.
    """
    s = s.strip()
    if s.startswith('[') and ']:' in s:
        bracket_end = s.find(']')
        if bracket_end != -1 and bracket_end + 1 < len(s) and s[bracket_end + 1] == ':':
            host = s[:bracket_end + 1]
            port_str = s[bracket_end + 2:]
            try:
                port = int(port_str) if port_str else DNS_PORT_DEFAULT
            except ValueError:
                port = DNS_PORT_DEFAULT
        else:
            host = s
            port = DNS_PORT_DEFAULT
    elif ':' in s:
        parts = s.rsplit(':', 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            host = s
            port = DNS_PORT_DEFAULT
    else:
        host = s
        port = DNS_PORT_DEFAULT
    return host, port


def parse_server(raw: str) -> ServerSpec:
    """
    Поддержка форм (с @ опционально):
    - @194.58.44.150:54 => UDP IPv4
    - @[2605:e440:2::3:272]:54 => UDP IPv6
    - @tls://nl2.ogne.top:854 => DoT
    - @https://nl2.ogne.top:8443/dns-query => DoH (binary)
    - @https://dns.google/resolve => DoH (JSON)
    """
    s = raw.strip()
    if s.startswith("@"):
        s = s[1:]  # Игнорируем @ silently

    if s.startswith("https://"):
        u = urlparse(s)
        port = u.port if u.port else DOH_PORT_DEFAULT
        # нормализуем URL (оставляем как есть, если путь не указан)
        path = u.path or "/dns-query"
        norm = ParseResult(
            scheme="https",
            netloc=f"{u.hostname}:{port}",
            path=path,
            params="",
            query=u.query,
            fragment="",
        )
        return ServerSpec(protocol="doh", url=urlunparse(norm), host=u.hostname, port=port)

    if s.startswith("tls://"):
        hostport = s[len("tls://") :]
        # Сначала парсим host и port, используя общий helper (в том числе для IPv6)
        host, port = parse_udp_hostport(hostport)
        # Если порт явно не указан (нет ":port" или "]:port"), то для DoT
        # используем стандартный порт DOT_PORT_DEFAULT (853), а не 53
        if ":" not in hostport and not (hostport.startswith("[") and "]:" in hostport):
            port = DOT_PORT_DEFAULT
        return ServerSpec(protocol="dot", host=host, port=port)

    # UDP по умолчанию
    host, port = parse_udp_hostport(s)
    return ServerSpec(protocol="udp", host=host, port=port)


def get_ns_records(domain: str) -> Set[str]:
    """
    Получить список NS records для домена (или родительского, если поддомен).
    Используем delegation walk: если нет NS — стрипим лейбл и повторяем.
    """
    ns_set: Set[str] = set()
    current_domain = domain
    res = dns.resolver.Resolver()
    res.timeout = 10
    res.lifetime = 10

    while current_domain:
        try:
            answers = res.resolve(current_domain, 'NS')  # resolve вместо query (fix deprecation)
            if answers:
                for rdata in answers:
                    ns_set.add(str(rdata.target).rstrip('.'))
                break  # Нашли — выходим
        except dns.resolver.NoAnswer:
            # Нет ответа — поднимаемся к родителю
            pass
        except (dns.resolver.NXDOMAIN, dns.exception.DNSException):
            # Другие ошибки — пропускаем
            break

        # Strip первый лейбл (e.g., nl2.x8lab.org -> x8lab.org)
        if '.' in current_domain:
            current_domain = '.'.join(current_domain.split('.')[1:])
        else:
            break  # Root — стоп

    return ns_set


def resolve_udp(domain: str, spec: ServerSpec) -> List[Tuple[int, str]]:
    res = dns.resolver.Resolver(configure=False)

    # dnspython 2.7+ требует, чтобы nameservers были IP-адресами или валидными URL.
    # Если в spec.host пришло доменное имя (например, "dns.google"), сначала
    # резолвим его через системный резольвер в один или несколько IP и используем
    # первый IP как адрес DNS-сервера.
    target = spec.host
    try:
        # Если это уже корректный IP (v4/v6), ip_address не выбросит исключение
        ipaddress.ip_address(target)
    except ValueError:
        # Не IP-строка: пробуем получить IP через системный DNS
        try:
            infos = socket.getaddrinfo(target, spec.port, type=socket.SOCK_DGRAM)
            addrs = []
            for fam, _, _, _, sa in infos:
                host_ip = sa[0]
                if host_ip not in addrs:
                    addrs.append(host_ip)
            if addrs:
                target = addrs[0]
        except Exception as e:
            print(f"Cannot resolve DNS server hostname {target}: {e}", file=sys.stderr)

    res.nameservers = [target]
    res.port = spec.port
    res.timeout = 10
    res.lifetime = 10

    out: List[Tuple[int, str]] = []
    for rdtype in ("A", "AAAA"):
        try:
            ans = res.resolve(domain, rdtype)  # resolve для consistency
            ttl = ans.rrset.ttl if ans.rrset is not None else 0
            for rdata in ans:
                ip = getattr(rdata, "address", str(rdata))
                out.append((ttl, ip))
        except dns.resolver.NoAnswer:
            # Отсутствие ответа для данного типа (например, нет AAAA) не считаем ошибкой
            continue
        except Exception as e:
            # не прерываем; продолжаем собирать что есть
            print(f"DNS {rdtype} via UDP error: {e}", file=sys.stderr)
    return out


def _extract_from_dns_message(response: dns.message.Message) -> List[Tuple[int, str]]:
    out: List[Tuple[int, str]] = []
    for rrset in response.answer:
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            ttl = rrset.ttl
            for rdata in rrset:
                ip = getattr(rdata, "address", str(rdata))
                out.append((ttl, ip))
    return out


def resolve_dot(domain: str, spec: ServerSpec) -> List[Tuple[int, str]]:
    out: List[Tuple[int, str]] = []

    # Аналогично resolve_udp: если в spec.host доменное имя (например, "dns.google"),
    # резолвим его в IP и используем IP как адрес DoT-сервера, а исходное имя в SNI.
    target = spec.host
    server_hostname = None
    try:
        # Попытка интерпретировать как IP-адрес (v4/v6)
        ipaddress.ip_address(target)
    except ValueError:
        # Не IP: считаем, что это hostname и сохраняем его для SNI
        server_hostname = target
        try:
            infos = socket.getaddrinfo(target, spec.port, type=socket.SOCK_STREAM)
            addrs = []
            for fam, _, _, _, sa in infos:
                host_ip = sa[0]
                if host_ip not in addrs:
                    addrs.append(host_ip)
            if addrs:
                target = addrs[0]
        except Exception as e:
            print(f"Cannot resolve DoT server hostname {target}: {e}", file=sys.stderr)

    for rdtype in ("A", "AAAA"):
        try:
            q = dns.message.make_query(domain, rdtype)
            resp = dns.query.tls(
                q,
                where=target,
                port=spec.port,
                timeout=10,
                server_hostname=server_hostname,
            )
            out.extend(_extract_from_dns_message(resp))
        except Exception as e:
            err_type = type(e).__name__
            # Показываем тип исключения и repr(e), чтобы видеть, что именно пошло не так
            print(f"DNS {rdtype} via DoT error [{err_type}]: {e!r}", file=sys.stderr)
    return out


def resolve_doh(domain: str, spec: ServerSpec) -> List[Tuple[int, str]]:
    """
    Поддерживает два варианта DoH:
    - binary endpoint (/dns-query): dns.query.https (если стандартный 443), fallback requests.post
    - JSON endpoint (/resolve): requests.get
    verify=False только для non-standard (custom port/path).
    """
    out: List[Tuple[int, str]] = []
    u = urlparse(spec.url)
    hostname = u.hostname
    port = u.port or DOH_PORT_DEFAULT
    path = u.path or "/dns-query"

    # JSON-эндпоинт (/resolve)
    if spec.url.endswith("/resolve"):
        def fetch_json(rdtype_name: str) -> None:
            params = {"name": domain, "type": rdtype_name}
            try:
                r = requests.get(spec.url, params=params, timeout=10)
                r.raise_for_status()
                data = r.json()
                answers = data.get("Answer", [])
                for a in answers:
                    t = a.get("type")
                    if (rdtype_name == "A" and t == 1) or (rdtype_name == "AAAA" and t == 28):
                        ttl = a.get("TTL", 0)
                        ip = a.get("data", "")
                        if ip:
                            out.append((ttl, ip))
            except Exception as e:
                print(f"DNS {rdtype_name} via DoH(JSON) error: {e}", file=sys.stderr)

        fetch_json("A")
        fetch_json("AAAA")
        return out

    # Binary DoH: пробуем dns.query.https (только для 443 + /dns-query), fallback requests.post
    use_dns_query = (port == DOH_PORT_DEFAULT and path == "/dns-query")
    verify_cert = use_dns_query  # True для standard (secure), False для custom (e.g., 8443 self-signed)
    for rdtype in ("A", "AAAA"):
        try:
            if use_dns_query:
                q = dns.message.make_query(domain, rdtype)
                resp = dns.query.https(q, where=hostname, timeout=10)  # where=str, port=443 auto
                out.extend(_extract_from_dns_message(resp))
            else:
                raise ValueError("Non-standard")
        except Exception as e:
            # Fallback: requests POST (verify=False для custom)
            try:
                q = dns.message.make_query(domain, rdtype)
                headers = {"Content-Type": "application/dns-message"}
                r = requests.post(spec.url, data=q.to_wire(), headers=headers, timeout=10, verify=verify_cert)
                r.raise_for_status()
                resp = dns.message.from_wire(r.content)
                out.extend(_extract_from_dns_message(resp))
            except Exception as e2:
                print(f"DNS {rdtype} via DoH error: {e2}", file=sys.stderr)
    return out


def resolve_dns(domain: str, server_raw: str) -> Tuple[List[Tuple[int, str]], ServerSpec]:
    spec = parse_server(server_raw)
    if spec.protocol == "udp":
        records = resolve_udp(domain, spec)
    elif spec.protocol == "dot":
        records = resolve_dot(domain, spec)
    elif spec.protocol == "doh":
        records = resolve_doh(domain, spec)
    else:
        raise ValueError("Unsupported protocol")
    return records, spec


def get_geolocation(ip: str) -> Dict[str, str]:
    """
    Lookup геоданных через локальную CLI-команду ipinfo:
    - ipinfo <IP> -j
    Используем только её вывод:
    - country_name и country_flag.emoji для формирования "Country" (флаг + полное название страны),
    - city для "City",
    - org для ASN и ASN-Name (org вида "AS12345 Provider Name").
    Для служебных/приватных IP сразу возвращаем спец-метку без вызова ipinfo.
    """
    NA = {"country": "N/A", "city": "N/A", "asn": "N/A"}

    # Для служебных и приватных IP не дёргаем внешние команды, сразу возвращаем метку
    if is_special_ip(ip):
        return {
            "country": "N/A",
            "city": "Special IP",
            "asn": "Special or local IP (no geo)",
        }

    try:
        # Запускаем локальную CLI ipinfo с JSON-выводом
        proc = subprocess.run(
            ["ipinfo", ip, "-j"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        data = json.loads(proc.stdout)

        # Страна: флаг + полное название
        country_name = data.get("country_name") or "N/A"
        country_code = data.get("country") or ""
        flag_emoji = ""

        # Пытаемся взять эмодзи флага из country_flag, если есть
        cf = data.get("country_flag")
        if isinstance(cf, dict):
            flag_emoji = cf.get("emoji") or ""

        # Если флаг не пришёл, пробуем сгенерировать по ISO-коду
        if not flag_emoji and country_code:
            flag_emoji = country_to_flag(country_code)

        if country_name != "N/A":
            if flag_emoji:
                country_display = f"{flag_emoji}  {country_name}"
            else:
                country_display = country_name
        else:
            country_display = "N/A"

        # Город берём напрямую из ipinfo
        city = data.get("city") or "N/A"

        # ASN: используем org целиком в одном столбце
        org = data.get("org") or "N/A"

        return {
            "country": country_display,
            "city": city,
            "asn": org,
        }
    except Exception as e:
        err_type = type(e).__name__
        # Печатаем только тип ошибки, без длинного вывода
        print(f"Geo CLI error for {ip}: {err_type}", file=sys.stderr)
        return NA


def format_nameserver_for_header(spec: ServerSpec, original: str) -> str:
    """
    Для шапки выводим с протоколом (для DoT/DoH) или host:port (UDP, с [] для IPv6).
    """
    if spec.protocol == "dot":
        return f"tls://{spec.host}:{spec.port}"
    elif spec.protocol == "doh":
        return spec.url
    else:
        return f"{spec.host}:{spec.port}"


def format_row(ttl: int, ip: str, country: str, city: str, asn: str, partial: bool = False) -> str:
    """
    Форматирует строку таблицы с заданными ширинами. Partial: только TTL + IP, остальное пусто.
    Если partial=True, возвращаем строку БЕЗ хвостовых пробелов (только TTL и IP),
    чтобы избежать переноса строки в узких терминалах, который ломает \r.
    """
    ttl_str = f"{ttl:4d}"
    
    # Сначала формируем начало строки
    row_start = (
        f"{ttl_str:>{COL_WIDTHS['TTL']}}  "
        f"{ip:<{COL_WIDTHS['IP']}}"
    )
    
    if partial:
        # Для частичного вывода возвращаем только это, без длинного паддинга справа
        return row_start

    # Для полного вывода добавляем остальное
    return (
        f"{row_start}  "
        f"{country:<{COL_WIDTHS['Country']}}  "
        f"{city:<{COL_WIDTHS['City']}}  "
        f"{asn}"
    )


def print_header():
    """Печатает заголовок таблицы с ширинами."""
    header = (
        f"{'TTL':>{COL_WIDTHS['TTL']}}  "
        f"{'IP':<{COL_WIDTHS['IP']}}  "
        f"{'Country':<{COL_WIDTHS['Country']}}  "
        f"{'City':<{COL_WIDTHS['City']}}  "
        f"{'ASN':<{COL_WIDTHS['ASN']}}"
    )
    print(header)


def main():
    parser = argparse.ArgumentParser(
        description="doggi: DNS resolver with DoH/DoT and online geo (IPGeolocation + IPInfo)"
    )
    parser.add_argument(
        "server",
        nargs="?",
        default=DEFAULT_SERVER,
        help="DNS server (first arg, optional @). Examples: @194.58.44.150:54 | @[2605:e440:2::3:272]:54 | @tls://nl2.ogne.top:854 | @https://nl2.ogne.top:8443/dns-query | @https://dns.google/resolve",
    )
    parser.add_argument("domain", help="Domain to resolve (second arg, e.g., ya.ru)")
    args = parser.parse_args()

    domain = args.domain.strip()
    server_raw = args.server.strip() if args.server else DEFAULT_SERVER

    # Резолвим A/AAAA
    records, spec = resolve_dns(domain, server_raw)

    if not records:
        print("No records found", file=sys.stderr)
        sys.exit(1)

    # Динамически расширяем колонку IP, чтобы влезали IPv6-адреса целиком
    max_ip_len = max((len(ip) for _, ip in records), default=COL_WIDTHS["IP"])
    if max_ip_len > COL_WIDTHS["IP"]:
        COL_WIDTHS["IP"] = max_ip_len + 1  # небольшой запас

    # Получаем NS records (с delegation walk)
    ns_set = get_ns_records(domain)
    ns_str = ', '.join(sorted(ns_set)) if ns_set else "N/A"

    # Новый заголовок (с протоколом)
    print(f"domain: {domain}")
    print(f"dns: {format_nameserver_for_header(spec, server_raw)}")
    print(f"ns: {ns_str}")
    print()

    # Заголовок таблицы
    print_header()
    print()

    # Progressive вывод: partial → overwrite full (без дубликатов)
    seen_ips = set()
    for ttl, ip in records:
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        # Partial строка (TTL + IP, без \n)
        partial_row = format_row(ttl, ip, '', '', '', partial=True)
        print(partial_row, end='', flush=True)

        # API запросы (после partial)
        geo = get_geolocation(ip)

        # Overwrite: \r + full строка + \n
        full_row = format_row(ttl, ip, geo["country"], geo["city"], geo["asn"])
        print(f'\r{full_row}')


if __name__ == "__main__":
    main()
