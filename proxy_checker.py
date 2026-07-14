#!/usr/bin/env python3
"""
Proxy Checker — утилита для проверки скорости, аптайма и анонимности
SOCKS5/HTTP прокси.

Использование:
    python proxy_checker.py --proxies proxies.txt
    python proxy_checker.py --proxy socks5://user:pass@1.2.3.4:1080

Формат файла со списком прокси (по одному на строку):
    socks5://user:pass@1.2.3.4:1080
    http://1.2.3.4:8080
"""

import argparse
import concurrent.futures
import csv
import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

TEST_URL = "https://httpbin.org/ip"
HEADERS_TEST_URL = "https://httpbin.org/headers"
TIMEOUT = 10
DEFAULT_WORKERS = 20


@dataclass
class ProxyResult:
    proxy: str
    is_alive: bool = False
    latency_ms: Optional[float] = None
    exit_ip: Optional[str] = None
    anonymity: Optional[str] = None  # elite / anonymous / transparent
    error: Optional[str] = None
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def build_requests_proxy_dict(proxy_url: str) -> dict:
    """requests умеет socks5/socks5h/http/https напрямую через схему в URL."""
    return {"http": proxy_url, "https": proxy_url}


def detect_anonymity(proxy_url: str, timeout: int) -> Optional[str]:
    """
    Грубая эвристика анонимности через httpbin.org/headers:
    - elite (high anonymity): сервер не видит вообще никаких proxy-заголовков
    - anonymous: proxy-заголовки есть, но реальный IP клиента не палится
    - transparent: реальный IP клиента виден в заголовках (X-Forwarded-For и т.п.)
    """
    proxies = build_requests_proxy_dict(proxy_url)
    try:
        my_ip = requests.get(TEST_URL, timeout=timeout).json().get("origin", "")
    except Exception:
        my_ip = ""

    try:
        resp = requests.get(HEADERS_TEST_URL, proxies=proxies, timeout=timeout)
        headers = {k.lower(): v for k, v in resp.json().get("headers", {}).items()}
    except Exception:
        return None

    proxy_marker_headers = ["via", "x-forwarded-for", "forwarded", "x-proxy-id", "proxy-connection"]
    has_proxy_markers = any(h in headers for h in proxy_marker_headers)

    if not has_proxy_markers:
        return "elite"

    leaked_ip = headers.get("x-forwarded-for", "") + headers.get("forwarded", "")
    if my_ip and my_ip in leaked_ip:
        return "transparent"

    return "anonymous"


def check_single_proxy(proxy_url: str, timeout: int = TIMEOUT, check_anonymity: bool = False) -> ProxyResult:
    result = ProxyResult(proxy=proxy_url)
    proxies = build_requests_proxy_dict(proxy_url)

    start = time.perf_counter()
    try:
        resp = requests.get(TEST_URL, proxies=proxies, timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000

        if resp.status_code == 200:
            result.is_alive = True
            result.latency_ms = round(elapsed, 1)
            try:
                result.exit_ip = resp.json().get("origin")
            except ValueError:
                result.exit_ip = None
            if check_anonymity:
                result.anonymity = detect_anonymity(proxy_url, timeout)
        else:
            result.error = f"HTTP {resp.status_code}"
    except requests.exceptions.ProxyError as e:
        result.error = f"ProxyError: {e}"
    except requests.exceptions.ConnectTimeout:
        result.error = "Timeout при подключении"
    except requests.exceptions.ReadTimeout:
        result.error = "Timeout при чтении ответа"
    except Exception as e:  # noqa: BLE001 — репортим любую ошибку в отчёт
        result.error = f"{type(e).__name__}: {e}"

    return result


def check_proxies(proxy_list: list[str], workers: int = DEFAULT_WORKERS, check_anonymity: bool = False) -> list[ProxyResult]:
    results: list[ProxyResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(check_single_proxy, p, TIMEOUT, check_anonymity): p for p in proxy_list}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return results


def print_report(results: list[ProxyResult]) -> None:
    alive = [r for r in results if r.is_alive]
    dead = [r for r in results if not r.is_alive]

    print("\n" + "=" * 70)
    print(f"Проверено прокси: {len(results)}  |  Живых: {len(alive)}  |  Мёртвых: {len(dead)}")
    print("=" * 70)

    if alive:
        print("\n✅ РАБОЧИЕ ПРОКСИ (отсортированы по скорости):\n")
        for r in sorted(alive, key=lambda x: x.latency_ms or 999999):
            anon = f"   anonymity={r.anonymity}" if r.anonymity else ""
            print(f"  {r.proxy:<45} {r.latency_ms:>7.1f} ms   exit_ip={r.exit_ip}{anon}")

    if dead:
        print("\n❌ НЕРАБОЧИЕ ПРОКСИ:\n")
        for r in dead:
            print(f"  {r.proxy:<45} {r.error}")

    if alive:
        avg = sum(r.latency_ms for r in alive) / len(alive)
        uptime_pct = round(len(alive) / len(results) * 100, 1)
        print(f"\nСредняя задержка: {avg:.1f} ms   |   Uptime в этой проверке: {uptime_pct}%")
    print()


def export_to_csv(results: list[ProxyResult], path: str) -> None:
    fieldnames = ["proxy", "is_alive", "latency_ms", "exit_ip", "anonymity", "error", "checked_at"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))
    print(f"CSV-отчёт сохранён: {path}")


def export_to_json(results: list[ProxyResult], path: str) -> None:
    alive = [r for r in results if r.is_alive]
    summary = {
        "checked_total": len(results),
        "alive": len(alive),
        "dead": len(results) - len(alive),
        "avg_latency_ms": round(sum(r.latency_ms for r in alive) / len(alive), 1) if alive else None,
        "uptime_pct": round(len(alive) / len(results) * 100, 1) if results else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = {"summary": summary, "results": [asdict(r) for r in results]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"JSON-отчёт сохранён: {path}")


def load_proxies_from_file(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main() -> None:
    global TIMEOUT
    parser = argparse.ArgumentParser(description="Проверка скорости и живости SOCKS5/HTTP прокси")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--proxies", help="Путь к файлу со списком прокси (по одному на строку)")
    group.add_argument("--proxy", help="Один прокси для проверки, например socks5://user:pass@ip:port")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Число параллельных потоков")
    parser.add_argument("--timeout", type=int, default=TIMEOUT, help="Таймаут одного запроса, сек")
    parser.add_argument("--check-anonymity", action="store_true", help="Дополнительно определить уровень анонимности (elite/anonymous/transparent)")
    parser.add_argument("--export-csv", metavar="FILE", help="Сохранить отчёт в CSV, например report.csv")
    parser.add_argument("--export-json", metavar="FILE", help="Сохранить отчёт в JSON, например report.json")
    args = parser.parse_args()

    TIMEOUT = args.timeout

    proxy_list = [args.proxy] if args.proxy else load_proxies_from_file(args.proxies)

    print(f"Запускаю проверку {len(proxy_list)} прокси...")
    results = check_proxies(proxy_list, workers=args.workers, check_anonymity=args.check_anonymity)
    print_report(results)

    if args.export_csv:
        export_to_csv(results, args.export_csv)
    if args.export_json:
        export_to_json(results, args.export_json)


if __name__ == "__main__":
    main()
