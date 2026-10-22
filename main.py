import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
import time
import json
import argparse
import sys
import sqlite3
from pathlib import Path
from typing import List, Dict, Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

DEFAULT_TEST_URL = "https://httpbin.org/ip"
DEFAULT_TIMEOUT = 5.0
DEFAULT_CONCURRENT = 100
DB_NAME = "proxy_audit.db"


def init_db(db_path: str):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proxy TEXT NOT NULL,
                status TEXT NOT NULL,
                latency_ms REAL,
                ip TEXT,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def save_to_db(db_path: str, results: List[Dict[str, Any]]):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        for res in results:
            cursor.execute("""
                INSERT INTO checks (proxy, status, latency_ms, ip)
                VALUES (?, ?, ?, ?)
            """, (res["proxy"], res["status"], res["latency_ms"], res["ip"]))
        conn.commit()


async def check_proxy(semaphore: asyncio.Semaphore, session: aiohttp.ClientSession, proxy: str, test_url: str,
                      timeout: float) -> Dict[str, Any]:
    clean_proxy = proxy.strip()
    formatted_proxy = f"http://{clean_proxy}" if not clean_proxy.startswith(
        ("http://", "https://", "socks4://", "socks5://")) else clean_proxy
    start_time = time.perf_counter()

    async with semaphore:
        try:
            connector = ProxyConnector.from_url(formatted_proxy)
            async with aiohttp.ClientSession(connector=connector) as client:
                async with client.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        latency = round((time.perf_counter() - start_time) * 1000, 2)
                        return {
                            "proxy": clean_proxy,
                            "status": "ALIVE",
                            "latency_ms": latency,
                            "ip": data.get("origin", "Unknown")
                        }
        except (asyncio.TimeoutError, aiohttp.ClientError, Exception):
            pass

    return {
        "proxy": clean_proxy,
        "status": "DEAD",
        "latency_ms": None,
        "ip": None
    }


async def run_validator(proxy_list: List[str], test_url: str, timeout: float, concurrency: int) -> List[Dict[str, Any]]:
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [check_proxy(semaphore, session, proxy, test_url, timeout) for proxy in proxy_list if proxy.strip()]

        results = []
        with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
        ) as progress:
            task = progress.add_task("[cyan]Валидация эндпоинтов...", total=len(tasks))

            for coro in asyncio.as_completed(tasks):
                res = await coro
                results.append(res)
                progress.update(task, advance=1)

        return results


def parse_args():
    parser = argparse.ArgumentParser(description="Enterprise Async Proxy Validator & Audit Tool")
    parser.add_argument("-i", "--input", required=True, help="Путь к файлу со списком прокси")
    parser.add_argument("-o", "--output", default="alive_proxies.json", help="Файл для сохранения JSON-отчета")
    parser.add_argument("-d", "--database", default=DB_NAME, help="Путь к SQLite базе данных")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="Таймаут запроса в секундах")
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENT,
                        help="Максимальное число параллельных потоков")
    parser.add_argument("--url", default=DEFAULT_TEST_URL, help="URL для проверки соединения")
    return parser.parse_args()


def main():
    args = parse_args()
    input_path = Path(args.input)

    if not input_path.exists():
        console.print(f"[bold red][-] Ошибка: файл {input_path} не найден.[/bold red]")
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        proxies = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not proxies:
        console.print("[bold red][-] Ошибка: файл прокси пуст.[/bold red]")
        sys.exit(1)

    console.print(f"[bold green][*][/bold green] Загружено эндпоинтов: {len(proxies)}")
    console.print(f"[bold green][*][/bold green] Инициализация хранилища SQLite: {args.database}")
    init_db(args.database)

    start_global = time.perf_counter()
    results = asyncio.run(run_validator(proxies, args.url, args.timeout, args.concurrency))
    elapsed = round(time.perf_counter() - start_global, 2)

    alive = [r for r in results if r["status"] == "ALIVE"]

    console.print(f"\n[bold cyan][+] Проверка завершена за {elapsed} сек.[/bold cyan]")
    console.print(f"[bold green][+] Рабочих эндпоинтов: {len(alive)}/{len(proxies)}[/bold green]")

    save_to_db(args.database, results)

    output_path = Path(args.output)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    console.print(f"[bold blue][+] JSON-отчет сохранен в:[/bold blue] {output_path.resolve()}")
    console.print(f"[bold blue][+] История аудита записана в БД:[/bold blue] {Path(args.database).resolve()}")


if __name__ == "__main__":
    main()