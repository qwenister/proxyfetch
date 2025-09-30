#!/usr/bin/env python3
"""
proxyfetch.py — быстрый асинхронный фетчер с ротацией прокси/UA, ретраями и выводом в CSV/JSONL.

Особенности:
- aiohttp, asyncio; конкурентность N
- Ротация прокси и User-Agent на каждый запрос
- Повторные попытки с экспоненциальным джиттером
- Поддержка методов GET/POST, заголовков, куки, form/json тела
- Чтение URL из файла или CLI
- Фильтр по HTTP-коду и/или regex по контенту
- Вывод: results.jsonl + results.csv (+ сохранение тел по опции)

Примечание: поддерживаются http/https прокси вида http://user:pass@host:port . SOCKS не поддержан без доп. зависимости.

Установка:
  python -m venv .venv && source .venv/bin/activate
  pip install aiohttp pandas

Примеры:
  python proxyfetch.py --urls urls.txt --proxies proxies.txt --ua-pool user_agents.txt \
      --concurrency 20 --retries 3 --timeout 15 --out out --save-bodies ./bodies

  python proxyfetch.py https://example.com https://httpbin.org/get --status-allow 200 204

Автор: для открытого репозитория (MIT).
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Dict, Any, Tuple

import aiohttp

# -------------------------
# УТИЛИТЫ ЧТЕНИЯ ФАЙЛОВ
# -------------------------

def read_lines(path: Optional[str]) -> List[str]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        print(f"[warn] file not found: {path}", file=sys.stderr)
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]


def read_json(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        print(f"[warn] json not found: {path}", file=sys.stderr)
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[warn] bad json {path}: {e}", file=sys.stderr)
        return {}


# -------------------------
# МОДЕЛИ
# -------------------------

@dataclass
class Job:
    url: str
    idx: int

@dataclass
class Result:
    url: str
    status: Optional[int]
    ok: bool
    elapsed_ms: int
    bytes: int
    proxy: Optional[str]
    ua: Optional[str]
    error: Optional[str]
    path: Optional[str]


# -------------------------
# ПРОКСИ/UA РОТАЦИЯ
# -------------------------

class RoundRobin:
    def __init__(self, items: List[str]):
        self.items = items or []
        self.i = 0

    def next(self) -> Optional[str]:
        if not self.items:
            return None
        v = self.items[self.i % len(self.items)]
        self.i += 1
        return v


# -------------------------
# ОСНОВНАЯ ЛОГИКА ЗАПРОСОВ
# -------------------------

async def fetch_one(session: aiohttp.ClientSession, job: Job, *,
                    method: str, data: Optional[str], json_data: Optional[Dict[str, Any]],
                    headers_base: Dict[str, str], cookies: Dict[str, str],
                    rr_proxy: RoundRobin, rr_ua: RoundRobin,
                    retries: int, timeout: int,
                    delay_range: Tuple[float, float],
                    save_dir: Optional[Path],
                    status_allow: Optional[List[int]],
                    content_regex: Optional[re.Pattern]) -> Result:
    t0 = time.perf_counter()
    proxy = rr_proxy.next()
    ua = rr_ua.next()

    attempt = 0
    last_err: Optional[str] = None

    # Собираем заголовки
    headers = dict(headers_base)
    if ua:
        headers.setdefault("User-Agent", ua)

    while attempt <= retries:
        try:
            if attempt:
                # бэкофф с джиттером
                await asyncio.sleep(min(5.0, 0.3 * (2 ** (attempt - 1))) + random.random() * 0.2)
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with session.request(method.upper(), job.url,
                                       data=data, json=json_data,
                                       timeout=timeout_obj,
                                       headers=headers or None,
                                       cookies=cookies or None,
                                       proxy=proxy) as resp:
                body = await resp.read()
                ok = 200 <= resp.status < 300
                # фильтры
                if status_allow is not None:
                    ok = ok and (resp.status in status_allow)
                if content_regex is not None:
                    try:
                        ok = ok and bool(content_regex.search(body.decode(errors="ignore")))
                    except Exception:
                        ok = False
                save_path = None
                if save_dir is not None:
                    save_dir.mkdir(parents=True, exist_ok=True)
                    fname = f"{job.idx:05d}_{resp.status}.bin"
                    fpath = save_dir / fname
                    fpath.write_bytes(body)
                    save_path = str(fpath)
                elapsed_ms = int((time.perf_counter() - t0) * 1000)
                return Result(url=job.url, status=resp.status, ok=ok, elapsed_ms=elapsed_ms,
                              bytes=len(body), proxy=proxy, ua=ua, error=None, path=save_path)
        except Exception as e:
            last_err = str(e)
        attempt += 1

    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    return Result(url=job.url, status=None, ok=False, elapsed_ms=elapsed_ms,
                  bytes=0, proxy=proxy, ua=ua, error=last_err, path=None)


async def worker(name: str, q: "asyncio.Queue[Job]", **kwargs) -> List[Result]:
    out: List[Result] = []
    while True:
        job = await q.get()
        if job is None:  # type: ignore
            q.task_done()
            break
        # межзапросная задержка (джиттер)
        delay_min, delay_max = kwargs.get("delay_range", (0.0, 0.0))
        if delay_max > 0:
            await asyncio.sleep(random.uniform(delay_min, delay_max))
        res = await fetch_one(**kwargs, job=job)
        out.append(res)
        # лаконичный прогресс
        status = res.status if res.status is not None else "ERR"
        print(f"[{name}] #{job.idx} {status} {res.elapsed_ms}ms {res.bytes}B — {job.url}")
        q.task_done()
    return out


async def run(opts: argparse.Namespace) -> List[Result]:
    urls: List[str] = []
    if opts.urls:
        urls.extend(read_lines(opts.urls))
    urls.extend(opts.urls_inline or [])
    urls = [u for u in urls if u]
    if not urls:
        print("Нет URL для запроса", file=sys.stderr)
        sys.exit(2)

    proxies = read_lines(opts.proxies)
    uas = read_lines(opts.ua_pool)
    headers = read_json(opts.headers)
    cookies = read_json(opts.cookies)

    rr_proxy = RoundRobin(proxies)
    rr_ua = RoundRobin(uas)

    jobs = [Job(url=u, idx=i) for i, u in enumerate(urls, 1)]
    q: asyncio.Queue[Job] = asyncio.Queue()
    for j in jobs:
        await q.put(j)
    for _ in range(opts.concurrency):
        await q.put(None)  # сигналы завершения

    connector = aiohttp.TCPConnector(limit=0, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        workers = [asyncio.create_task(worker(f"W{i+1}", q,
                                             session=session,
                                             method=opts.method,
                                             data=opts.data,
                                             json_data=read_json(opts.json) if opts.json else None,
                                             headers_base=headers,
                                             cookies=cookies,
                                             rr_proxy=rr_proxy,
                                             rr_ua=rr_ua,
                                             retries=opts.retries,
                                             timeout=opts.timeout,
                                             delay_range=(opts.delay_min, opts.delay_max),
                                             save_dir=Path(opts.save_bodies) if opts.save_bodies else None,
                                             status_allow=list(map(int, opts.status_allow)) if opts.status_allow else None,
                                             content_regex=re.compile(opts.grep, re.IGNORECASE | re.DOTALL) if opts.grep else None))
                   for i in range(opts.concurrency)]
        results_nested = await asyncio.gather(*workers)

    results = [r for sub in results_nested for r in sub]
    results.sort(key=lambda r: (r.ok is False, (r.status or 0) >= 400, r.elapsed_ms))

    out_prefix = opts.out
    jsonl = Path(f"{out_prefix}.jsonl")
    csvp = Path(f"{out_prefix}.csv")

    with jsonl.open("w", encoding="utf-8") as jf:
        for r in results:
            jf.write(json.dumps(r.__dict__, ensure_ascii=False) + "\n")

    with csvp.open("w", newline="", encoding="utf-8") as cf:
        w = csv.writer(cf)
        w.writerow(["url", "status", "ok", "elapsed_ms", "bytes", "proxy", "ua", "error", "path"])
        for r in results:
            w.writerow([r.url, r.status, int(r.ok), r.elapsed_ms, r.bytes, r.proxy or "", r.ua or "", r.error or "", r.path or ""])

    print(f"\nSaved: {jsonl} and {csvp}")
    return results


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Async fetcher with proxy/UA rotation and retries")
    p.add_argument("urls_inline", nargs="*", help="URL через пробел")
    p.add_argument("--urls", help="Файл со списком URL (по одному в строке)")
    p.add_argument("--proxies", help="Файл с прокси http(s)://user:pass@host:port")
    p.add_argument("--ua-pool", help="Файл с User-Agent строками")
    p.add_argument("--headers", help="headers.json (dict)")
    p.add_argument("--cookies", help="cookies.json (dict)")
    p.add_argument("--method", default="GET", help="HTTP метод (GET/POST)")
    p.add_argument("--data", help="Отправить как form/data (строка или @file.txt)")
    p.add_argument("--json", help="Отправить JSON из файла (json)")
    p.add_argument("--concurrency", type=int, default=20)
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--delay-min", type=float, default=0.0)
    p.add_argument("--delay-max", type=float, default=0.0)
    p.add_argument("--grep", help="Regex: тело должно содержать совпадение")
    p.add_argument("--status-allow", nargs="*", help="Список допущенных кодов (например 200 204)")
    p.add_argument("--save-bodies", help="Папка для сохранения ответов")
    p.add_argument("--out", default="results", help="Префикс файлов вывода")
    return p


def parse_data_arg(opts: argparse.Namespace) -> None:
    # Позволяет --data @file.txt
    if opts.data and opts.data.startswith("@"):
        path = Path(opts.data[1:])
        opts.data = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else opts.data


def main() -> None:
    parser = build_parser()
    opts = parser.parse_args()
    parse_data_arg(opts)
    try:
        asyncio.run(run(opts))
    except KeyboardInterrupt:
        print("\n[ctrl-c] cancelled", file=sys.stderr)


if __name__ == "__main__":
    main()
