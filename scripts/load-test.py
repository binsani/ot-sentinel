"""Run a bounded read-only load test against an OT-Sentinel API."""

import argparse
import concurrent.futures
import json
import os
import random
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

ENDPOINTS = (
    "/api/v1/assets?limit=100",
    "/api/v1/assets/sites/summary",
    "/api/v1/assets/risk/summary?limit=500",
    "/api/v1/assets/graph/communications?limit=500",
    "/api/v1/anomalies",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--p95-budget-ms", type=float, default=3_000)
    parser.add_argument("--max-error-rate", type=float, default=0.005)
    parser.add_argument("--allow-remote", action="store_true")
    parser.add_argument("--output")
    return parser.parse_args()


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * percentile_value)))
    return ordered[position]


def validate(args: argparse.Namespace) -> str:
    parsed = urllib.parse.urlparse(args.base_url)
    if parsed.scheme not in {"http", "https"}:
        raise SystemExit("--base-url must use http or https")
    if not args.allow_remote and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("remote targets require --allow-remote")
    if not 1 <= args.duration <= 3_600 or not 1 <= args.concurrency <= 256:
        raise SystemExit("duration must be 1..3600 seconds and concurrency 1..256")
    api_key = os.environ.get("OT_SENTINEL_LOAD_API_KEY")
    if not api_key:
        raise SystemExit("OT_SENTINEL_LOAD_API_KEY is required")
    return api_key


def request_once(base_url: str, api_key: str, endpoint: str) -> tuple[str, int, float]:
    request = urllib.request.Request(
        base_url.rstrip("/") + endpoint,
        headers={"X-API-Key": api_key, "User-Agent": "ot-sentinel-load-test/1"},
    )
    started = time.perf_counter()
    status = 0
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
            response.read()
    except urllib.error.HTTPError as error:
        status = error.code
    except (TimeoutError, urllib.error.URLError):
        status = 0
    return endpoint.split("?", 1)[0], status, (time.perf_counter() - started) * 1_000


def main() -> None:
    args = parse_args()
    api_key = validate(args)
    deadline = time.monotonic() + args.duration

    def worker(worker_id: int) -> list[tuple[str, int, float]]:
        rng = random.Random(worker_id)
        results = []
        while time.monotonic() < deadline:
            results.append(request_once(args.base_url, api_key, rng.choice(ENDPOINTS)))
        return results

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        nested = list(executor.map(worker, range(args.concurrency)))
    results = [result for worker_results in nested for result in worker_results]
    latencies = [result[2] for result in results]
    errors = sum(not 200 <= result[1] < 300 for result in results)
    report = {
        "requests": len(results),
        "errors": errors,
        "error_rate": errors / len(results) if results else 1.0,
        "latency_ms": {
            "median": round(statistics.median(latencies), 2) if latencies else 0,
            "p95": round(percentile(latencies, 0.95), 2),
            "maximum": round(max(latencies), 2) if latencies else 0,
        },
        "status_counts": dict(sorted(Counter(result[1] for result in results).items())),
        "endpoint_counts": dict(sorted(Counter(result[0] for result in results).items())),
        "budgets": {"p95_ms": args.p95_budget_ms, "max_error_rate": args.max_error_rate},
    }
    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as output_file:
            output_file.write(rendered + "\n")
    budget_exceeded = (
        report["error_rate"] > args.max_error_rate
        or report["latency_ms"]["p95"] > args.p95_budget_ms
    )
    if budget_exceeded:
        raise SystemExit("performance budget exceeded")


if __name__ == "__main__":
    main()
