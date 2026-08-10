import argparse
import time

from app.anomalies import analyze_active_baselines
from app.database import SessionLocal


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect new communication edges")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval-seconds", type=int, default=60)
    args = parser.parse_args()
    while True:
        with SessionLocal() as session:
            analyze_active_baselines(session)
        if not args.watch:
            return
        time.sleep(max(5, args.interval_seconds))


if __name__ == "__main__":
    main()
