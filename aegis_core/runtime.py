from __future__ import annotations

import argparse
import signal
import time

from aegis_core.config import get_settings
from aegis_core.pipeline import GovernancePipeline


def run_forever(interval: float | None = None, batch_size: int | None = None, seed: int | None = None) -> None:
    settings = get_settings()
    pipeline = GovernancePipeline(seed=seed)
    delay = interval if interval is not None else settings.loop_interval_seconds
    running = True

    def _stop(signum: int, _frame: object) -> None:
        nonlocal running
        running = False
        print(f"received signal {signum}; draining current tick")

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    tick_number = 0
    print("Aegis governance loop started. Worker 1 → 2 → 3.")
    while running:
        tick_number += 1
        result = pipeline.tick(batch_size=batch_size)
        print(
            f"tick={tick_number} "
            f"events={len(result['ingested_events'])} "
            f"violations={len(result['violations'])} "
            f"prs={len(result['pull_requests'])} "
            f"store={result['store']}"
        )
        deadline = time.time() + delay
        while running and time.time() < deadline:
            time.sleep(0.1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Aegis three-worker governance loop.")
    parser.add_argument("--interval", type=float, default=None, help="Seconds between ticks")
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--once", action="store_true", help="Run a single tick and exit")
    args = parser.parse_args()
    if args.once:
        result = GovernancePipeline(seed=args.seed).tick(batch_size=args.batch_size)
        print(result)
        return
    run_forever(interval=args.interval, batch_size=args.batch_size, seed=args.seed)


if __name__ == "__main__":
    main()
