# core/engine.py

import asyncio
import time
from typing import List, Dict, Any, Callable


class AsyncEngine:
    """
    High-performance async execution engine
    Designed for large-scale service scanning
    """

    def __init__(
        self,
        max_concurrency: int = 300,
        base_rate_delay: float = 0.0,
        adaptive_rate: bool = True,
        enable_metrics: bool = True,
    ):
        self.max_concurrency = max_concurrency
        self.base_rate_delay = base_rate_delay
        self.rate_delay = base_rate_delay
        self.adaptive_rate = adaptive_rate
        self.enable_metrics = enable_metrics

        self._semaphore = asyncio.Semaphore(max_concurrency)

        self._results: List[Dict[str, Any]] = []
        self._errors: List[Dict[str, Any]] = []

        self._error_count = 0
        self._executed_tasks = 0

        self._start_time = None
        self._end_time = None

    # ---------------------------------------------------------
    # PUBLIC ENTRYPOINT
    # ---------------------------------------------------------

    async def run(
        self,
        scan_jobs: List[Dict[str, Any]],
        dispatcher: Callable,
    ) -> List[Dict[str, Any]]:

        self._start_time = time.time()

        tasks = [
            asyncio.create_task(self._execute_job(job, dispatcher))
            for job in scan_jobs
        ]

        await asyncio.gather(*tasks, return_exceptions=False)

        self._end_time = time.time()

        return self._results

    # ---------------------------------------------------------
    # INTERNAL JOB EXECUTION
    # ---------------------------------------------------------

    async def _execute_job(self, job: Dict[str, Any], dispatcher: Callable):

        async with self._semaphore:

            # Adaptive rate limiting delay
            if self.rate_delay > 0:
                await asyncio.sleep(self.rate_delay)

            try:
                result = await dispatcher(
                    job["ip"],
                    job["port"],
                    job["service"],
                    job["version"],
                )

                self._executed_tasks += 1

                if result:
                    self._results.append(result)

            except Exception as e:
                self._error_count += 1
                self._errors.append({
                    "ip": job.get("ip"),
                    "port": job.get("port"),
                    "service": job.get("service"),
                    "error": str(e),
                })

            # Adaptive rate logic
            if self.adaptive_rate:
                self._adjust_rate()

    # ---------------------------------------------------------
    # ADAPTIVE RATE CONTROL
    # ---------------------------------------------------------

    def _adjust_rate(self):

        # If too many errors → slow down
        if self._error_count > 50:
            self.rate_delay = min(self.rate_delay + 0.01, 0.5)

        # If stable execution → gradually speed up
        if self._error_count == 0 and self.rate_delay > self.base_rate_delay:
            self.rate_delay = max(self.rate_delay - 0.005, self.base_rate_delay)

    # ---------------------------------------------------------
    # METRICS
    # ---------------------------------------------------------

    def get_metrics(self) -> Dict[str, Any]:

        if not self.enable_metrics:
            return {}

        total_time = None
        if self._start_time and self._end_time:
            total_time = round(self._end_time - self._start_time, 2)

        tasks_per_second = None
        if total_time and total_time > 0:
            tasks_per_second = round(self._executed_tasks / total_time, 2)

        return {
            "execution_time_seconds": total_time,
            "total_tasks_executed": self._executed_tasks,
            "total_errors": self._error_count,
            "tasks_per_second": tasks_per_second,
            "max_concurrency": self.max_concurrency,
            "final_rate_delay": round(self.rate_delay, 4),
        }

    def get_errors(self) -> List[Dict[str, Any]]:
        return self._errors