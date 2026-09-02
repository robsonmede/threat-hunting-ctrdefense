"""Execução segura e paralela de consultas."""

from __future__ import annotations

import concurrent.futures
import logging
from dataclasses import dataclass
from typing import Any, Callable


LOGGER = logging.getLogger(__name__)


@dataclass
class SearchOutcome:
    source: str
    success: bool
    data: Any = None
    error: str | None = None
    skipped: bool = False

    def to_dict(self) -> dict[str, Any]:
        if self.skipped:
            return {
                "configured": False,
                "message": self.error or "Fonte não configurada.",
            }
        if not self.success:
            return {"error": self.error or "Falha desconhecida."}
        return self.data


def execute_safe(
    source: str,
    callback: Callable,
    *args,
    **kwargs,
) -> SearchOutcome:
    try:
        result = callback(*args, **kwargs)

        if isinstance(result, dict) and result.get("error"):
            return SearchOutcome(
                source=source,
                success=False,
                data=result,
                error=str(result["error"]),
            )

        return SearchOutcome(
            source=source,
            success=True,
            data=result,
        )
    except Exception as exc:
        LOGGER.exception("Falha na consulta da fonte %s", source)
        return SearchOutcome(
            source=source,
            success=False,
            error=str(exc),
        )


def execute_parallel(
    tasks: dict[str, tuple[Callable, tuple, dict]],
    *,
    max_workers: int = 8,
    timeout: int = 60,
) -> dict[str, Any]:
    """
    tasks = {
        "VirusTotal": (funcao, (arg1, arg2), {"opcao": True}),
    }
    """
    if not tasks:
        return {}

    results: dict[str, Any] = {}

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(max_workers, len(tasks))
    ) as executor:
        futures = {
            executor.submit(execute_safe, source, callback, *args, **kwargs): source
            for source, (callback, args, kwargs) in tasks.items()
        }

        try:
            iterator = concurrent.futures.as_completed(
                futures,
                timeout=timeout,
            )
            for future in iterator:
                source = futures[future]
                try:
                    outcome = future.result()
                    results[source] = outcome.to_dict()
                except Exception as exc:
                    results[source] = {"error": str(exc)}
        except concurrent.futures.TimeoutError:
            for future, source in futures.items():
                if not future.done():
                    future.cancel()
                    results[source] = {
                        "error": f"Consulta excedeu {timeout}s."
                    }

    return results
