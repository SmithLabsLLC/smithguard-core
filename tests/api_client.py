"""Ordinary API tests begin after the real initial coverage task succeeds.

Startup/failure tests use FastAPI's raw TestClient so they can inspect the
unavailable interval. This helper sends no extra requests and does not prime or
replace the production builder.
"""

import asyncio
import sys

from fastapi.testclient import TestClient as FastAPITestClient


def coverage_runtime(app):
    return next(
        route.endpoint.__self__
        for route in app.routes
        if getattr(route, "path", None) == "/v1/artifacts/assess"
    )


async def wait_for_initial_coverage(app):
    await asyncio.wait_for(coverage_runtime(app).coverage_ready.wait(), 10)


class TestClient(FastAPITestClient):
    __test__ = False

    def __init__(self, app, *args, readiness_app=None, **kwargs):
        self.readiness_app = readiness_app if readiness_app is not None else app
        super().__init__(app, *args, **kwargs)

    def __enter__(self):
        super().__enter__()
        try:
            self.portal.call(wait_for_initial_coverage, self.readiness_app)
        except BaseException:
            super().__exit__(*sys.exc_info())
            raise
        return self
