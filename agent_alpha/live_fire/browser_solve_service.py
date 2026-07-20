"""browser_solve service — Playwright-backed CF/Turnstile solver (9c DeepSeek lane).

This is the **server side** of the 9c contract. It exposes an HTTP endpoint
that the :class:`DeepSeekBrowserSolve` adapter (Claude lane) calls via POST.

Architecture:

    a1_validation_runner → DeepSeekBrowserSolve (HTTP adapter)
                                        │
                                        ▼
                         ┌──────────────────────────────────────┐
                         │  browser_solve_service (this file)    │
                         │                                       │
                         │  0. assert_lab_only_target(url) FIRST  │
                         │  1. Reuse persistent Chromium instance │
                         │  2. New lightweight context per request│
                         │  3. Navigate to target URL             │
                         │  4. Detect CF challenge (Turnstile)    │
                         │  5. Wait for auto-solve / interact     │
                         │  6. Extract body, cookies, headers     │
                         │  7. Return JSON to adapter             │
                         └──────────────────────────────────────┘
                                        │
                                        ▼
                             alpha-ai.web.id (lab target)

Security (defense-in-depth): the ``target`` for this service is caller
controlled — it arrives in the POST body, not from argv/YAML. That is a wider
attack surface than the other ``live_fire`` harnesses (a network caller could
otherwise point this service at anything), so it independently calls
``assert_lab_only_target`` on every URL BEFORE any network egress, in addition
to the guard already enforced upstream by ``a1_validation_runner``. Never
remove this check even if the only caller is trusted — belt-and-suspenders is
the point.

Stealth techniques applied:
  - Chromium with --disable-blink-features=AutomationControlled
  - Navigator webdriver / plugins / languages / chrome.runtime overrides
  - Realistic User-Agent + viewport randomisation
  - Optional ``playwright-stealth`` (soft dependency) for deeper patches
    (WebGL vendor/renderer, iframe contentWindow, etc.) if installed —
    the hand-rolled JS above is detectable by a `Function.prototype.toString`
    check on the patched getters; playwright-stealth patches more of the
    surface. For CF Turnstile specifically, a Firefox-based fingerprint
    (e.g. camoufox) is a stronger drop-in replacement for the
    ``pw.chromium.launch(...)`` call below if this JS-only approach proves
    insufficient against a hardened Turnstile deployment.

Performance: a single Chromium process is lazily launched once and reused
across requests (``_get_browser``) — only a lightweight ``BrowserContext`` is
created/destroyed per solve, avoiding the ~1-3s cold-launch cost on
constrained ARM64 hosts. Concurrent solves are bounded by ``_solve_semaphore``
so a burst of requests cannot exhaust a small VM.

Run on Oracle ARM64:

    pip install playwright && playwright install chromium
    # optional, more sophisticated stealth patches:
    pip install playwright-stealth
    uvicorn agent_alpha.live_fire.browser_solve_service:app \\
        --host 127.0.0.1 --port 8080

Then set on the runner side:

    export A1_BROWSER_SOLVE_ENDPOINT=http://localhost:8080/solve
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from agent_alpha.live_fire.lab_guard import assert_lab_only_target

logger = logging.getLogger(__name__)

async_playwright: Any = None
try:
    from playwright.async_api import async_playwright as _async_playwright

    async_playwright = _async_playwright
except ImportError:  # pragma: no cover — exercised only when playwright unavailable
    pass

stealth_async: Any = None
try:
    from playwright_stealth import stealth_async as _stealth_async

    stealth_async = _stealth_async
except ImportError:  # pragma: no cover — optional, more sophisticated stealth
    pass


# ── Persistent browser singleton (lazy — never launched at import/startup) ────

_browser_lock = asyncio.Lock()
_browser_state: dict[str, Any] = {"playwright": None, "browser": None}

_MAX_CONCURRENT_SOLVES = int(os.environ.get("BROWSER_SOLVE_MAX_CONCURRENCY", "2"))
_solve_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_SOLVES)


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """No eager startup (keeps import/test collection cheap). On shutdown,
    close the persistent browser ONLY if a request ever launched one."""
    yield
    async with _browser_lock:
        if _browser_state["browser"] is not None:
            await _browser_state["browser"].close()
            _browser_state["browser"] = None
        if _browser_state["playwright"] is not None:
            await _browser_state["playwright"].stop()
            _browser_state["playwright"] = None


app = FastAPI(title="Agent-Alpha browser_solve service", version="9c", lifespan=_lifespan)

# ── Request / response models ─────────────────────────────────────────────────


class SolveRequest(BaseModel):
    url: str
    engagement_id: str


class SolveResponse(BaseModel):
    status_code: int
    body: str
    headers: dict[str, str]
    cleared_cookies: dict[str, str]
    challenge_encountered: bool
    challenge_solved: bool


# ── Stealth configuration ─────────────────────────────────────────────────────

_STEALTH_JS = """
() => {
    // Override navigator.webdriver
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

    // Override chrome.runtime to look real
    window.chrome = { runtime: {} };

    // Override permissions query
    const originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = (parameters) =>
        parameters.name === 'notifications'
            ? Promise.resolve({ state: Notification.permission })
            : originalQuery(parameters);

    // Override plugins to look real
    Object.defineProperty(navigator, 'plugins', {
        get: () => [1, 2, 3, 4, 5],
    });

    // Override languages
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
    });
}
"""

_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

_VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1536, "height": 864},
    {"width": 1440, "height": 900},
    {"width": 1280, "height": 720},
]

# CF challenge selectors — covers Turnstile + managed challenge
_CHALLENGE_SELECTORS = [
    "#challenge-running",
    "#challenge-stage",
    ".cf-turnstile",
    "iframe[src*='challenges.cloudflare.com']",
    "#cf-please-wait",
    ".cf-browser-verification",
]

# Max wait for challenge to auto-solve (seconds)
_CHALLENGE_TIMEOUT_SEC = 30
# Extra wait after challenge clears for page to settle
_POST_CHALLENGE_WAIT_SEC = 3


# ── Persistent browser lifecycle ──────────────────────────────────────────────


async def _get_browser() -> Any:
    """Lazily launch and cache a single persistent Chromium instance.

    Reusing one browser process across requests avoids the ~1-3s cold-launch
    cost per solve on constrained ARM64 hosts; only a lightweight
    ``BrowserContext`` (not the whole browser process) is created/destroyed
    per request in :func:`_solve_and_fetch`.
    """
    if async_playwright is None:
        raise RuntimeError(
            "playwright is not installed. Run: pip install playwright && playwright install chromium"
        )
    async with _browser_lock:
        if _browser_state["browser"] is None:
            pw = await async_playwright().start()
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            _browser_state["playwright"] = pw
            _browser_state["browser"] = browser
        return _browser_state["browser"]


# ── Core solver ───────────────────────────────────────────────────────────────


async def _solve_and_fetch(url: str, engagement_id: str) -> SolveResponse:
    """Drive a stealth Playwright browser to solve CF challenge and fetch page.

    This function is the heart of the 9c service. It:
    0. Refuses any non-lab target BEFORE any network egress (defense-in-depth)
    1. Reuses the persistent Chromium instance (lazy singleton)
    2. Opens a fresh, lightweight BrowserContext for this request only
    3. Injects stealth JS (+ optional playwright-stealth) before navigation
    4. Navigates to the target URL
    5. Detects CF challenge presence
    6. Waits for challenge to auto-solve
    7. Extracts final page content, cookies, and response headers

    Concurrency is bounded by ``_solve_semaphore`` so a burst of requests
    cannot spawn unbounded contexts on a small host.
    """
    # Defense-in-depth: this service is reachable over HTTP with a
    # caller-supplied target, wider surface than argv/YAML-driven harnesses.
    # Refuse anything outside the self-owned lab allowlist before any egress.
    assert_lab_only_target(url)

    async with _solve_semaphore:
        browser = await _get_browser()
        ua = random.choice(_USER_AGENTS)  # nosec B311 — fingerprint rotation, not crypto
        viewport = random.choice(_VIEWPORTS)  # nosec B311 — fingerprint rotation, not crypto

        context = await browser.new_context(
            user_agent=ua,
            viewport=viewport,
            locale="en-US",
            timezone_id="America/New_York",
            java_script_enabled=True,
            ignore_https_errors=True,
        )
        try:
            # Inject stealth JS before every page load
            await context.add_init_script(_STEALTH_JS)

            page = await context.new_page()
            if stealth_async is not None:
                await stealth_async(page)

            logger.info("browser_solve: navigating to %s (engagement=%s)", url, engagement_id)

            response = await page.goto(url, wait_until="domcontentloaded", timeout=60000)

            # Detect CF challenge
            challenge_encountered = await _detect_challenge(page)
            challenge_solved = False

            if challenge_encountered:
                logger.info("browser_solve: CF challenge detected, waiting for auto-solve...")
                challenge_solved = await _wait_for_challenge_clear(page)
                if challenge_solved:
                    # Wait for page to settle after challenge clears
                    await asyncio.sleep(_POST_CHALLENGE_WAIT_SEC)
                    # Reload to get the real page
                    response = await page.goto(url, wait_until="domcontentloaded", timeout=60000)
                    logger.info("browser_solve: challenge solved, page reloaded")
                else:
                    logger.warning("browser_solve: challenge did not auto-solve within timeout")

            # Extract final state
            body = await page.content()
            status_code = response.status if response else 200

            # Extract cookies from context
            cookies_list = await context.cookies()
            cleared_cookies: dict[str, str] = {c["name"]: c["value"] for c in cookies_list}

            # Extract response headers
            headers: dict[str, str] = {}
            if response:
                for key, value in response.headers.items():
                    headers[key.lower()] = value

            return SolveResponse(
                status_code=status_code,
                body=body,
                headers=headers,
                cleared_cookies=cleared_cookies,
                challenge_encountered=challenge_encountered,
                challenge_solved=challenge_solved,
            )
        finally:
            # ALWAYS close the context, even on navigation/timeout errors —
            # the browser process itself is reused, but a leaked context per
            # failed request would still exhaust memory over time.
            await context.close()


async def _detect_challenge(page: Any) -> bool:
    """Check if a CF challenge is present on the page."""
    for selector in _CHALLENGE_SELECTORS:
        try:
            element = await page.query_selector(selector)
            if element is not None:
                return True
        except Exception:
            continue

    # Also check for CF challenge in page title or body text
    try:
        title = await page.title()
        if "just a moment" in title.lower() or "checking your browser" in title.lower():
            return True
    except Exception:
        pass

    return False


async def _wait_for_challenge_clear(page: Any) -> bool:
    """Wait for CF challenge to auto-solve. Returns True if cleared."""
    # Wait for challenge selectors to disappear
    for selector in _CHALLENGE_SELECTORS:
        try:
            await page.wait_for_selector(
                selector, state="hidden", timeout=_CHALLENGE_TIMEOUT_SEC * 1000
            )
        except Exception:
            pass

    # Wait for title to change from "Just a moment..."
    try:
        await page.wait_for_function(
            "() => document.title && !document.title.toLowerCase().includes('just a moment')",
            timeout=_CHALLENGE_TIMEOUT_SEC * 1000,
        )
    except Exception:
        pass

    # Verify challenge actually cleared — re-check detection
    still_challenged = await _detect_challenge(page)
    return not still_challenged


# ── FastAPI endpoint ──────────────────────────────────────────────────────────


@app.post("/solve", response_model=SolveResponse)
async def solve(req: SolveRequest) -> SolveResponse:
    """Solve CF challenge for the given URL and return page content + cookies.

    Any failure (lab-guard refusal, playwright missing, navigation timeout,
    unexpected browser error) is surfaced as a clean HTTP 502 with a
    ``detail`` message — never a raw Python traceback — so the
    ``DeepSeekBrowserSolve`` adapter on the caller side gets a predictable
    ``resp.status_code != 200`` and raises its own ``RuntimeError`` cleanly.
    """
    logger.info("browser_solve /solve: url=%s engagement_id=%s", req.url, req.engagement_id)
    try:
        return await _solve_and_fetch(req.url, req.engagement_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("browser_solve: unexpected failure for url=%s", req.url)
        raise HTTPException(status_code=502, detail=f"browser_solve failed: {exc}") from exc


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "browser_solve", "version": "9c"}


# ── CLI entry point ───────────────────────────────────────────────────────────


def main() -> None:
    import uvicorn

    uvicorn.run(
        "agent_alpha.live_fire.browser_solve_service:app",
        host="127.0.0.1",
        port=8080,
        log_level="info",
    )


if __name__ == "__main__":
    main()
