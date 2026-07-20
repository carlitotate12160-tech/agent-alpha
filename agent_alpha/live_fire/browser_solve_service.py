"""browser_solve service — Camoufox-backed CF/Turnstile solver (9c DeepSeek lane).

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
                         │  1. Reuse persistent Camoufox instance │
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
  - Camoufox (a hardened Firefox fork) for engine-level fingerprint evasion —
    canvas, WebGL, audio, font, and screen noise are injected via native
    patches rather than JS-layer property overrides. This avoids the
    `Function.prototype.toString` tell that JS-only stealth patches
    (playwright-stealth, hand-rolled navigator.webdriver overrides) leave
    behind, and sidesteps the CDP-protocol artifacts Chromium automation
    exposes even with those patches applied.
  - A fresh per-context fingerprint identity (navigator, screen, WebGL,
    fonts, audio/canvas noise seeds) is generated for every request via
    ``camoufox.async_api.AsyncNewContext`` while the underlying Firefox
    process is reused — see Performance below.

Performance: a single Camoufox (Firefox) process is lazily launched once and
reused across requests (``_get_browser``) — only a lightweight
``BrowserContext`` (with its own randomised fingerprint) is created/destroyed
per solve, avoiding the multi-second cold-launch cost on constrained ARM64
hosts. Concurrent solves are bounded by ``_solve_semaphore`` so a burst of
requests cannot exhaust a small VM.

Run on Oracle ARM64 (Camoufox ships pre-built Firefox binaries for
linux/arm64):

    pip install "camoufox[geoip]"
    python -m camoufox fetch
    uvicorn agent_alpha.live_fire.browser_solve_service:app \\
        --host 127.0.0.1 --port 8080

Then set on the runner side:

    export A1_BROWSER_SOLVE_ENDPOINT=http://localhost:8080/solve
"""

from __future__ import annotations

import asyncio
import logging
import os
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

AsyncNewBrowser: Any = None
AsyncNewContext: Any = None
try:
    from camoufox.async_api import AsyncNewBrowser as _AsyncNewBrowser
    from camoufox.async_api import AsyncNewContext as _AsyncNewContext

    AsyncNewBrowser = _AsyncNewBrowser
    AsyncNewContext = _AsyncNewContext
except ImportError:  # pragma: no cover — exercised only when camoufox unavailable
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


# ── Challenge detection configuration ─────────────────────────────────────────

# CF challenge selectors — covers Turnstile + managed challenge
_CHALLENGE_SELECTORS = [
    "#challenge-running",
    "#challenge-stage",
    ".cf-turnstile",
    "iframe[src*='challenges.cloudflare.com']",
    "#cf-please-wait",
    ".cf-browser-verification",
]

# Max wait for challenge to auto-solve per attempt (seconds)
_CHALLENGE_TIMEOUT_SEC = 20
# Max wait for page navigation (seconds)
_NAV_TIMEOUT_SEC = 30
# Extra wait after challenge clears for page to settle
_POST_CHALLENGE_WAIT_SEC = 5
# Max solve attempts before giving up
_MAX_SOLVE_ATTEMPTS = 3


# ── Persistent browser lifecycle ──────────────────────────────────────────────


async def _get_browser() -> Any:
    """Lazily launch and cache a single persistent Camoufox (Firefox) instance.

    Reusing one browser process across requests avoids the multi-second
    cold-launch cost per solve on constrained ARM64 hosts; only a lightweight
    ``BrowserContext`` (not the whole browser process) is created/destroyed
    per request in :func:`_solve_and_fetch`.
    """
    if async_playwright is None or AsyncNewBrowser is None:
        raise RuntimeError(
            'camoufox is not installed. Run: pip install "camoufox[geoip]" && python -m camoufox fetch'
        )
    async with _browser_lock:
        if _browser_state["browser"] is None:
            pw = await async_playwright().start()
            # headless="virtual" uses Xvfb on Linux — some CF/Turnstile
            # challenges detect true headless mode; a virtual display
            # avoids that detection without needing a real GPU/display.
            headless_mode = os.environ.get("BROWSER_SOLVE_HEADLESS", "virtual")
            browser = await AsyncNewBrowser(pw, headless=headless_mode)
            _browser_state["playwright"] = pw
            _browser_state["browser"] = browser
        return _browser_state["browser"]


# ── Core solver ───────────────────────────────────────────────────────────────


async def _solve_and_fetch(url: str, engagement_id: str) -> SolveResponse:
    """Drive a stealth Camoufox (Firefox) browser to solve CF challenge and fetch page.

    This function is the heart of the 9c service. It:
    0. Refuses any non-lab target BEFORE any network egress (defense-in-depth)
    1. Reuses the persistent Camoufox (Firefox) instance (lazy singleton)
    2. Opens a fresh, lightweight BrowserContext with its own randomised
       fingerprint identity for this request only
    3. Navigates to the target URL
    4. Detects CF challenge presence
    5. Waits for challenge to auto-solve
    6. Extracts final page content, cookies, and response headers

    Concurrency is bounded by ``_solve_semaphore`` so a burst of requests
    cannot spawn unbounded contexts on a small host.
    """
    # Defense-in-depth: this service is reachable over HTTP with a
    # caller-supplied target, wider surface than argv/YAML-driven harnesses.
    # Refuse anything outside the self-owned lab allowlist before any egress.
    assert_lab_only_target(url)

    async with _solve_semaphore:
        browser = await _get_browser()

        # AsyncNewContext generates a fresh fingerprint identity (navigator,
        # screen, WebGL, fonts, audio/canvas noise seeds) for this request
        # only; the underlying Firefox process above is reused.
        context = await AsyncNewContext(
            browser,
            locale="en-US",
            timezone_id="America/New_York",
            java_script_enabled=True,
            ignore_https_errors=True,
            viewport={"width": 1920, "height": 1080},
            screen={"width": 1920, "height": 1080},
        )
        try:
            page = await context.new_page()

            logger.info("browser_solve: navigating to %s (engagement=%s)", url, engagement_id)

            # Use domcontentloaded + short settle wait instead of networkidle
            # (networkidle can hang on persistent connections like websockets)
            response = await page.goto(
                url, wait_until="domcontentloaded", timeout=_NAV_TIMEOUT_SEC * 1000
            )
            # Brief wait for Turnstile iframe to render
            await asyncio.sleep(2)

            # Detect CF challenge
            challenge_encountered = await _detect_challenge(page)
            challenge_solved = False

            if challenge_encountered:
                logger.info("browser_solve: CF challenge detected, attempting solve...")
                # Try up to _MAX_SOLVE_ATTEMPTS rounds of click + wait
                for attempt in range(_MAX_SOLVE_ATTEMPTS):
                    logger.info(
                        "browser_solve: solve attempt %d/%d",
                        attempt + 1,
                        _MAX_SOLVE_ATTEMPTS,
                    )
                    challenge_solved = await _wait_for_challenge_clear(page)
                    if challenge_solved:
                        break
                    # Human-like pause before retry
                    await asyncio.sleep(2)

                if challenge_solved:
                    # Wait for page to settle after challenge clears
                    await asyncio.sleep(_POST_CHALLENGE_WAIT_SEC)
                    # Reload to get the real page — fallback to existing body
                    # if reload times out (don't lose the solved state)
                    try:
                        response = await page.goto(
                            url,
                            wait_until="domcontentloaded",
                            timeout=_NAV_TIMEOUT_SEC * 1000,
                        )
                        logger.info("browser_solve: challenge solved, page reloaded")
                    except Exception as e:
                        logger.warning(
                            "browser_solve: reload failed after solve, using current page: %s",
                            e,
                        )
                else:
                    logger.warning(
                        "browser_solve: challenge did not solve after %d attempts",
                        _MAX_SOLVE_ATTEMPTS,
                    )

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
    """Wait for CF challenge to auto-solve. Returns True if cleared.

    Tries multiple strategies in order:
    1. Click the Turnstile checkbox via frame_locator (cross-origin safe)
    2. Click the Turnstile iframe bounding box directly
    3. Wait for challenge selectors to disappear
    4. Wait for page title to change from "Just a moment..."
    5. Re-check if challenge is still present
    """
    # Strategy 1: Use frame_locator to click inside cross-origin iframe
    # Playwright's frame_locator can interact with cross-origin frames
    # where content_frame() + query_selector would fail.
    try:
        # Human-like delay before interacting
        await asyncio.sleep(1)

        # Try clicking the Turnstile checkbox via frame_locator
        turnstile_locator = page.frame_locator("iframe[src*='challenges.cloudflare.com']")
        # The checkbox is inside a label or div container
        try:
            await turnstile_locator.locator("input[type='checkbox']").click(timeout=5000)
            logger.info("browser_solve: clicked Turnstile checkbox via frame_locator")
        except Exception:
            # Try clicking the body of the iframe (sometimes the checkbox
            # is wrapped or the click target is the container)
            try:
                await turnstile_locator.locator("body").click(timeout=5000)
                logger.info("browser_solve: clicked Turnstile iframe body")
            except Exception:
                # Strategy 2: Click the iframe element directly by bounding box
                iframe_element = await page.query_selector(
                    "iframe[src*='challenges.cloudflare.com']"
                )
                if iframe_element is not None:
                    box = await iframe_element.bounding_box()
                    if box is not None:
                        # Click slightly left-center where checkbox usually is
                        await page.mouse.click(
                            box["x"] + 30,
                            box["y"] + box["height"] / 2,
                        )
                        logger.info(
                            "browser_solve: clicked Turnstile iframe at (%.0f, %.0f)",
                            box["x"] + 30,
                            box["y"] + box["height"] / 2,
                        )
    except Exception as e:
        logger.debug("browser_solve: Turnstile click attempt failed: %s", e)

    # Strategy 3: Wait for challenge selectors to disappear
    for selector in _CHALLENGE_SELECTORS:
        try:
            await page.wait_for_selector(
                selector, state="hidden", timeout=_CHALLENGE_TIMEOUT_SEC * 1000
            )
        except Exception:
            pass

    # Strategy 4: Wait for title to change from "Just a moment..."
    try:
        await page.wait_for_function(
            "() => document.title && !document.title.toLowerCase().includes('just a moment')",
            timeout=_CHALLENGE_TIMEOUT_SEC * 1000,
        )
    except Exception:
        pass

    # Strategy 5: Verify challenge actually cleared — re-check detection
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
