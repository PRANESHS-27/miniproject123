"""Lightweight HTTP fingerprinting for asset tech detection.

Strategy:
  - Pull the home page (one request, small timeout)
  - Pull /robots.txt and /sitemap.xml opportunistically
  - Match Server / X-Powered-By headers, <meta generator>, cookie names,
    and a small set of body regexes for CMS markers

Returned shape is a list of dicts ready to be inserted as ``AssetTechnology``
rows. All names are lowercased to match NVD's `affected_products[*].vendor`.

Redirect handling: we deliberately do NOT follow redirects during the
initial probe. The original response is the one that tells us what
stack the *asset* runs (e.g., ``server: Vercel``,
``x-vercel-id: …``, ``x-nextjs-prerender: 1``). When the asset is
behind an auth wall (Vercel password protection, Netlify password,
Cloudflare Access), the response is a 3xx to ``vercel.com/login``
or similar — and the headers of that 3xx response still carry the
asset's true fingerprint. Following the redirect would take us to
the auth provider's stack and *that's* what we'd fingerprint,
which is wrong.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import httpx


# Hosts that are auth-walls / login pages for hosting platforms. When the
# initial probe 3xxs to one of these, the asset is password-protected —
# the redirect target isn't the asset, so we don't follow it for tech
# detection. The asset's own headers from the 3xx response are still
# captured and used.
_AUTH_WALL_HOSTS = frozenset({
    "vercel.com",
    "www.vercel.com",
    "netlify.com",
    "app.netlify.com",
    "cloudflare.com",
    "www.cloudflare.com",
    "workers.dev",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "auth0.com",
})


# ---------------------------------------------------------------------------
# Static dictionaries
# ---------------------------------------------------------------------------
HEADER_SIGNATURES: list[dict[str, Any]] = [
    # header_name -> regex (case-insensitive). Vendor/product are CPE-shaped.
    {
        "header": "server",
        "patterns": [
            (r"apache[/\s]([\d.]+)?", "apache", "http_server"),
            (r"nginx[/\s]([\d.]+)?", "nginx", "http_server"),
            (r"microsoft-iis[/\s]([\d.]+)?", "microsoft", "iis"),
            (r"litespeed", "litespeedtech", "litespeed_web_server"),
            (r"openresty[/\s]([\d.]+)?", "openresty", "openresty"),
            (r"gunicorn[/\s]([\d.]+)?", "gunicorn", "gunicorn"),
            (r"cloudflare", "cloudflare", "cloudflare"),
            (r"envoy[/\s]([\d.]+)?", "envoyproxy", "envoy"),
            (r"caddy", "caddyserver", "caddy"),
            (r"^vercel$", "vercel", "vercel"),
        ],
    },
    {
        "header": "x-powered-by",
        "patterns": [
            (r"PHP[/\s]([\d.]+)?", "php", "php"),
            (r"ASP\.NET", "microsoft", "asp.net"),
            (r"Express", "expressjs", "express"),
            (r"Next\.js", "vercel", "next.js"),
        ],
    },
    {
        # Next.js exposes itself via x-nextjs-* and Vercel via x-vercel-*.
        "header": "x-nextjs-prerender",
        "patterns": [(r".*", "vercel", "next.js")],
    },
    {
        "header": "x-vercel-id",
        "patterns": [(r".*", "vercel", "vercel")],
    },
]

META_GENERATOR_PATTERNS: list[tuple[str, str, str]] = [
    (r"WordPress\s*([\d.]+)?", "wordpress", "wordpress"),
    (r"Drupal\s*(\d+)?", "drupal", "drupal"),
    (r"Joomla!?\s*([\d.]+)?", "joomla", "joomla"),
    (r"TYPO3\s*([\d.]+)?", "typo3", "typo3"),
    (r"Ghost\s*([\d.]+)?", "ghost", "ghost"),
    (r"Magento\s*([\d.]+)?", "magento", "magento"),
    (r"Shopify", "shopify", "shopify"),
    (r"Squarespace", "squarespace", "squarespace"),
    (r"Wix\.com", "wix", "wix"),
]

COOKIE_PATTERNS: list[tuple[str, str, str]] = [
    (r"PHPSESSID", "php", "php"),
    (r"JSESSIONID", "java", "java"),
    (r"ASP\.NET_SessionId", "microsoft", "asp.net"),
    (r"wp-settings-\d+", "wordpress", "wordpress"),
    (r"Drupal\.visitor", "drupal", "drupal"),
    (r"joomla_user_state", "joomla", "joomla"),
    (r"django_language", "djangoproject", "django"),
    (r"_rails_session|request_method", "rubyonrails", "rails"),
    (r"laravel_session", "laravel", "laravel"),
]

BODY_MARKER_PATTERNS: list[tuple[str, str, str, float]] = [
    # regex, vendor, product, confidence
    (r"/wp-content/|/wp-includes/", "wordpress", "wordpress", 0.95),
    (r"/sites/default/files/", "drupal", "drupal", 0.85),
    (r"/templates/|/libraries/", "joomla", "joomla", 0.7),
    (r"csrfmiddlewaretoken", "djangoproject", "django", 0.9),
    (r"laravel_session", "laravel", "laravel", 0.9),
    (r"window\.__NUXT__", "nuxt", "nuxt.js", 0.9),
    (r"react-app|data-reactroot", "facebook", "react", 0.6),
]

PATH_SIGNATURES: list[tuple[str, str, str]] = [
    # When the asset responds 200 on these paths, we confidently tag the CMS.
    ("/wp-login.php", "wordpress", "wordpress"),
    ("/administrator/", "joomla", "joomla"),
    ("/user/login", "drupal", "drupal"),
    ("/_next/", "vercel", "next.js"),
]


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def _make_tech(
    vendor: str, product: str, version: str | None, source: str, confidence: float
) -> dict[str, Any]:
    return {
        "vendor": vendor.lower().strip(),
        "product": product.lower().strip(),
        "version": (version or "").strip() or None,
        "source": source,
        "confidence": float(confidence),
    }


def _merge(
    accumulator: dict[tuple[str, str], dict[str, Any]],
    tech: dict[str, Any],
) -> None:
    key = (tech["vendor"], tech["product"])
    if key not in accumulator or tech["confidence"] > accumulator[key]["confidence"]:
        accumulator[key] = tech


def _extract_version(pattern_match: re.Match | None) -> str | None:
    if not pattern_match:
        return None
    try:
        return pattern_match.group(1) or None
    except (IndexError, AttributeError):
        return None


async def fingerprint_asset(
    url: str, *, timeout: float = 10.0, verify: bool | str = False
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Probe ``url`` and return ``(probed_meta, technologies)``.

    ``probed_meta`` carries the parts of the response other scanners need
    (status, headers, body, final URL). One request is issued to the home
    page; ``/robots.txt`` and ``/sitemap.xml`` are best-effort follow-ups.

    Any ``?_vercel_share=...`` / ``?_vercel_signature=...`` query params are
    stripped first — they cause Vercel to redirect shared links to
    ``vercel.com/login`` instead of the app.

    Redirects are intentionally NOT followed on the initial probe. When
    the asset is behind an auth wall (Vercel password protection, etc.)
    the 3xx response's headers still carry the asset's true fingerprint
    (``server: Vercel``, ``x-vercel-id: …``); following the redirect
    would take us to the auth provider's stack and fingerprint *that*.
    If the redirect target is one of the known auth-wall hosts we mark
    the response so the UI can show a "password-protected" badge.
    """
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

    parts = urlsplit(url)
    if parts.query:
        kept = [
            (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if not k.startswith("_vercel")
        ]
        parts = parts._replace(query=urlencode(kept))
        url = urlunsplit(parts)

    headers = {"User-Agent": "Mozilla/5.0 (compatible; VulnWatch/1.0)"}
    techs: dict[tuple[str, str], dict[str, Any]] = {}

    probed_meta: dict[str, Any] = {
        "home_url": None,
        "status_code": None,
        "headers": {},
        "body": "",
        "cookies": [],
        "robots_txt": "",
        "sitemap_xml": "",
        "path_probes": {},
        "redirected_via": None,  # None | "auth_wall" | <other-host>
    }

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, verify=verify, headers=headers
    ) as client:
        try:
            r = await client.get(url)
            probed_meta["status_code"] = r.status_code
            probed_meta["headers"] = {k.lower(): v for k, v in r.headers.items()}
            probed_meta["cookies"] = [
                c if isinstance(c, str) else f"{c.name}={c.value}"
                for c in (r.cookies or [])
            ]
            # If the asset responded with a redirect, capture the location
            # but keep the original response (its headers are the fingerprint).
            if r.is_redirect:
                location = r.headers.get("location") or ""
                # IMPORTANT: keep ``home_url`` set to the original request
                # URL so downstream consumers (asset_js.extract_scripts)
                # absolutize relative script paths against the *asset*, not
                # against the auth-wall host (which would produce nonsense
                # URLs like ``https://vercel.com//cdn/x.js``).
                probed_meta["home_url"] = url
                probed_meta["redirected_to"] = location
                # Auth-wall redirects: trust the original headers, mark it.
                loc_host = (urlparse(location).netloc or "").lower()
                if loc_host in _AUTH_WALL_HOSTS or any(
                    loc_host == h or loc_host.endswith("." + h)
                    for h in _AUTH_WALL_HOSTS
                ):
                    probed_meta["redirected_via"] = "auth_wall"
                else:
                    # Unknown external redirect — for tech detection we still
                    # trust the original headers, but flag it for the UI.
                    probed_meta["redirected_via"] = f"redirect:{loc_host}"
                body = ""  # body of a 3xx is rarely useful
                probed_meta["body"] = ""
            else:
                probed_meta["home_url"] = str(r.url)
                body = r.text or ""
                probed_meta["body"] = body[:200_000]  # cap so memory stays bounded
        except httpx.HTTPError:
            body = ""

        # opportunistic ancillary fetches — failures are fine
        for label, sub in [("robots_txt", "robots.txt"), ("sitemap_xml", "sitemap.xml")]:
            try:
                rr = await client.get(f"{base}/{sub}")
                if rr.status_code == 200:
                    probed_meta[label] = rr.text[:50_000]
            except httpx.HTTPError:
                pass

    # 1. Header signatures
    for sig in HEADER_SIGNATURES:
        value = probed_meta["headers"].get(sig["header"], "")
        if not value:
            continue
        for pat, vendor, product in sig["patterns"]:
            m = re.search(pat, value, re.IGNORECASE)
            if m:
                _merge(techs, _make_tech(vendor, product, _extract_version(m), "header", 0.9))

    # 2. Meta generator — accept either ``name=... content=...`` or
    # ``content=... name=...`` (HTML5 doesn't fix attribute order).
    # We search the *capped* body, not the full response, so a multi-MB
    # response can't blow up memory or false-positive on JS template
    # literals.
    capped_body = (body or "")[:200_000]
    for pat, vendor, product in META_GENERATOR_PATTERNS:
        for attr_order in (
            rf'<meta[^>]+name=["\']generator["\'][^>]+content=["\']({pat})["\']',
            rf'<meta[^>]+content=["\']({pat})["\'][^>]+name=["\']generator["\']',
        ):
            m = re.search(attr_order, capped_body, re.IGNORECASE)
            if m:
                _merge(techs, _make_tech(vendor, product, _extract_version(m), "meta", 0.95))
                break

    # 3. Cookies
    for cookie_str in probed_meta["cookies"]:
        for pat, vendor, product in COOKIE_PATTERNS:
            if re.search(pat, cookie_str, re.IGNORECASE):
                _merge(techs, _make_tech(vendor, product, None, "cookie", 0.8))

    # 4. Body markers
    for pat, vendor, product, conf in BODY_MARKER_PATTERNS:
        if re.search(pat, capped_body, re.IGNORECASE):
            _merge(techs, _make_tech(vendor, product, None, "body", conf))

    # 5. Auth-wall inference — when an asset is behind Vercel SSO/Netlify
    # password protection we only see a 3xx with no body. The headers tell
    # us the *platform* (Vercel/Netlify) but not the framework. Without a
    # fallback, those assets scan as 0 technologies and miss every CVE.
    #
    # Heuristic: if the asset is on Vercel AND we didn't already tag a
    # Next.js entry, add one with lower confidence. Vercel is by far the
    # most common Next.js host, and the matcher's loose alias catches
    # CVE prose that mentions "next.js"/"nextjs".
    is_vercel = (
        probed_meta["headers"].get("server", "").lower() == "vercel"
        or probed_meta["headers"].get("x-vercel-id") is not None
    )
    already_has_next = ("vercel", "next.js") in {
        (t["vendor"], t["product"]) for t in techs.values()
    }
    if is_vercel and not already_has_next:
        _merge(techs, _make_tech("vercel", "next.js", None, "auth_wall_inference", 0.5))

    return probed_meta, list(techs.values())


async def probe_paths(
    url: str,
    paths: list[str],
    *,
    timeout: float = 5.0,
    verify: bool | str = False,
    max_concurrency: int = 5,
) -> dict[str, dict[str, Any]]:
    """HEAD-then-GET each path. Returns ``{path: {status, redirected, length}}``."""
    import asyncio

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    sem = asyncio.Semaphore(max_concurrency)
    results: dict[str, dict[str, Any]] = {}

    async def _probe(path: str) -> None:
        async with sem:
            target = base + path
            try:
                async with httpx.AsyncClient(
                    timeout=timeout, follow_redirects=False, verify=verify
                ) as c:
                    r = await c.head(target)
                    if r.status_code in (405, 403):
                        r = await c.get(target)
                    results[path] = {
                        "status": r.status_code,
                        "redirected": bool(r.is_redirect),
                        "location": r.headers.get("location"),
                        "length": len(r.content or b""),
                    }
            except httpx.HTTPError as exc:
                results[path] = {"status": None, "error": str(exc)[:120]}

    await asyncio.gather(*[_probe(p) for p in paths], return_exceptions=True)
    return results