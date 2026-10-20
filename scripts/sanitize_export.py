#!/usr/bin/env python3
"""Find and remove secrets and personal data before anything reaches this public repository.

Usage:
  sanitize_export.py INPUT [-o OUTPUT] [--keep-pii]  write a cleaned copy (stdout if no -o)
  sanitize_export.py --check PATH [PATH...]          report findings, exit 1 if anything is found
  sanitize_export.py --check-commits A..B            check the lines added by every commit in A..B,
                                                     so data added and later removed is found too

Run --check on every file BEFORE uploading it through the GitHub web page: browser uploads
skip the pre-commit hooks, and in a public repository a pushed commit is public at once.

What is reported (--check) and removed (sanitise mode)
  SECRET  JSON keys and Shuffle parameters holding credentials (apikey, password, token,
          secret, authkey, cookie, ...), Authorization / API-key / Cookie headers,
          Bearer / Basic tokens, Shuffle webhook IDs (webhook_<uuid> and webhook trigger IDs
          in workflow exports), credentials in URLs (user:pass@, ?apikey=, &token=), private
          keys, JWTs, WireGuard keys, Proxmox API tokens, password and NTLM hashes, Wazuh
          agent keys, secret XML elements (Wazuh, OPNsense), KEY=value / key: value
          assignments, passwords on command lines, well-known token formats (GitHub, GitLab,
          AWS, Google, Slack, OpenAI / Anthropic, Hugging Face)
  PII     public IP addresses (IPv4 / IPv6) outside documentation ranges, e-mail addresses
          outside example / test domains, home-directory paths with a real user name
  LOCAL   anything listed in your private, git-ignored .leakcheck-local file (your home IP,
          real name, router password, ...) - see SECURITY.md

Sanitise mode replaces secrets with REDACTED (webhook IDs with 00000000-...), public IPs with
RFC 5737 addresses, e-mails with userN@example.com and user names with <user>.

Allowlist: .leakcheck-allow in the repository root - one IP, CIDR, e-mail or literal value per
line, or "sha256:<hash> <path>" for a file a human has reviewed (the entry stops working as
soon as the file changes); '#' starts a comment. Placeholders like <CORTEX_API_KEY>, __NAME__,
$shuffle_variable, REDACTED and 00000000-0000-0000-0000-... are never reported.

Standard library only, so it runs anywhere - also as a single downloaded file.
"""
from __future__ import annotations

import argparse
import bisect
import difflib
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator

REDACTED = "REDACTED"
ZERO_UUID_PREFIX = "00000000-0000-0000-0000-"
ZERO_UUID = ZERO_UUID_PREFIX + "000000000000"
REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOW_FILE = ".leakcheck-allow"
LOCAL_FILE = ".leakcheck-local"

UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
UUID_RE = re.compile(UUID)

# --------------------------------------------------------------------------- helpers

PLACEHOLDER_RE = re.compile(
    r"""^\s*(?:
        <[^<>\n]{1,80}>                                   # <CORTEX_API_KEY>
      | __[A-Za-z0-9_]+__                                 # __SHUFFLE_WEBHOOK_URL__
      | \*{3,} | [xX]{4,} | \.{3} | …                # ***  xxxx  ...
      | \$[\w.#\[\]-]+ | \$\{[^}]*\} | \{\{[^}]*\}\}     # $shuffle.var  ${ENV}  {{ template }}
      | %[A-Za-z_]+% | \$env:\w+                          # %USERNAME%  $env:VAR
      | Secret\.\ Replaced\ during\ app\ execution!       # Shuffle's own masking
      | none | null | nil | true | false
    )\s*$""",
    re.IGNORECASE | re.VERBOSE,
)


def is_placeholder(value: object) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip()
    return (
        not v
        or REDACTED in v
        or "REPLACE_ME" in v.upper()
        or v.startswith(ZERO_UUID_PREFIX)
        or bool(PLACEHOLDER_RE.match(v))
    )


def looks_random(s: str) -> bool:
    """True for token-like strings, False for ordinary words ('authentication', 'Content-Type')."""
    if len(s) < 12:
        return False
    if re.fullmatch(r"[0-9a-fA-F]{32,}", s):  # hex API keys (VirusTotal, AbuseIPDB, ...)
        return True
    has_digit = bool(re.search(r"\d", s))
    if not has_digit and re.fullmatch(r"[A-Za-z]+(?:[-_.][A-Za-z]+)*", s):
        return len(s) >= 32
    classes = sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
    return classes == 3 or (classes == 2 and len(s) >= 20) or (has_digit and len(s) >= 24)


@dataclass
class Finding:
    kind: str  # SECRET | PII | LOCAL
    rule: str
    where: str
    value: str = field(repr=False)

    def masked(self) -> str:
        v = self.value
        if self.kind == "SECRET":
            return f"***({len(v)} chars)"
        if self.kind == "LOCAL":
            return "***"
        if self.rule == "public-ip":
            if ":" in v:
                return v.split(":")[0] + ":..."
            a, b, *_ = v.split(".")
            return f"{a}.{b}.x.x"
        if self.rule == "email":
            local, _, dom = v.partition("@")
            return f"{local[:1]}***@{dom}"
        return v[:1] + "***"

    def __str__(self) -> str:
        return f"[{self.kind}] {self.rule} at {self.where}: {self.masked()}"


# --------------------------------------------------------------------------- secret rules

@dataclass(frozen=True)
class Rule:
    id: str
    regex: re.Pattern
    random: bool = False  # weak context: the value must look like a token
    replace: str = REDACTED
    check: Callable[[re.Match, "Scanner"], bool] | None = None
    compact: bool = False  # OCR: remove stray spaces inside the value before judging it


# Start of a "key: value" token: line start, a separator, or an escaped \n inside a JSON string.
LB = r"(?:^|(?<=[\s\"'`,;{(\[|])|(?<=\\n)|(?<=\\r)|(?<=\\t))"

NON_SECRET_KEY_SUFFIX = re.compile(
    r"(?i)(?:_|-|\.)(?:type|length|policy|url|uri|endpoint|file|path|header|name|id|enabled|"
    r"required|expires?|expiry|ttl|hint|format|field|param|count|prefix|algorithm|version)$"
)
BORING_VALUE = re.compile(r"(?i)^(?:true|false|yes|no|on|off|none|null|\d+)$")


CODE_SUFFIXES = {".py", ".js", ".ts", ".ps1", ".psm1", ".go", ".rb", ".java", ".cs"}


def _assignment_is_secret(m: re.Match, scanner: "Scanner") -> bool:
    key, value = m.group("k"), m.group("s")
    if NON_SECRET_KEY_SUFFIX.search(key) or BORING_VALUE.match(value):
        return False
    if re.search(r"[()\[\]{}]", value):  # a function call / expression, not a literal
        return False
    if scanner.code_mode:  # in source code only a quoted literal is a hard-coded secret
        return m.string[m.start("s") - 1: m.start("s")] in {'"', "'"}
    return True


def _rule(rule_id: str, pattern: str, flags: int = 0, **kw) -> Rule:
    return Rule(rule_id, re.compile(pattern, flags), **kw)


SECRET_RULES: list[Rule] = [
    _rule("private-key",
          r"(?P<s>-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?"
          r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)",
          re.S, replace="-----REDACTED PRIVATE KEY-----"),
    _rule("shuffle-webhook-id", r"webhook_(?P<s>" + UUID + r")", replace=ZERO_UUID),
    _rule("jwt", r"(?P<s>\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"),
    _rule("known-token-format",
          r"(?P<s>\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}"
          r"|A(?:KIA|SIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[abprs]-[A-Za-z0-9-]{10,}"
          r"|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{30,})\b)"),
    _rule("authorization-header",
          LB + r"(?:proxy-)?authorization[\"']?[ \t]*[:=][ \t]*[\"']?"
          r"(?:(?:bearer|basic|token|apikey|key|digest)[ \t]+)?(?P<s>[A-Za-z0-9._~+/-]{12,}={0,2})",
          re.I | re.M, random=True),
    _rule("bearer-token", r"\b(?:bearer|basic)[ \t]+(?P<s>[A-Za-z0-9._~+/-]{12,}={0,2})", re.I, random=True),
    _rule("api-key-header",
          LB + r"(?:x-)?(?:api[-_]?key|apikey|api[-_]?token|auth[-_]?key|authkey|access[-_]?key"
          r"|secret[-_]?key|x-auth-token|x-misp-key|key|token)[\"']?[ \t]*[:=][ \t]*[\"']?"
          r"(?P<s>[A-Za-z0-9._~+/=-]{16,})",
          re.I | re.M, random=True),
    _rule("cookie-header",
          LB + r"(?:set-)?cookie[\"']?[ \t]*[:=][ \t]*[\"']?(?P<s>[^\"'\r\n\\]{16,})",
          re.I | re.M, random=True),
    _rule("url-secret-param",
          r"[?&](?:api[-_]?key|apikey|access[-_]?token|token|authkey|auth[-_]?token|password|passwd"
          r"|pwd|secret|client[-_]?secret)=(?P<s>[^&\s\"'<>#\\]{6,})", re.I),
    _rule("url-signature-param", r"[?&](?:key|sig|signature|code|auth)=(?P<s>[^&\s\"'<>#\\]{12,})",
          re.I, random=True),
    _rule("url-credentials", r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@\"'<>]+:(?P<s>[^/\s@\"'<>]+)@"),
    _rule("wireguard-key",
          r"^[ \t]*(?:PrivateKey|PresharedKey)[ \t]*=[ \t]*(?P<s>[A-Za-z0-9+/]{42,43}=)", re.I | re.M),
    _rule("proxmox-api-token", r"PVEAPIToken=[^=\s\"']+=(?P<s>" + UUID + r")"),
    _rule("proxmox-ticket", r"PVEAuthCookie=(?P<s>[^;\s\"']{20,})"),
    _rule("password-hash",
          r"(?P<s>\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}"
          r"|\$[56]\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43,86}"
          r"|\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}"
          r"|\$argon2(?:id|i|d)\$[^\s\"']{20,})"),
    _rule("ntlm-hash", r"(?<![0-9a-fA-F])(?P<s>[0-9a-fA-F]{32}:[0-9a-fA-F]{32})(?![0-9a-fA-F])"),
    _rule("wazuh-agent-key",
          r"^[ \t]*\d{3,}[ \t]+[\w.-]+[ \t]+(?:any|[\d./]+)[ \t]+(?P<s>[0-9a-fA-F]{64})[ \t]*$", re.M),
    _rule("xml-secret-element",
          r"<(?P<tag>api_?key|apikey|password|passwd|hook_url|webhook_url|privkey|psk|pre_?shared_?key"
          r"|authkey|secret|token|auth_pass|shared_?secret)>[ \t\r\n]*(?P<s>[^<]*?[^<\s])[ \t\r\n]*</(?P=tag)>",
          re.I | re.S),
    _rule("assignment-secret",
          r"^[ \t]*(?:-[ \t]+)?(?:export[ \t]+|set[ \t]+|\$env:|\$)?"
          r"(?P<k>[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[-_]?key|apikey|authkey"
          r"|private[-_]?key|access[-_]?key|client[-_]?secret|encryption[-_]?(?:key|modifier)|admin[-_]?key)"
          r"[A-Za-z0-9_.-]*)[ \t]*(?::=|=|:)[ \t]*[\"']?(?P<s>[^\s\"'#<>]{6,})",
          re.I | re.M, check=_assignment_is_secret),
    _rule("cli-password",
          r"(?:\bsshpass[ \t]+-p[ \t]*|\b(?:mysql|mariadb|mysqldump|psql|mongo|mongosh|redis-cli)\b[^\n]*?[ \t]-p(?=\S)"
          r"|[ \t]/p:|--password[= ][ \t]*|\bcurl\b[^\n]*?[ \t](?:-u|--user)[ \t]+[\"']?[^:\s\"']+:)"
          r"[\"']?(?P<s>[^\s\"'@]{4,})",
          re.I),
]

# Text read from a screenshot: OCR inserts stray spaces into long tokens and drops separators,
# and UIs show "API key  <value>" without a colon.
_OCR_HEX = r"(?:[0-9a-fA-F][ \t]?)"
OCR_RULES: list[Rule] = [
    _rule("shuffle-webhook-id",
          r"webhook[_ \t]{0,2}(?P<s>" + _OCR_HEX + r"{8}-[ \t]?" + _OCR_HEX + r"{4}-[ \t]?" + _OCR_HEX
          + r"{4}-[ \t]?" + _OCR_HEX + r"{4}-[ \t]?" + _OCR_HEX + r"{11}[0-9a-fA-F])",
          re.I, compact=True, replace=ZERO_UUID,
          check=lambda m, _sc: bool(UUID_RE.fullmatch(re.sub(r"\s", "", m.group("s"))))),
    _rule("labelled-secret",
          r"\b(?:ap[il1|][ _-]?(?:key|token|secret)|ap[il1|]key|auth[ _-]?key|authkey|access[ _-]?key|private[ _-]?key"
          r"|secret|token|password|passwd)\b[ \t:=]{1,6}"
          r"(?P<s>[A-Za-z0-9._~+/=-]{6,}(?:[ \t][A-Za-z0-9._~+/=-]{6,}){0,2})",
          re.I, compact=True, random=True),
]
OCR_DASHES = str.maketrans({"—": "-", "–": "-", "‐": "-", "−": "-"})

# Keys / Shuffle parameter names whose value is a credential.
SECRET_KEY_RE = re.compile(
    r"^(?:x[-_])?(?:api[-_]?key|apikey|api[-_]?token|api[-_]?secret|access[-_]?token|refresh[-_]?token"
    r"|id[-_]?token|token|auth[-_]?token|authkey|auth[-_]?key|password|passwd|pwd|passphrase|secret"
    r"|secret[-_]?key|client[-_]?secret|shared[-_]?secret|authorization|proxy[-_]?authorization|cookie"
    r"|set[-_]?cookie|private[-_]?key|privkey|psk|pre[-_]?shared[-_]?key|session[-_]?id|sessionid"
    r"|csrf[-_]?token|webhook[-_]?url|hook[-_]?url|encryption[-_]?key|signing[-_]?key)$",
    re.IGNORECASE,
)
# Match the pattern above but are not secrets in Shuffle / TheHive exports.
SAFE_KEYS = {"authentication_id", "token_type", "key_type", "auth_type"}
SECRET_WORD_RE = re.compile(r"(?i)api[-_]?key|apikey|token|secret|passw|authkey|cookie|private[-_]?key")

# --------------------------------------------------------------------------- personal data

IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\.?\d)")
IPV6_RE = re.compile(r"(?<![\w:.])((?:[0-9A-Fa-f]{1,4})?(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:])")
IPV6_GLOBAL = ipaddress.ip_network("2000::/3")
EMAIL_RE = re.compile(
    r"(?<![\w.+%-])(?P<local>[A-Za-z0-9._%+-]{1,64})@(?P<domain>(?:[A-Za-z0-9-]{1,63}\.)+(?P<tld>[A-Za-z]{2,24}))\b"
)
HOME_RE = re.compile(r"(?<![\w.-])/(?:Users|home)/(?P<n>[A-Za-z0-9._-]{2,64})(?=[/\s\"'`),;:\\]|$)", re.M)
WINHOME_RE = re.compile(r"\b[A-Za-z]:(?:\\{1,4}|/)Users(?:\\{1,4}|/)(?P<n>[^\\/\s\"'<>:|*?]{1,64})", re.I)

# Public resolvers are common, harmless test values.
DEFAULT_ALLOWED_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
                       "208.67.222.222", "208.67.220.220"}
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.net", "example.org", "users.noreply.github.com",
                         "noreply.github.com"}
ALLOWED_EMAIL_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".local", ".lab", ".internal",
                          ".home.arpa", ".example.com", ".example.net", ".example.org")
ALLOWED_EMAILS = {"git@github.com", "noreply@github.com", "noreply@anthropic.com"}
FILE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "json", "md", "txt", "py", "html"}
ALLOWED_USERS = {"administrator", "admin", "public", "default", "default user", "all users", "shared",
                 "user", "username", "users", "root", "runner", "ubuntu", "kali", "socadmin", "labuser",
                 "wazuh", "wazuh-user", "vagrant", "test", "testuser", "guest", "defaultaccount",
                 "wdagutilityaccount", "localadmin", "analyst"}
GENERIC_USER_RE = re.compile(r"(?i)^(?:user|test|lab|demo|analyst|victim|student|admin)[-_.]?\d{0,4}$")

DOC_IPV4_POOLS = ("203.0.113.", "198.51.100.", "192.0.2.")

# --------------------------------------------------------------------------- allowlists


@dataclass
class Allowlist:
    networks: list = field(default_factory=list)
    emails: set = field(default_factory=set)
    literals: set = field(default_factory=set)
    hashes: set = field(default_factory=set)
    commits: set = field(default_factory=set)

    def commit_acknowledged(self, sha: str) -> bool:
        return any(sha.lower().startswith(c) for c in self.commits)

    def ip_allowed(self, ip) -> bool:
        return str(ip) in DEFAULT_ALLOWED_IPS or any(ip in n for n in self.networks if n.version == ip.version)

    def value_allowed(self, value: str) -> bool:
        return value.lower() in self.literals

    def file_reviewed(self, path: Path) -> bool:
        return bool(self.hashes) and file_sha256(path) in self.hashes


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_entries(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def load_allowlist() -> Allowlist:
    allow = Allowlist()
    for base in {REPO_ROOT, Path.cwd()}:
        for entry in _read_entries(base / ALLOW_FILE):
            value = entry.split()[0]
            if value.lower().startswith("sha256:"):
                allow.hashes.add(value[7:].lower())
                continue
            if value.lower().startswith("commit:") and len(value) >= 14:
                allow.commits.add(value[7:].lower())
                continue
            try:
                allow.networks.append(ipaddress.ip_network(value, strict=False))
                continue
            except ValueError:
                pass
            if "@" in value:
                allow.emails.add(value.lower())
            else:
                allow.literals.add(value.lower())
    return allow


def load_local_denylist() -> list[str]:
    """Private strings that must never be committed. The file is git-ignored and never shared."""
    candidates = [REPO_ROOT / LOCAL_FILE, Path.cwd() / LOCAL_FILE, Path.home() / LOCAL_FILE]
    if os.environ.get("LEAKCHECK_LOCAL"):
        candidates.append(Path(os.environ["LEAKCHECK_LOCAL"]))
    seen: list[str] = []
    for f in candidates:
        for entry in _read_entries(f):
            if len(entry) >= 4 and entry not in seen:
                seen.append(entry)
    return seen


# --------------------------------------------------------------------------- scanner


class Scanner:
    def __init__(self, scrub: bool, keep_pii: bool = False,
                 allow: Allowlist | None = None, local: list[str] | None = None):
        self.scrub = scrub
        self.anonymise = scrub and not keep_pii
        self.allow = allow if allow is not None else load_allowlist()
        self.local = local if local is not None else load_local_denylist()
        self.code_mode = False
        self.ocr_mode = False  # text read from pixels: tolerate small misreads of allowed names
        self.findings: list[Finding] = []
        self._seen: set = set()
        self._ip_map: dict[str, str] = {}
        self._email_map: dict[str, str] = {}

    def add(self, kind: str, rule: str, where: str, value: str) -> bool:
        if kind != "LOCAL" and self.allow.value_allowed(value):
            return False
        key = (kind, rule, where, value)
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(Finding(kind, rule, where, value))
        return True

    # -- text ------------------------------------------------------------------
    def text(self, s: str, where: Callable[[int], str]) -> str:
        if self.ocr_mode:
            s = s.translate(OCR_DASHES)
            for rule in OCR_RULES:
                s = self._secret(rule, s, where)
        for rule in SECRET_RULES:
            s = self._secret(rule, s, where)
        s = self._local(s, where)
        s = self._ips(s, where)
        s = self._emails(s, where)
        s = self._homes(s, where)
        return s

    def _apply(self, regex: re.Pattern, s: str, cb: Callable[[re.Match], str]) -> str:
        if self.scrub:
            return regex.sub(cb, s)
        for m in regex.finditer(s):
            cb(m)
        return s

    def _secret(self, rule: Rule, s: str, where) -> str:
        def cb(m: re.Match) -> str:
            secret = re.sub(r"\s+", "", m.group("s")) if rule.compact else m.group("s")
            if is_placeholder(secret):
                return m.group(0)
            if rule.random and not looks_random(secret):
                return m.group(0)
            if rule.check and not rule.check(m, self):
                return m.group(0)
            if not self.add("SECRET", rule.id, where(m.start("s")), secret):
                return m.group(0)
            a, b = m.span("s")
            o = m.start()
            return m.group(0)[: a - o] + rule.replace + m.group(0)[b - o:]

        return self._apply(rule.regex, s, cb)

    def _local(self, s: str, where) -> str:
        for literal in self.local:
            regex = re.compile(re.escape(literal), re.I)

            def cb(m: re.Match) -> str:
                self.add("LOCAL", "local-denylist", where(m.start()), m.group(0))
                return REDACTED

            s = self._apply(regex, s, cb)
        return s

    def _doc_ip(self, ip) -> str:
        key = str(ip)
        if key not in self._ip_map:
            n = len(self._ip_map)
            if ip.version == 6:
                self._ip_map[key] = f"2001:db8::{n + 10:x}"
            else:
                pool, idx = DOC_IPV4_POOLS[(n // 240) % 3], 10 + n % 240
                self._ip_map[key] = f"{pool}{idx}"
        return self._ip_map[key]

    def _ips(self, s: str, where) -> str:
        def cb(m: re.Match) -> str:
            token = m.group(1)
            try:
                ip = ipaddress.ip_address(token)
            except ValueError:
                return token
            if ip.version == 6 and (ip not in IPV6_GLOBAL or ip.ipv4_mapped):
                return token
            if not ip.is_global or self.allow.ip_allowed(ip):
                return token
            cidr = re.match(r"/(\d{1,3})\b", m.string[m.end(1):])
            if cidr and int(cidr.group(1)) <= (24 if ip.version == 4 else 64):
                return token  # a whole network range (e.g. 8.8.8.0/24), not a host
            if not self.add("PII", "public-ip", where(m.start(1)), str(ip)):
                return token
            return self._doc_ip(ip) if self.anonymise else token

        s = self._apply(IPV4_RE, s, cb)
        return self._apply(IPV6_RE, s, cb)

    def _emails(self, s: str, where) -> str:
        def cb(m: re.Match) -> str:
            email, domain = m.group(0), m.group("domain").lower()
            if (
                m.group("tld").lower() in FILE_TLDS
                or domain in ALLOWED_EMAIL_DOMAINS
                or domain.endswith(ALLOWED_EMAIL_SUFFIXES)
                or email.lower() in ALLOWED_EMAILS
                or email.lower() in self.allow.emails
            ):
                return email
            if not self.add("PII", "email", where(m.start()), email):
                return email
            if not self.anonymise:
                return email
            key = email.lower()
            if key not in self._email_map:
                self._email_map[key] = f"user{len(self._email_map) + 1}@example.com"
            return self._email_map[key]

        return self._apply(EMAIL_RE, s, cb)

    def _homes(self, s: str, where) -> str:
        def cb(m: re.Match) -> str:
            name = m.group("n")
            if name.lower() in ALLOWED_USERS or GENERIC_USER_RE.match(name) or is_placeholder(name):
                return m.group(0)
            if self.ocr_mode and difflib.get_close_matches(name.lower(), ALLOWED_USERS, n=1, cutoff=0.8):
                return m.group(0)
            if not self.add("PII", "home-path-user", where(m.start("n")), name):
                return m.group(0)
            if not self.anonymise:
                return m.group(0)
            a, b = m.span("n")
            o = m.start()
            return m.group(0)[: a - o] + "<user>" + m.group(0)[b - o:]

        s = self._apply(HOME_RE, s, cb)
        return self._apply(WINHOME_RE, s, cb)

    # -- JSON ------------------------------------------------------------------
    def json(self, obj, path: str = "$"):
        if isinstance(obj, dict):
            name = obj.get("name")
            secret_param = (
                isinstance(name, str)
                and SECRET_KEY_RE.match(name.strip())
                and name.strip().lower() not in SAFE_KEYS
            )
            out = {}
            for k, v in obj.items():
                here = f"{path}.{k}"
                if secret_param and k == "value" and isinstance(v, str) and not is_placeholder(v):
                    hit = self.add("SECRET", "secret-parameter", f"{here} (parameter '{name}')", v)
                    out[k] = REDACTED if (hit and self.scrub) else v
                elif (
                    isinstance(k, str)
                    and SECRET_KEY_RE.match(k)
                    and k.lower() not in SAFE_KEYS
                    and isinstance(v, str)
                    and not is_placeholder(v)
                ):
                    hit = self.add("SECRET", "secret-key", here, v)
                    out[k] = REDACTED if (hit and self.scrub) else v
                else:
                    out[k] = self.json(v, here)
            return out
        if isinstance(obj, list):
            return [self.json(v, f"{path}[{i}]") for i, v in enumerate(obj)]
        if isinstance(obj, str):
            return self.text(obj, lambda _pos, p=path: p)
        return obj

    def shuffle(self, data):
        """Workflow exports: the webhook trigger ID *is* the webhook URL (/api/v1/hooks/webhook_<id>)."""
        if not (isinstance(data, dict) and isinstance(data.get("actions"), list)
                and isinstance(data.get("triggers"), list)):
            return data
        mapping: dict[str, str] = {}
        for i, t in enumerate(data["triggers"]):
            if not isinstance(t, dict):
                continue
            kind = " ".join(str(t.get(k) or "") for k in ("trigger_type", "app_name", "name")).upper()
            if "WEBHOOK" not in kind:
                continue
            tid = t.get("id")
            if isinstance(tid, str) and UUID_RE.fullmatch(tid) and not tid.startswith(ZERO_UUID_PREFIX):
                if self.add("SECRET", "shuffle-webhook-trigger-id", f"$.triggers[{i}].id", tid):
                    mapping[tid] = f"{ZERO_UUID_PREFIX}{len(mapping) + 1:012d}"
            for j, p in enumerate(t.get("parameters") or []):
                if (isinstance(p, dict) and p.get("name") == "auth_headers"
                        and isinstance(p.get("value"), str) and not is_placeholder(p["value"])):
                    if self.add("SECRET", "shuffle-webhook-auth-headers",
                                f"$.triggers[{i}].parameters[{j}].value", p["value"]) and self.scrub:
                        p["value"] = REDACTED
        for i, var in enumerate(data.get("workflow_variables") or []):
            if not (isinstance(var, dict) and isinstance(var.get("value"), str)) or is_placeholder(var["value"]):
                continue
            if SECRET_WORD_RE.search(str(var.get("name", ""))) or looks_random(var["value"]):
                if self.add("SECRET", "shuffle-workflow-variable", f"$.workflow_variables[{i}].value",
                            var["value"]) and self.scrub:
                    var["value"] = REDACTED
        if not self.scrub:
            return data
        if "owner" in data:
            data["owner"] = ""
        if isinstance(data.get("contact_info"), dict):
            data["contact_info"] = {k: "" for k in data["contact_info"]}
        if isinstance(data.get("execution_org"), dict) and "users" in data["execution_org"]:
            data["execution_org"]["users"] = []
        return _replace_strings(data, mapping) if mapping else data


def _replace_strings(obj, mapping: dict[str, str]):
    if isinstance(obj, dict):
        return {k: _replace_strings(v, mapping) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_replace_strings(v, mapping) for v in obj]
    if isinstance(obj, str):
        for old, new in mapping.items():
            obj = obj.replace(old, new)
    return obj


# --------------------------------------------------------------------------- files

BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff", ".heic",
                   ".pdf", ".zip", ".gz", ".tgz", ".7z", ".tar", ".xz", ".bz2", ".exe", ".dll", ".so",
                   ".pyc", ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".mov", ".webm", ".mp3", ".wav",
                   ".pcap", ".pcapng", ".evtx", ".sqlite", ".db"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache", "fixtures"}
SKIP_NAMES = {LOCAL_FILE}


def read_text(path: Path) -> str | None:
    if path.suffix.lower() in BINARY_SUFFIXES:
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8", errors="replace")


def sanitize_text(raw: str, scanner: Scanner, json_mode: bool) -> str:
    if json_mode:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            pass
        else:
            data = scanner.shuffle(data)
            cleaned = scanner.json(data)
            return json.dumps(cleaned, indent=2, ensure_ascii=False) + "\n"
    starts = [0] + [m.end() for m in re.finditer("\n", raw)]
    return scanner.text(raw, lambda pos: f"line {bisect.bisect_right(starts, pos)}")


def sanitize_file(path: Path, scrub: bool = True, keep_pii: bool = False,
                  scanner: Scanner | None = None) -> tuple[str, list[Finding]]:
    scanner = scanner or Scanner(scrub=scrub, keep_pii=keep_pii)
    raw = read_text(Path(path))
    if raw is None:
        return "", []
    scanner.code_mode = Path(path).suffix.lower() in CODE_SUFFIXES
    cleaned = sanitize_text(raw, scanner, Path(path).suffix.lower() == ".json")
    return cleaned, scanner.findings


def _git_files(directory: Path) -> list[Path] | None:
    try:
        res = subprocess.run(["git", "-C", str(directory), "ls-files", "-co", "--exclude-standard", "-z", "--", "."],
                             capture_output=True, check=False)
    except OSError:
        return None
    if res.returncode != 0:
        return None
    return [directory / p for p in sorted(res.stdout.decode("utf-8", "replace").split("\0")) if p]


def iter_files(paths: Iterable[str]) -> Iterator[Path]:
    for p in map(Path, paths):
        if p.is_file():
            if p.name not in SKIP_NAMES:
                yield p
        elif p.is_dir():
            files = _git_files(p)
            if files is None:
                files = sorted(f for f in p.rglob("*") if f.is_file())
            for f in files:
                if f.is_file() and f.name not in SKIP_NAMES and not (SKIP_DIRS & set(f.parts)):
                    yield f


def _display(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def report(findings: list[Finding]) -> list[str]:
    """One line per distinct value (first location + how many more)."""
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.kind, f.value), []).append(f)
    lines = []
    for items in groups.values():
        more = f" (+{len(items) - 1} more)" if len(items) > 1 else ""
        lines.append(f"{items[0]}{more}")
    return lines


def _commit_skipped(path: str) -> bool:
    parts = set(Path(path).parts)
    return (bool(SKIP_DIRS & parts) or Path(path).name in SKIP_NAMES | {ALLOW_FILE}
            or Path(path).suffix.lower() in BINARY_SUFFIXES)


def check_commits(rev_range: str, allow: Allowlist, local: list[str]) -> int:
    """Scan the lines each commit in rev_range adds (merge commits are skipped)."""
    cmd = ["git", "log", "-p", "--no-color", "--no-ext-diff", "--no-merges", "-U0",
           "--format=%x00%H %an", rev_range]
    try:
        res = subprocess.run(cmd, capture_output=True, check=False)
    except OSError as e:
        print(f"cannot run git: {e}", file=sys.stderr)
        return 2
    if res.returncode != 0:
        print(f"git log {rev_range} failed: {res.stderr.decode('utf-8', 'replace').strip()}", file=sys.stderr)
        return 2

    total = commits = 0
    acknowledged: set = set()
    commit = author = path = None
    added: list[tuple[int, str]] = []
    line_no = 0

    def flush():
        nonlocal total, added
        if commit and allow.commit_acknowledged(commit):
            acknowledged.add(commit[:7])
        elif commit and path and added and not _commit_skipped(path):
            text = "\n".join(t for _, t in added)
            starts = [0] + [m.end() for m in re.finditer("\n", text)]
            numbers = [n for n, _ in added]
            scanner = Scanner(scrub=False, allow=allow, local=local)
            scanner.code_mode = Path(path).suffix.lower() in CODE_SUFFIXES
            scanner.text(text, lambda pos: f"{path}:{numbers[bisect.bisect_right(starts, pos) - 1]}")
            for line in report(scanner.findings):
                print(f"commit {commit[:7]} ({author}): {line}")
                total += 1
        added = []

    for raw in res.stdout.decode("utf-8", "replace").split("\n"):
        if raw.startswith("\x00"):
            flush()
            commit, _, author = raw[1:].partition(" ")
            commits += 1
            path = None
        elif raw.startswith("+++ "):
            flush()
            target = raw[4:].rstrip("\t").strip('"')  # git adds a tab / quotes for unusual names
            path = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
        elif raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            line_no = int(m.group(1)) if m else 0
        elif raw.startswith("+") and path is not None:
            added.append((line_no, raw[1:]))
            line_no += 1
    flush()

    ack = f" ({len(acknowledged)} acknowledged in {ALLOW_FILE}: {', '.join(sorted(acknowledged))})" if acknowledged else ""
    if total:
        print(f"{total} finding(s) in {commits} commit(s){ack}.{HELP}"
              "  * already pushed -> deleting it in a later commit does NOT remove it from GitHub:\n"
              "    rotate secrets, fix the files, then the repo owner acknowledges the commit with\n"
              f"    'commit:<sha>  # reason' in {ALLOW_FILE} (never paste the value itself there)\n",
              file=sys.stderr)
        return 1
    print(f"OK: {commits} commit(s) in {rev_range} checked, nothing found{ack}.", file=sys.stderr)
    return 0


HELP = """
How to fix:
  * secrets   -> remove them; if the value was ever pushed, ROTATE it (SECURITY.md)
  * exports   -> python3 scripts/sanitize_export.py RAW_FILE -o CLEAN_FILE
  * false hit -> add the value to .leakcheck-allow with a reason (the repo owner reviews it)
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("-o", "--output", help="output file (sanitise mode)")
    ap.add_argument("--check", action="store_true", help="only report, exit 1 on findings")
    ap.add_argument("--check-commits", metavar="A..B", help="check every commit in a git revision range")
    ap.add_argument("--keep-pii", action="store_true",
                    help="sanitise mode: keep public IPs, e-mails and user names (secrets are still removed)")
    args = ap.parse_args(argv)

    if args.check_commits:
        return check_commits(args.check_commits, load_allowlist(), load_local_denylist())
    if not args.paths:
        ap.error("give at least one path (or --check-commits A..B)")

    if args.check:
        allow, local = load_allowlist(), load_local_denylist()
        total = 0
        for f in iter_files(args.paths):
            if allow.file_reviewed(f):
                continue
            _, findings = sanitize_file(f, scanner=Scanner(scrub=False, allow=allow, local=local))
            for line in report(findings):
                print(f"{_display(f)}: {line}")
                total += 1
        if total:
            print(f"{total} finding(s).{HELP}", file=sys.stderr)
            return 1
        print("OK: no secrets or personal data found.", file=sys.stderr)
        return 0

    if len(args.paths) != 1:
        ap.error("sanitise mode takes exactly one input file")
    cleaned, findings = sanitize_file(Path(args.paths[0]), scrub=True, keep_pii=args.keep_pii)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(cleaned, encoding="utf-8")
    else:
        sys.stdout.write(cleaned)
    print(f"Cleaned {len(findings)} value(s).", file=sys.stderr)
    for line in report(findings):
        print(f"  - {line}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
