"""
Email Validation Engine
Handles: syntax, domain/MX checks, disposable detection, role detection, activity scoring
"""

import re
import hashlib
import socket
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Optional


# ─── Blocklists ───────────────────────────────────────────────────────────────

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
    "yopmail.com", "sharklasers.com", "grr.la", "spam4.me", "trashmail.com",
    "fakeinbox.com", "dispostable.com", "mailnull.com", "spamgourmet.com",
    "spoofmail.de", "getairmail.com", "guerrillamailblock.com", "guerrillamail.net",
    "guerrillamail.org", "guerrillamail.de", "guerrillamail.biz", "guerrillamail.info",
    "disposableaddress.com", "tempr.email", "discard.email", "spamhereplease.com",
    "spamgourmet.net", "spamgourmet.org", "emailondeck.com", "throwam.com",
    "mailnesia.com", "maildrop.cc", "spamfree24.org", "trashmail.at",
    "trashmail.io", "trashmail.me", "trashmail.net", "trashmail.org",
    "tempinbox.com", "tempinbox.co.uk", "spamcowboy.com", "spam.la",
    "spaml.de", "spaml.com", "spamspot.com", "spamevader.com",
    "byom.de", "spamgob.com", "spamcanyon.com", "spamboy.com",
    "10minutemail.com", "10minutemail.net", "10minutemail.org", "10minutemail.co.uk",
    "tempmail.net", "tempmailer.com", "tempinbox.com", "mailtemp.info",
    "throwablemail.com", "throwam.com", "dispostable.com",
}

ROLE_PREFIXES = {
    "admin", "info", "support", "sales", "noreply", "no-reply", "postmaster",
    "webmaster", "help", "contact", "team", "abuse", "billing", "security",
    "legal", "privacy", "compliance", "hr", "helpdesk", "service", "mail",
    "newsletter", "notifications", "alert", "alerts", "do-not-reply",
    "donotreply", "mailer", "mailer-daemon", "bounce", "bounces",
}

FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "protonmail.com", "zoho.com", "yandex.com", "mail.com",
    "gmx.com", "gmx.net", "live.com", "msn.com", "me.com", "mac.com",
}

KNOWN_TLDS = {
    "com", "net", "org", "edu", "gov", "io", "co", "uk", "ca", "au",
    "de", "fr", "jp", "in", "br", "mx", "es", "it", "nl", "se", "no",
    "fi", "dk", "ch", "at", "be", "pl", "ru", "cn", "sg", "nz", "za",
    "us", "info", "biz", "tech", "app", "dev", "ai", "digital",
}

# Regex — strict RFC 5321-compatible
EMAIL_REGEX = re.compile(
    r'^(?P<local>[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~\.\-]{1,64})'
    r'@'
    r'(?P<domain>(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$'
)

# Cache DNS results to avoid repeat lookups
_dns_cache: dict = {}


# ─── Result model ─────────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    email: str
    local: str = ""
    domain: str = ""
    tld: str = ""

    # Syntax
    syntax_valid: bool = False
    syntax_issues: list = None

    # Domain
    domain_exists: bool = False
    mx_records: list = None
    mx_checked: bool = False

    # Risk signals
    is_disposable: bool = False
    is_role: bool = False
    is_free_provider: bool = False
    tld_known: bool = False

    # Scores and buckets
    score: int = 0
    legitimacy: str = "invalid"   # valid | risky | invalid
    activity: str = "unknown"     # active | inactive | unknown
    risk_flags: list = None

    def __post_init__(self):
        if self.syntax_issues is None:
            self.syntax_issues = []
        if self.mx_records is None:
            self.mx_records = []
        if self.risk_flags is None:
            self.risk_flags = []

    def to_dict(self):
        d = asdict(self)
        d["mx_records"] = d["mx_records"][:3]  # trim for JSON
        return d


# ─── Validation steps ─────────────────────────────────────────────────────────

def _syntax_check(email: str, result: ValidationResult) -> bool:
    """Returns True if syntax is valid."""
    issues = []

    if not email:
        issues.append("Empty email")
        result.syntax_issues = issues
        return False

    if len(email) > 254:
        issues.append("Email exceeds 254 characters")

    m = EMAIL_REGEX.match(email)
    if not m:
        at = email.count("@")
        if at == 0:
            issues.append("Missing @ symbol")
        elif at > 1:
            issues.append("Multiple @ symbols")
        else:
            local, domain = email.split("@", 1)
            if not local:
                issues.append("Empty local part")
            if ".." in local:
                issues.append("Consecutive dots in local part")
            if local.startswith(".") or local.endswith("."):
                issues.append("Local part starts or ends with dot")
            if not domain or "." not in domain:
                issues.append("Invalid domain — no TLD")
        result.syntax_issues = issues
        return False

    local = m.group("local")
    domain = m.group("domain")

    if local.startswith(".") or local.endswith("."):
        issues.append("Local part starts or ends with dot")
    if ".." in local:
        issues.append("Consecutive dots in local part")

    result.local = local.lower()
    result.domain = domain.lower()
    result.tld = domain.split(".")[-1].lower()
    result.syntax_issues = issues
    return len(issues) == 0


def _dns_mx_check(domain: str, result: ValidationResult):
    """Checks MX and A records for the domain."""
    if domain in _dns_cache:
        cached = _dns_cache[domain]
        result.mx_records = cached["mx"]
        result.domain_exists = cached["exists"]
        result.mx_checked = True
        return

    mx_records = []
    exists = False

    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_records = sorted(
            [str(r.exchange).rstrip(".") for r in answers],
            key=lambda x: x
        )
        exists = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # Try A record fallback
        try:
            dns.resolver.resolve(domain, "A", lifetime=3)
            exists = True
        except Exception:
            pass
    except (dns.exception.Timeout, dns.resolver.NoNameservers, Exception):
        # Network issues — don't penalise
        exists = True  # assume exists to avoid false negatives

    _dns_cache[domain] = {"mx": mx_records, "exists": exists}
    result.mx_records = mx_records
    result.domain_exists = exists
    result.mx_checked = True


def _risk_signals(result: ValidationResult):
    """Populate risk flags."""
    flags = []
    if result.is_disposable:
        flags.append("Disposable domain")
    if result.is_role:
        flags.append("Role address")
    if not result.mx_records and result.mx_checked:
        flags.append("No MX records")
    if not result.domain_exists:
        flags.append("Domain not found")
    if not result.tld_known:
        flags.append("Unknown TLD")
    if result.is_free_provider:
        flags.append("Free email provider")
    result.risk_flags = flags


def _score(result: ValidationResult) -> int:
    s = 40

    # Syntax
    if not result.syntax_valid:
        return 0

    # MX / domain
    if result.mx_checked:
        if result.mx_records:
            s += 25
        elif result.domain_exists:
            s += 8
        else:
            s -= 30
    else:
        # DNS not checked — give neutral credit for known TLD
        s += 12

    # Disposable
    if result.is_disposable:
        s -= 50

    # Role
    if result.is_role:
        s -= 10

    # TLD
    if result.tld_known:
        s += 10
    else:
        s -= 8

    # Free provider (small penalty)
    if result.is_free_provider:
        s -= 3

    # Local part quality
    local = result.local
    if re.match(r'^[a-z][a-z0-9._+\-]{1,19}$', local):
        s += 10
    if re.search(r'\d{5,}', local):
        s -= 5
    if len(local) == 1:
        s -= 10

    return max(0, min(100, s))


def _activity(result: ValidationResult) -> str:
    """
    Deterministic simulated activity from email hash.
    In production: replace with ESP engagement API call.
    """
    if result.legitimacy == "invalid" or result.is_disposable:
        return "inactive"
    if not result.domain_exists:
        return "inactive"

    h = int(hashlib.md5(result.email.encode()).hexdigest(), 16)
    r = h % 100

    # Higher score = higher probability of active
    if result.score >= 70:
        return "active" if r < 70 else "inactive"
    elif result.score >= 50:
        return "active" if r < 55 else "inactive"
    else:
        return "active" if r < 35 else "inactive"


# ─── Public API ───────────────────────────────────────────────────────────────

def validate_single(raw_email: str, check_dns: bool = True) -> Optional[ValidationResult]:
    email = raw_email.strip().lower()
    if not email:
        return None

    result = ValidationResult(email=email)

    # 1. Syntax
    result.syntax_valid = _syntax_check(email, result)
    if not result.syntax_valid:
        result.legitimacy = "invalid"
        result.activity = "inactive"
        result.score = 0
        _risk_signals(result)
        return result

    # 2. Risk signals (pre-DNS)
    result.is_disposable = result.domain in DISPOSABLE_DOMAINS
    prefix = re.split(r'[.+_\-]', result.local)[0]
    result.is_role = prefix in ROLE_PREFIXES
    result.is_free_provider = result.domain in FREE_PROVIDERS
    result.tld_known = result.tld in KNOWN_TLDS

    # 3. DNS (MX lookup)
    if check_dns and not result.is_disposable:
        try:
            _dns_mx_check(result.domain, result)
        except Exception:
            result.domain_exists = True  # fail open
            result.mx_checked = True

    # 4. Score
    result.score = _score(result)

    # 5. Legitimacy bucket
    if not result.syntax_valid:
        result.legitimacy = "invalid"
    elif result.is_disposable:
        result.legitimacy = "invalid"
    elif result.mx_checked and not result.domain_exists:
        result.legitimacy = "invalid"
    elif result.score >= 62:
        result.legitimacy = "valid"
    elif result.score >= 38:
        result.legitimacy = "risky"
    else:
        result.legitimacy = "invalid"

    # 6. Activity
    result.activity = _activity(result)

    # 7. Risk flags
    _risk_signals(result)

    return result


def validate_batch(emails: list[str], check_dns: bool = True,
                   max_workers: int = 20, progress_cb=None) -> list[dict]:
    """
    Validate a list of emails concurrently.
    progress_cb(done, total) called periodically.
    """
    deduped = list({e.strip().lower() for e in emails if e and e.strip()})
    total = len(deduped)
    results = []
    done = 0

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(validate_single, e, check_dns): e for e in deduped}
        for future in as_completed(futures):
            r = future.result()
            if r:
                results.append(r.to_dict())
            done += 1
            if progress_cb and done % 100 == 0:
                progress_cb(done, total)

    if progress_cb:
        progress_cb(total, total)

    return results
