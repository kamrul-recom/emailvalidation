"""
Email Validation Engine
Handles: syntax, domain/MX checks, disposable detection, role detection, activity scoring
"""

import re
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Optional

from core.blocklists import get_disposable_domains, get_role_prefixes
from core.config import get_settings
from core.domain_check import check_domain

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

EMAIL_REGEX = re.compile(
    r'^(?P<local>[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~\.\-]{1,64})'
    r'@'
    r'(?P<domain>(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$'
)


@dataclass
class ValidationResult:
    email: str
    local: str = ""
    domain: str = ""
    tld: str = ""

    syntax_valid: bool = False
    domain_pattern_valid: bool = False
    syntax_issues: list = None

    domain_exists: bool | None = None
    domain_active: bool | None = None
    domain_status: str = "unknown"
    mx_records: list = None
    ns_records: list = None
    mx_checked: bool = False

    mailbox_exists: bool | None = None
    smtp_status: str = "skipped"

    is_disposable: bool = False
    is_role: bool = False
    is_free_provider: bool = False
    tld_known: bool = False

    score: int = 0
    legitimacy: str = "invalid"
    activity: str = "unknown"
    risk_flags: list = None

    needs_api_check: bool = True
    catch_all: bool | None = None
    provider: str = ""
    provider_status: str = ""
    provider_sub_status: str = ""
    active_in_days: int | None = None

    def __post_init__(self):
        if self.syntax_issues is None:
            self.syntax_issues = []
        if self.mx_records is None:
            self.mx_records = []
        if self.ns_records is None:
            self.ns_records = []
        if self.risk_flags is None:
            self.risk_flags = []

    def to_dict(self):
        d = asdict(self)
        d["mx_records"] = d["mx_records"][:3]
        d["ns_records"] = d["ns_records"][:3]
        return d


def _syntax_check(email: str, result: ValidationResult) -> bool:
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


def _apply_domain_check(result: ValidationResult, dc) -> None:
    result.domain_exists = dc.domain_exists
    result.domain_active = dc.domain_active
    result.domain_status = dc.domain_status
    result.mx_records = dc.mx_records or []
    result.ns_records = dc.ns_records or []
    result.mx_checked = True
    result.domain_pattern_valid = dc.domain_pattern_valid


def _risk_signals(result: ValidationResult):
    flags = []
    if result.is_disposable:
        flags.append("Disposable domain")
    if result.is_role:
        flags.append("Role address")
    if result.domain_status == "not_found":
        flags.append("Domain not found")
    elif result.domain_status == "inactive":
        flags.append("Domain inactive (no MX)")
    elif result.domain_status == "unknown":
        flags.append("Domain DNS unknown")
    if not result.mx_records and result.mx_checked and result.domain_active is False:
        flags.append("No MX records")
    if result.domain_active is True and result.mailbox_exists is None and result.smtp_status in ("skipped", "unknown"):
        flags.append("Mailbox not verified")
    if result.mailbox_exists is False:
        flags.append("Mailbox not found")
    if not result.tld_known:
        flags.append("Unknown TLD")
    if result.is_free_provider:
        flags.append("Free email provider")
    result.risk_flags = flags


def _score(result: ValidationResult) -> int:
    s = 40

    if not result.syntax_valid:
        return 0

    if result.domain_status == "not_found":
        return 0
    if result.domain_status == "inactive":
        return max(0, s - 35)
    if result.domain_status == "unknown":
        return max(0, s - 15)

    if result.mx_checked:
        if result.mx_records:
            s += 25
        elif result.domain_exists:
            s += 8
        else:
            s -= 30
    else:
        s += 12

    if result.is_disposable:
        s -= 50
    if result.is_role:
        s -= 10
    if result.tld_known:
        s += 10
    else:
        s -= 8
    if result.is_free_provider:
        s -= 3

    local = result.local
    if re.match(r'^[a-z][a-z0-9._+\-]{1,19}$', local):
        s += 10
    if re.search(r'\d{5,}', local):
        s -= 5
    if len(local) == 1:
        s -= 10

    return max(0, min(100, s))


def _activity(result: ValidationResult) -> str:
    if result.legitimacy == "invalid" or result.is_disposable:
        return "inactive"
    if result.domain_exists is False or result.domain_status in ("not_found", "inactive"):
        return "inactive"
    if result.mailbox_exists is False:
        return "inactive"
    if result.mailbox_exists is None:
        return "unknown"

    settings = get_settings()
    if not settings.use_provider:
        return "unknown"

    h = int(hashlib.md5(result.email.encode()).hexdigest(), 16)
    r = h % 100

    if result.score >= 70:
        return "active" if r < 70 else "inactive"
    elif result.score >= 50:
        return "active" if r < 55 else "inactive"
    else:
        return "active" if r < 35 else "inactive"


def _apply_legitimacy_rules(result: ValidationResult) -> None:
    if not result.syntax_valid:
        result.domain_pattern_valid = False
        result.domain_status = "invalid_pattern"
        result.legitimacy = "invalid"
        result.needs_api_check = False
        result.smtp_status = "skipped"
        result.mailbox_exists = None
        return

    result.domain_pattern_valid = True

    if result.is_disposable:
        result.legitimacy = "invalid"
        result.needs_api_check = False
        result.smtp_status = "skipped"
        return

    if result.domain_exists is False or result.domain_status == "not_found":
        result.legitimacy = "invalid"
        result.needs_api_check = False
        result.smtp_status = "skipped"
        result.mailbox_exists = None
        return

    if result.domain_active is False or result.domain_status == "inactive":
        result.legitimacy = "invalid"
        result.needs_api_check = False
        result.smtp_status = "skipped"
        result.mailbox_exists = None
        return

    if result.domain_status == "unknown" or result.domain_exists is None:
        result.legitimacy = "risky"
        result.needs_api_check = False
        result.smtp_status = "skipped"
        return

    if result.mailbox_exists is False:
        result.legitimacy = "invalid"
        result.needs_api_check = False
        return

    if result.mailbox_exists is True and result.catch_all is True:
        result.legitimacy = "risky"
        return

    if result.mailbox_exists is True:
        result.legitimacy = "valid"
        return

    # Domain accepts mail but mailbox was not verified (Reacher off or not run yet).
    if result.domain_active is True:
        result.legitimacy = "risky"
        if result.smtp_status == "skipped":
            result.smtp_status = "unknown"
        result.needs_api_check = True
        return

    if result.score >= 38:
        result.legitimacy = "risky"
    else:
        result.legitimacy = "invalid"
        result.needs_api_check = False


def validate_single(raw_email: str, check_dns: bool = True) -> Optional[ValidationResult]:
    email = raw_email.strip().lower()
    if not email:
        return None

    result = ValidationResult(email=email)

    result.syntax_valid = _syntax_check(email, result)
    result.domain_pattern_valid = result.syntax_valid
    if not result.syntax_valid:
        result.legitimacy = "invalid"
        result.activity = "inactive"
        result.score = 0
        result.needs_api_check = False
        result.domain_status = "invalid_pattern"
        result.smtp_status = "skipped"
        _risk_signals(result)
        return result

    disposable_domains = get_disposable_domains()
    role_prefixes = get_role_prefixes()
    result.is_disposable = result.domain in disposable_domains
    prefix = re.split(r'[.+_\-]', result.local)[0]
    result.is_role = prefix in role_prefixes
    result.is_free_provider = result.domain in FREE_PROVIDERS
    result.tld_known = result.tld in KNOWN_TLDS

    if check_dns and not result.is_disposable:
        dc = check_domain(result.domain, pattern_valid=True)
        _apply_domain_check(result, dc)
    else:
        result.mx_checked = False
        result.domain_status = "unknown"

    result.score = _score(result)
    _apply_legitimacy_rules(result)

    settings = get_settings()
    if not settings.use_provider:
        result.activity = _activity(result)

    if result.legitimacy == "invalid" or result.score == 0:
        result.needs_api_check = False

    _risk_signals(result)
    return result


def validate_batch(emails: list[str], check_dns: bool = True,
                   max_workers: int = 20, progress_cb=None) -> list[dict]:
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
            interval = get_settings().progress_interval
            if progress_cb and done % interval == 0:
                progress_cb(done, total)

    if progress_cb:
        progress_cb(total, total)

    return results
