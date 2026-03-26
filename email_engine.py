"""
email_engine.py
═══════════════════════════════════════════════════════════════════
Full-stack email validation engine implementing:
  1. Syntax check
  2. Domain DNS check
  3. MX record check
  4. SMTP handshake check
  5. Catch-all detection
  6. Disposable email detection
  7. Role-based detection
  8. Risk classification / confidence score
═══════════════════════════════════════════════════════════════════
"""

import re
import socket
import smtplib
import dns.resolver
import dns.exception
import time
import random
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum

# ──────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("email_engine")


# ──────────────────────────────────────────────
# ENUMS & RESULT DATACLASS
# ──────────────────────────────────────────────

class EmailStatus(str, Enum):
    VALID       = "valid"
    INVALID     = "invalid"
    CATCHALL    = "catch-all"
    UNKNOWN     = "unknown"
    DISPOSABLE  = "disposable"
    RISKY       = "risky"


class RiskLevel(str, Enum):
    LOW     = "low"
    MEDIUM  = "medium"
    HIGH    = "high"
    CRITICAL = "critical"


@dataclass
class ValidationResult:
    email:              str
    status:             EmailStatus     = EmailStatus.UNKNOWN
    risk_level:         RiskLevel       = RiskLevel.HIGH
    confidence_score:   int             = 0          # 0–100
    is_deliverable:     bool            = False

    # Per-check results
    syntax_valid:       bool            = False
    syntax_detail:      str             = ""

    domain_exists:      bool            = False
    domain_detail:      str             = ""

    mx_found:           bool            = False
    mx_records:         list            = field(default_factory=list)
    mx_detail:          str             = ""

    smtp_checked:       bool            = False
    smtp_connectable:   bool            = False
    smtp_accepted:      bool            = False
    smtp_detail:        str             = ""

    is_catch_all:       bool            = False
    catch_all_detail:   str             = ""

    is_disposable:      bool            = False
    disposable_detail:  str             = ""

    is_role_based:      bool            = False
    role_detail:        str             = ""

    suggested_action:   str             = ""
    reasons:            list            = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"]     = self.status.value
        d["risk_level"] = self.risk_level.value
        return d

    def short_summary(self) -> str:
        icon = {
            EmailStatus.VALID:      "✅",
            EmailStatus.INVALID:    "❌",
            EmailStatus.CATCHALL:   "⚠️ ",
            EmailStatus.UNKNOWN:    "❓",
            EmailStatus.DISPOSABLE: "🗑️ ",
            EmailStatus.RISKY:      "🔶",
        }.get(self.status, "❓")
        return (
            f"{icon} {self.email:<42} "
            f"│ {self.status.value:<12} "
            f"│ score: {self.confidence_score:>3}/100 "
            f"│ risk: {self.risk_level.value:<8} "
            f"│ {'; '.join(self.reasons[:2])}"
        )


# ──────────────────────────────────────────────
# STATIC DATA SETS
# ──────────────────────────────────────────────

DISPOSABLE_DOMAINS = {
    # --- common disposable/temp providers ---
    "mailinator.com", "guerrillamail.com", "guerrillamail.net",
    "guerrillamail.org", "guerrillamail.de", "guerrillamail.biz",
    "guerrillamailblock.com", "grr.la", "sharklasers.com", "spam4.me",
    "tempmail.com", "temp-mail.org", "temp-mail.io", "throwam.com",
    "yopmail.com", "yopmail.fr", "cool.fr.nf", "jetable.fr.nf",
    "nospam.ze.tc", "nomail.xl.cx", "mega.zik.dj", "speed.1s.fr",
    "courriel.fr.nf", "moncourrier.fr.nf", "monemail.fr.nf",
    "monmail.fr.nf", "10minutemail.com", "10minutemail.net",
    "10minutemail.org", "10minemail.com", "20minutemail.com",
    "trashmail.com", "trashmail.at", "trashmail.io", "trashmail.me",
    "trashmail.net", "trashmail.org", "trashmail.xyz", "fakeinbox.com",
    "dispostable.com", "mailnull.com", "spamgourmet.com",
    "spamgourmet.net", "spamgourmet.org", "getairmail.com",
    "filzmail.com", "maildrop.cc", "discard.email", "mailnesia.com",
    "mytemp.email", "tempinbox.com", "tempr.email", "dropmail.me",
    "mintemail.com", "binkmail.com", "safetymail.info", "mailscrap.com",
    "spamoff.de", "throwam.com", "tempemail.net", "spambox.us",
    "mailzilla.com", "mailzilla.org", "spam.la", "spaml.com",
    "mailexpire.com", "spammotel.com", "spamex.com", "spamfree24.org",
    "deadaddress.com", "spamgob.com", "kasmail.com", "spamhereplease.com",
    "gishpuppy.com", "bugmenot.com", "jetable.net", "jetable.org",
    "jetable.fr", "nospamfor.us", "owlpic.com", "meltmail.com",
    "anonymbox.com", "courrieltemporaire.com", "tempomail.fr",
    "tempmail.it", "objectmail.com", "crazymailing.com",
    "spoofmail.de", "throwam.com", "fakemailgenerator.com",
    "mailnew.com", "pookmail.com", "sogetthis.com", "suremail.info",
    "spikio.com", "rklips.com", "frapmail.com", "okulimu.com",
    "deagot.com", "gowikibooks.com", "gowikicampus.com",
    "gowikicars.com", "gowikifilms.com", "gowikigames.com",
    "gowikimusic.com", "gowikinetwork.com", "gowikitravel.com",
    "gowikitv.com", "mailme.lv", "mailmetrash.com", "mailnew.com",
    "moncourrier.fr.nf", "nospam.ze.tc", "nowmymail.com",
}

ROLE_ACCOUNTS = {
    "abuse", "admin", "administrator", "billing", "bounce", "bounces",
    "contact", "do-not-reply", "donotreply", "email", "errors",
    "ftp", "help", "helpdesk", "hostmaster", "info", "is", "it",
    "list", "list-request", "listserv", "maildaemon", "mailer-daemon",
    "mailerdaemon", "majordomo", "marketing", "noc", "no-reply",
    "noreply", "null", "office", "operator", "postmaster", "privacy",
    "register", "registrar", "remove", "reply", "root", "sales",
    "security", "service", "services", "smtp", "spam", "support",
    "sysadmin", "tech", "test", "trouble", "undisclosed-recipients",
    "unsubscribe", "usenet", "uucp", "webmaster", "www",
}

FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "yahoo.co.uk", "yahoo.com.au",
    "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com", "protonmail.com", "protonmail.ch",
    "pm.me", "aol.com", "aol.co.uk", "rediffmail.com", "zoho.com",
    "yandex.com", "yandex.ru", "mail.com", "inbox.com", "gmx.com",
    "gmx.net", "gmx.de", "fastmail.com", "fastmail.fm", "tutanota.com",
    "tutanota.de", "hey.com", "mail.ru", "list.ru", "bk.ru", "inbox.ru",
}

# Common domain typo map
DOMAIN_TYPOS = {
    "gmial.com": "gmail.com", "gmal.com": "gmail.com", "gmai.com": "gmail.com",
    "gamil.com": "gmail.com", "gnail.com": "gmail.com", "gmail.co": "gmail.com",
    "gmail.cm": "gmail.com", "gmail.om": "gmail.com", "gmailcom": "gmail.com",
    "yahooo.com": "yahoo.com", "yaho.com": "yahoo.com", "yahoo.co": "yahoo.com",
    "yahoo.cm": "yahoo.com", "yhoo.com": "yahoo.com", "yaho.co.in": "yahoo.co.in",
    "hotmial.com": "hotmail.com", "hotmai.com": "hotmail.com",
    "homail.com": "hotmail.com", "hotmaill.com": "hotmail.com",
    "hotmailcom": "hotmail.com", "hotmail.cm": "hotmail.com",
    "outlok.com": "outlook.com", "outloo.com": "outlook.com",
    "outlookk.com": "outlook.com", "outlook.cm": "outlook.com",
    "icould.com": "icloud.com", "iclould.com": "icloud.com",
    "icloud.co": "icloud.com",
    "protonmial.com": "protonmail.com", "protonmai.com": "protonmail.com",
    "rediffmal.com": "rediffmail.com", "redifmail.com": "rediffmail.com",
}

# Regex for RFC 5321/5322 compliant email syntax
EMAIL_REGEX = re.compile(
    r"^(?!.*\.\.)"                        # no consecutive dots anywhere
    r"[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+"   # local part start
    r"(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*"  # local part dots
    r"@"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"  # domain labels
    r"[a-zA-Z]{2,}$"                      # TLD
)


# ──────────────────────────────────────────────
# CHECK 1: SYNTAX
# ──────────────────────────────────────────────

def check_syntax(email: str) -> tuple[bool, str, str, str]:
    """
    Returns (valid, detail, local_part, domain)
    """
    email = email.strip()

    if not email:
        return False, "Empty email address", "", ""

    if len(email) > 254:
        return False, f"Email too long ({len(email)} chars, max 254)", "", ""

    at_count = email.count("@")
    if at_count == 0:
        return False, "Missing @ symbol", "", ""
    if at_count > 1:
        return False, "Multiple @ symbols found", "", ""

    local, domain = email.rsplit("@", 1)

    if not local:
        return False, "Empty local part (before @)", local, domain
    if len(local) > 64:
        return False, f"Local part too long ({len(local)} chars, max 64)", local, domain
    if local.startswith(".") or local.endswith("."):
        return False, "Local part cannot start or end with a dot", local, domain

    if not domain:
        return False, "Empty domain (after @)", local, domain
    if len(domain) > 255:
        return False, "Domain too long", local, domain
    if "." not in domain:
        return False, "Domain has no TLD (no dot found)", local, domain

    tld = domain.rsplit(".", 1)[-1]
    if len(tld) < 2:
        return False, f"TLD too short: '.{tld}'", local, domain

    if not EMAIL_REGEX.match(email):
        return False, "Failed RFC 5321/5322 syntax check", local, domain

    # Check for known typos
    if domain.lower() in DOMAIN_TYPOS:
        suggestion = DOMAIN_TYPOS[domain.lower()]
        return False, f"Domain typo detected — did you mean @{suggestion}?", local, domain

    return True, "Syntax is valid", local, domain


# ──────────────────────────────────────────────
# CHECK 2: DOMAIN DNS
# ──────────────────────────────────────────────

def check_domain_dns(domain: str, timeout: float = 5.0) -> tuple[bool, str]:
    """
    Checks if the domain resolves via A or AAAA records.
    Returns (exists, detail)
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(domain, record_type)
            ips = [str(r) for r in answers]
            return True, f"Domain resolves ({record_type}): {', '.join(ips[:3])}"
        except dns.resolver.NXDOMAIN:
            return False, "Domain does not exist (NXDOMAIN)"
        except dns.resolver.NoAnswer:
            continue  # try next record type
        except dns.resolver.NoNameservers:
            return False, "No nameservers found for domain"
        except dns.exception.Timeout:
            return False, "DNS lookup timed out"
        except Exception as e:
            return False, f"DNS error: {e}"

    # No A/AAAA — try NS to see if domain at least has nameservers
    try:
        resolver.resolve(domain, "NS")
        return True, "Domain has NS records (no A/AAAA but exists)"
    except Exception:
        return False, "Domain has no A, AAAA, or NS records"


# ──────────────────────────────────────────────
# CHECK 3: MX RECORDS
# ──────────────────────────────────────────────

def check_mx_records(domain: str, timeout: float = 5.0) -> tuple[bool, list, str]:
    """
    Returns (found, mx_list_sorted_by_priority, detail)
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    try:
        answers = resolver.resolve(domain, "MX")
        mx_records = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0]
        )
        mx_hosts = [f"{host} (priority {pref})" for pref, host in mx_records]
        return True, [host for _, host in mx_records], f"Found {len(mx_records)} MX record(s): {', '.join(mx_hosts)}"

    except dns.resolver.NXDOMAIN:
        return False, [], "Domain does not exist"
    except dns.resolver.NoAnswer:
        # Some domains have no MX but A record can receive mail (implicit MX)
        return False, [], "No MX records found — domain may not accept email"
    except dns.resolver.NoNameservers:
        return False, [], "No nameservers available"
    except dns.exception.Timeout:
        return False, [], "MX lookup timed out"
    except Exception as e:
        return False, [], f"MX lookup error: {e}"


# ──────────────────────────────────────────────
# CHECK 4: SMTP HANDSHAKE
# ──────────────────────────────────────────────

# Sender used in SMTP probe — use a real-looking domain
SMTP_FROM = "verify@clearbounce-check.com"
SMTP_TIMEOUT = 10  # seconds

def _smtp_check_single(mx_host: str, email: str, from_addr: str, timeout: int) -> tuple[bool, bool, str]:
    """
    Attempts SMTP handshake to a single MX host.
    Returns (connectable, accepted, detail)
    """
    try:
        with smtplib.SMTP(timeout=timeout) as smtp:
            smtp.connect(mx_host, 25)
            smtp.ehlo_or_helo_if_needed()

            # MAIL FROM
            code, msg = smtp.mail(from_addr)
            if code not in (250, 251):
                return True, False, f"MAIL FROM rejected (code {code}): {msg.decode(errors='ignore')}"

            # RCPT TO — this is the key check
            code, msg = smtp.rcpt(email)
            smtp.rset()   # politely reset
            smtp.quit()

            msg_str = msg.decode(errors="ignore").strip()

            if code in (250, 251):
                return True, True, f"SMTP accepted RCPT TO (code {code})"
            elif code == 550:
                return True, False, f"Mailbox does not exist (550): {msg_str}"
            elif code == 551:
                return True, False, f"User not local (551): {msg_str}"
            elif code == 552:
                return True, False, f"Mailbox full / storage exceeded (552)"
            elif code == 553:
                return True, False, f"Mailbox name invalid (553): {msg_str}"
            elif code in (450, 451, 452):
                return True, None, f"Temporary failure (code {code}) — greylisting likely: {msg_str}"
            elif code == 421:
                return True, None, f"Service temporarily unavailable (421)"
            else:
                return True, None, f"Unexpected SMTP response (code {code}): {msg_str}"

    except smtplib.SMTPConnectError as e:
        return False, False, f"Could not connect to MX {mx_host}: {e}"
    except smtplib.SMTPServerDisconnected:
        return False, None, f"Server {mx_host} disconnected unexpectedly"
    except smtplib.SMTPHeloError as e:
        return True, None, f"HELO/EHLO error from {mx_host}: {e}"
    except ConnectionRefusedError:
        return False, False, f"Connection refused by {mx_host}:25"
    except socket.timeout:
        return False, None, f"Connection to {mx_host}:25 timed out"
    except OSError as e:
        return False, None, f"Network error connecting to {mx_host}: {e}"
    except Exception as e:
        return False, None, f"SMTP error with {mx_host}: {e}"


def check_smtp(mx_records: list, email: str, timeout: int = SMTP_TIMEOUT) -> tuple[bool, bool, str]:
    """
    Tries each MX in priority order.
    Returns (smtp_connectable, smtp_accepted, detail)
    accepted can be True / False / None (inconclusive)
    """
    if not mx_records:
        return False, False, "No MX records to connect to"

    errors = []
    for mx_host in mx_records[:3]:   # try top 3 MX hosts max
        connectable, accepted, detail = _smtp_check_single(mx_host, email, SMTP_FROM, timeout)
        if connectable:
            return connectable, accepted, f"[{mx_host}] {detail}"
        errors.append(f"{mx_host}: {detail}")

    return False, False, "Could not connect to any MX host — " + "; ".join(errors)


# ──────────────────────────────────────────────
# CHECK 5: CATCH-ALL DETECTION
# ──────────────────────────────────────────────

def _random_local() -> str:
    """Generate a random string that almost certainly doesn't exist as a mailbox."""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "catchall_probe_" + "".join(random.choices(chars, k=16))


def check_catch_all(mx_records: list, domain: str, timeout: int = SMTP_TIMEOUT) -> tuple[bool, str]:
    """
    Probes the domain with a definitely-fake address.
    If the server accepts it → domain is catch-all.
    Returns (is_catch_all, detail)
    """
    if not mx_records:
        return False, "Cannot check catch-all — no MX records"

    probe_email = f"{_random_local()}@{domain}"
    connectable, accepted, detail = _smtp_check_single(
        mx_records[0], probe_email, SMTP_FROM, timeout
    )

    if not connectable:
        return False, f"Catch-all check inconclusive (could not connect): {detail}"
    if accepted is True:
        return True, f"Domain accepts all addresses — catch-all confirmed (probe: {probe_email})"
    elif accepted is False:
        return False, "Domain correctly rejects non-existent addresses — not catch-all"
    else:
        return False, f"Catch-all check inconclusive: {detail}"


# ──────────────────────────────────────────────
# CHECK 6: DISPOSABLE DETECTION
# ──────────────────────────────────────────────

def check_disposable(domain: str) -> tuple[bool, str]:
    domain = domain.lower()
    if domain in DISPOSABLE_DOMAINS:
        return True, f"'{domain}' is a known disposable/temporary email provider"
    # Check parent domain (e.g. sub.mailinator.com)
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in DISPOSABLE_DOMAINS:
            return True, f"Subdomain of known disposable provider '{parent}'"
    return False, "Not a known disposable provider"


# ──────────────────────────────────────────────
# CHECK 7: ROLE-BASED DETECTION
# ──────────────────────────────────────────────

def check_role_based(local: str) -> tuple[bool, str]:
    local_lower = local.lower()
    if local_lower in ROLE_ACCOUNTS:
        return True, f"'{local}' is a role-based address (not a personal mailbox)"
    # Partial match for common patterns
    for role in ROLE_ACCOUNTS:
        if local_lower.startswith(role + ".") or local_lower.startswith(role + "_") or local_lower.startswith(role + "-"):
            return True, f"'{local}' appears to start with role keyword '{role}'"
    return False, "Not a role-based address"


# ──────────────────────────────────────────────
# CHECK 8: RISK CLASSIFICATION & CONFIDENCE SCORE
# ──────────────────────────────────────────────

def classify_risk(result: ValidationResult) -> tuple[RiskLevel, int, str, str]:
    """
    Returns (risk_level, confidence_score, status, suggested_action)
    Score is 0-100 reflecting confidence the email IS deliverable.
    """
    score = 0
    reasons = result.reasons

    # --- Hard failures → score stays very low ---
    if not result.syntax_valid:
        return RiskLevel.CRITICAL, 0, EmailStatus.INVALID, "Do not send — invalid syntax"

    if result.is_disposable:
        return RiskLevel.CRITICAL, 3, EmailStatus.DISPOSABLE, "Do not send — disposable provider"

    if result.is_role_based:
        # Role-based isn't always invalid but is high risk
        score += 10
        return RiskLevel.HIGH, score, EmailStatus.RISKY, "Avoid sending — role-based address"

    if not result.domain_exists:
        return RiskLevel.CRITICAL, 0, EmailStatus.INVALID, "Do not send — domain does not exist"

    if not result.mx_found:
        return RiskLevel.CRITICAL, 2, EmailStatus.INVALID, "Do not send — no MX records (domain can't receive email)"

    # --- Domain exists and has MX — start scoring ---
    score += 20   # domain + MX baseline

    # SMTP connectivity
    if result.smtp_connectable:
        score += 15

    # SMTP decision
    if result.smtp_accepted is True:
        if result.is_catch_all:
            score += 15
            return RiskLevel.MEDIUM, min(score, 65), EmailStatus.CATCHALL, "Send with caution — catch-all domain, individual mailbox unconfirmed"
        else:
            score += 35
            return RiskLevel.LOW, min(score, 98), EmailStatus.VALID, "Safe to send — SMTP confirmed mailbox exists"

    elif result.smtp_accepted is False:
        return RiskLevel.CRITICAL, 5, EmailStatus.INVALID, "Do not send — SMTP rejected this mailbox"

    else:
        # smtp_accepted is None → inconclusive (timeout, greylist, etc.)
        if result.is_catch_all:
            score += 10
            return RiskLevel.MEDIUM, min(score, 55), EmailStatus.CATCHALL, "Send with caution — catch-all domain"
        score += 5
        return RiskLevel.HIGH, min(score, 40), EmailStatus.UNKNOWN, "Verify manually — SMTP check inconclusive (greylisting/timeout)"


# ──────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ──────────────────────────────────────────────

def validate_email(
    email: str,
    smtp_timeout: int = 10,
    dns_timeout: float = 5.0,
    skip_smtp: bool = False,
) -> ValidationResult:
    """
    Run all 8 validation checks on a single email address.

    Parameters
    ----------
    email       : email address to validate
    smtp_timeout: seconds to wait for SMTP responses
    dns_timeout : seconds to wait for DNS responses
    skip_smtp   : set True to skip SMTP + catch-all (faster, less accurate)

    Returns
    -------
    ValidationResult dataclass with all check results and final verdict
    """
    email = email.strip().lower()
    result = ValidationResult(email=email)

    # ── 1. SYNTAX ──────────────────────────────
    valid, detail, local, domain = check_syntax(email)
    result.syntax_valid  = valid
    result.syntax_detail = detail
    if not valid:
        result.reasons.append(detail)
        result.status, result.risk_level, result.confidence_score, result.suggested_action = (
            EmailStatus.INVALID, RiskLevel.CRITICAL, 0, "Do not send — syntax invalid"
        )
        return result

    # ── 6. DISPOSABLE (early exit) ─────────────
    is_disp, disp_detail = check_disposable(domain)
    result.is_disposable   = is_disp
    result.disposable_detail = disp_detail
    if is_disp:
        result.reasons.append(disp_detail)

    # ── 7. ROLE-BASED ──────────────────────────
    is_role, role_detail = check_role_based(local)
    result.is_role_based = is_role
    result.role_detail   = role_detail
    if is_role:
        result.reasons.append(role_detail)

    # Early exit for disposable
    if is_disp:
        result.status           = EmailStatus.DISPOSABLE
        result.risk_level       = RiskLevel.CRITICAL
        result.confidence_score = 3
        result.suggested_action = "Do not send — disposable provider"
        return result

    # ── 2. DOMAIN DNS ──────────────────────────
    dom_exists, dom_detail = check_domain_dns(domain, timeout=dns_timeout)
    result.domain_exists = dom_exists
    result.domain_detail = dom_detail
    if not dom_exists:
        result.reasons.append(f"Domain: {dom_detail}")

    # ── 3. MX RECORDS ──────────────────────────
    mx_found, mx_list, mx_detail = check_mx_records(domain, timeout=dns_timeout)
    result.mx_found   = mx_found
    result.mx_records = mx_list
    result.mx_detail  = mx_detail
    if not mx_found:
        result.reasons.append(f"MX: {mx_detail}")

    if skip_smtp or not mx_found:
        # Skip SMTP checks — classify with what we have
        level, score, status, action = classify_risk(result)
        result.risk_level       = level
        result.confidence_score = score
        result.status           = status
        result.suggested_action = action
        result.is_deliverable   = status in (EmailStatus.VALID, EmailStatus.CATCHALL)
        if not result.reasons:
            result.reasons.append(mx_detail if mx_found else dom_detail)
        return result

    # ── 5. CATCH-ALL (probe before real SMTP) ──
    is_catchall, ca_detail = check_catch_all(mx_list, domain, timeout=smtp_timeout)
    result.is_catch_all     = is_catchall
    result.catch_all_detail = ca_detail
    if is_catchall:
        result.reasons.append("Catch-all domain")
        # For catch-all, smtp_accepted is meaningless (server accepts everything)
        result.smtp_checked     = True
        result.smtp_connectable = True
        result.smtp_accepted    = True   # technically accepted but not meaningful
        result.smtp_detail      = ca_detail
    else:
        # ── 4. SMTP HANDSHAKE ──────────────────
        connectable, accepted, smtp_detail = check_smtp(mx_list, email, timeout=smtp_timeout)
        result.smtp_checked     = True
        result.smtp_connectable = connectable
        result.smtp_accepted    = accepted
        result.smtp_detail      = smtp_detail
        if accepted is False:
            result.reasons.append(f"SMTP: {smtp_detail}")
        elif accepted is None:
            result.reasons.append(f"SMTP inconclusive: {smtp_detail}")

    # ── 8. RISK & CONFIDENCE SCORE ─────────────
    level, score, status, action = classify_risk(result)
    result.risk_level       = level
    result.confidence_score = score
    result.status           = status
    result.suggested_action = action
    result.is_deliverable   = status in (EmailStatus.VALID, EmailStatus.CATCHALL)

    if not result.reasons:
        result.reasons.append(result.smtp_detail or result.mx_detail or result.domain_detail)

    return result
