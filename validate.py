#!/usr/bin/env python3
"""
validate.py — ClearBounce Email Validation
═══════════════════════════════════════════
Reads your original CSV, finds the email column automatically,
validates every email, and writes a NEW CSV with ALL your original
columns preserved — plus ONE new column at the end: "Email Status".

Usage:
  python3 validate.py --file your_sheet.csv
  python3 validate.py --file your_sheet.csv --fast          # DNS only, faster
  python3 validate.py --file your_sheet.csv --workers 20    # more speed
  python3 validate.py --email john@example.com              # single check
"""

import argparse
import csv
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

from email_engine import validate_email, EmailStatus, RiskLevel

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# ── Colour helpers ────────────────────────────────────────────
def colored(text, color):
    if HAS_COLOR:
        return f"{color}{text}{Style.RESET_ALL}"
    return text

STATUS_COLOR = {
    EmailStatus.VALID:      Fore.GREEN,
    EmailStatus.INVALID:    Fore.RED,
    EmailStatus.CATCHALL:   Fore.YELLOW,
    EmailStatus.UNKNOWN:    Fore.CYAN,
    EmailStatus.DISPOSABLE: Fore.MAGENTA,
    EmailStatus.RISKY:      Fore.YELLOW,
}

ICONS = {
    EmailStatus.VALID:      "✅",
    EmailStatus.INVALID:    "❌",
    EmailStatus.CATCHALL:   "⚠️ ",
    EmailStatus.UNKNOWN:    "❓",
    EmailStatus.DISPOSABLE: "🗑️ ",
    EmailStatus.RISKY:      "🔶",
}

# ── Status label for the output column ───────────────────────
def status_label(status: EmailStatus) -> str:
    return {
        EmailStatus.VALID:      "Valid",
        EmailStatus.INVALID:    "Invalid",
        EmailStatus.CATCHALL:   "Catch-All (send with caution)",
        EmailStatus.UNKNOWN:    "Unknown",
        EmailStatus.DISPOSABLE: "Disposable (do not send)",
        EmailStatus.RISKY:      "Risky (role-based)",
    }.get(status, "Unknown")

# ── Find email column in CSV header ──────────────────────────
# Common column names used for email in marketing sheets
EMAIL_COLUMN_NAMES = [
    "email id", "email", "email address", "emailid", "e-mail",
    "e mail", "mail", "email_id", "email id", "emailaddress",
]

def find_email_column(headers: list[str]) -> str | None:
    """Return the header name that most likely contains email addresses."""
    for h in headers:
        if h.strip().lower() in EMAIL_COLUMN_NAMES:
            return h
    # Fallback: check if any column name contains 'email' or 'mail'
    for h in headers:
        if "email" in h.lower() or "e-mail" in h.lower():
            return h
    return None

# ── Read CSV preserving all rows & columns ────────────────────
def read_csv_with_rows(path: str):
    """
    Returns (headers, rows, email_col)
    headers  : list of column names
    rows     : list of dicts (one per row)
    email_col: the column name containing email addresses
    """
    encodings = ["utf-8-sig", "utf-8", "latin-1", "cp1252"]
    for enc in encodings:
        try:
            with open(path, newline="", encoding=enc, errors="replace") as f:
                # Sniff delimiter
                sample = f.read(4096)
                f.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
                except csv.Error:
                    dialect = csv.excel
                reader = csv.DictReader(f, dialect=dialect)
                headers = reader.fieldnames or []
                rows = list(reader)
            print(f"  📂 Read {len(rows)} rows  ({enc} encoding, delimiter='{dialect.delimiter}')")
            return headers, rows
        except Exception as e:
            continue
    raise ValueError(f"Could not read file: {path}")

# ── Single result printer ─────────────────────────────────────
def print_single_result(r):
    w = 62
    icon  = ICONS.get(r.status, "❓")
    sc    = STATUS_COLOR.get(r.status, "")
    print()
    print("─" * w)
    print(f"  Email   : {Style.BRIGHT if HAS_COLOR else ''}{r.email}{Style.RESET_ALL if HAS_COLOR else ''}")
    print(f"  Status  : {icon} {colored(r.status.value.upper(), sc)}")
    print(f"  Score   : {r.confidence_score}/100")
    print(f"  Action  : {r.suggested_action}")
    print("─" * w)

    def row(name, ok, detail):
        m = colored("✔", Fore.GREEN) if ok is True else colored("✘", Fore.RED) if ok is False else colored("~", Fore.YELLOW)
        short = (detail or "")[:80]
        print(f"  {name:<22} {m}  {short}")

    row("1. Syntax",         r.syntax_valid,    r.syntax_detail)
    row("2. Domain DNS",     r.domain_exists,   r.domain_detail)
    row("3. MX Records",     r.mx_found,        r.mx_detail)
    smtp_ok = r.smtp_accepted if r.smtp_checked else None
    row("4. SMTP Handshake", smtp_ok,           r.smtp_detail if r.smtp_checked else "Not checked")
    row("5. Catch-All",      None if not r.smtp_checked else not r.is_catch_all,
                                                r.catch_all_detail if r.smtp_checked else "Not checked")
    row("6. Disposable",     not r.is_disposable, r.disposable_detail)
    row("7. Role-Based",     not r.is_role_based, r.role_detail)
    row("8. Risk Score",     r.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM),
                                                f"{r.confidence_score}/100 — {r.risk_level.value} risk")
    print("─" * w)
    print()

# ── Summary printer ───────────────────────────────────────────
def print_summary(results, elapsed):
    total = len(results)
    if not total:
        return
    counts = {s: sum(1 for r in results if r.status == s) for s in EmailStatus}
    avg    = sum(r.confidence_score for r in results) / total
    print()
    print("═" * 62)
    print(f"  {'VALIDATION SUMMARY':^60}")
    print("═" * 62)
    print(f"  Total             : {total}")
    print(f"  Time              : {elapsed:.1f}s  ({total/max(elapsed,0.1):.1f} emails/sec)")
    print(f"  Avg confidence    : {avg:.1f}/100")
    print()
    rows = []
    for status, cnt in counts.items():
        if cnt == 0:
            continue
        pct  = cnt / total * 100
        rows.append([
            f"{ICONS.get(status,'')} {colored(status.value.upper(), STATUS_COLOR.get(status,''))}",
            cnt,
            f"{pct:.1f}%",
        ])
    if HAS_TABULATE:
        print(tabulate(rows, headers=["Status", "Count", "%"], tablefmt="simple"))
    else:
        for r in rows:
            print(f"  {r[0]:<28} {r[1]:>6}  {r[2]:>6}")
    valid_cnt = counts[EmailStatus.VALID] + counts[EmailStatus.CATCHALL]
    hp = valid_cnt / total * 100
    hc = Fore.GREEN if hp >= 90 else Fore.YELLOW if hp >= 70 else Fore.RED
    print()
    print(f"  List health  : {colored(f'{hp:.1f}%', hc)}")
    print("═" * 62)
    print()

# ── MAIN ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ClearBounce — Email Validation (preserves your CSV columns)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--email", "-e", help="Single email to validate")
    group.add_argument("--file",  "-f", help="Your CSV file")

    parser.add_argument("--output",       "-o", default=None,   help="Output file name (default: original_name_validated.csv)")
    parser.add_argument("--email-column", "-c", default=None,   help="Column name with emails (auto-detected if not set)")
    parser.add_argument("--workers",      "-w", type=int, default=10, help="Parallel workers (default: 10)")
    parser.add_argument("--smtp-timeout", "-t", type=int, default=8,  help="SMTP timeout seconds (default: 8)")
    parser.add_argument("--dns-timeout",        type=float, default=4.0)
    parser.add_argument("--fast",         action="store_true",  help="Skip SMTP — DNS only (faster)")
    parser.add_argument("--json",         action="store_true",  help="JSON output (single email only)")

    args = parser.parse_args()

    # ── SINGLE EMAIL ─────────────────────────────────────────
    if args.email:
        print(f"\n  🔍 Validating: {args.email}\n")
        r = validate_email(args.email, smtp_timeout=args.smtp_timeout,
                           dns_timeout=args.dns_timeout, skip_smtp=args.fast)
        if args.json:
            print(json.dumps(r.to_dict(), indent=2))
        else:
            print_single_result(r)
        sys.exit(0 if r.is_deliverable else 1)

    # ── BULK CSV ─────────────────────────────────────────────
    path = args.file
    if not os.path.exists(path):
        print(f"❌ File not found: {path}")
        sys.exit(1)

    print(f"\n  📋 ClearBounce — Reading your file...")
    headers, rows = read_csv_with_rows(path)

    if not rows:
        print("❌ No rows found in file.")
        sys.exit(1)

    # Find email column
    email_col = args.email_column or find_email_column(list(headers))
    if not email_col:
        print("\n  ⚠️  Could not auto-detect the email column.")
        print("  Available columns:")
        for i, h in enumerate(headers):
            print(f"    [{i}] {h}")
        col_input = input("\n  Enter the column name or number containing emails: ").strip()
        if col_input.isdigit():
            email_col = headers[int(col_input)]
        else:
            email_col = col_input
        print(f"  Using column: '{email_col}'")
    else:
        print(f"  📧 Email column detected: '{email_col}'")

    # Extract emails from rows (keep row index so we can match back)
    email_to_rows = {}   # email → list of row indices (same email can appear multiple times)
    for i, row in enumerate(rows):
        raw = (row.get(email_col) or "").strip().lower()
        # Extract email if cell has extra text
        match = EMAIL_RE.search(raw)
        email = match.group(0) if match else raw
        row["_email_clean"] = email
        row["_row_idx"]     = i
        if email not in email_to_rows:
            email_to_rows[email] = []
        email_to_rows[email].append(i)

    # Get unique valid-looking emails to validate
    unique_emails = [e for e in email_to_rows if "@" in e]
    total_rows    = len(rows)

    print(f"  Rows total        : {total_rows}")
    print(f"  Unique emails     : {len(unique_emails)}")
    print(f"  Mode              : {'Fast (DNS only)' if args.fast else 'Full (DNS + SMTP)'}")
    print(f"  Workers           : {args.workers}")
    print()

    if not unique_emails:
        print("❌ No emails found in that column.")
        sys.exit(1)

    # ── VALIDATE ────────────────────────────────────────────
    start   = time.time()
    results = {}   # email → ValidationResult

    def validate_one(email):
        return email, validate_email(
            email,
            smtp_timeout=args.smtp_timeout,
            dns_timeout=args.dns_timeout,
            skip_smtp=args.fast,
        )

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(validate_one, e): e for e in unique_emails}

        if HAS_TQDM:
            pbar = tqdm(total=len(unique_emails), unit="email", desc="Validating",
                        ncols=80, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")
        else:
            pbar = None
            print(f"  Validating {len(unique_emails)} emails...")

        for future in as_completed(futures):
            email, r = future.result()
            results[email] = r
            if pbar:
                pbar.set_postfix_str(f"{email[:35]} → {r.status.value}", refresh=True)
                pbar.update(1)
            else:
                done = len(results)
                if done % 100 == 0 or done == len(unique_emails):
                    pct = done / len(unique_emails) * 100
                    print(f"  Progress: {done}/{len(unique_emails)} ({pct:.0f}%)")

        if pbar:
            pbar.close()

    elapsed = time.time() - start

    # ── BUILD OUTPUT CSV ─────────────────────────────────────
    # All original columns + "Email Status" at the end
    out_headers = list(headers) + ["Email Status"]

    # Remove internal tracking keys
    STATUS_COL = "Email Status"

    out_path = args.output
    if not out_path:
        stem     = Path(path).stem
        out_path = str(Path(path).parent / f"{stem}_validated.csv")

    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        # utf-8-sig so Excel opens it correctly on Mac/Windows
        writer = csv.DictWriter(f, fieldnames=out_headers, extrasaction="ignore")
        writer.writeheader()

        for row in rows:
            email  = row.get("_email_clean", "")
            result = results.get(email)

            if result:
                label = status_label(result.status)
            elif not email or "@" not in email:
                label = "No email / invalid format"
            else:
                label = "Not checked"

            # Write original row + new status column
            out_row = {k: row.get(k, "") for k in headers}
            out_row[STATUS_COL] = label
            writer.writerow(out_row)

    # ── ALSO SAVE VALID-ONLY FILE ────────────────────────────
    valid_path = str(Path(out_path).parent / (Path(out_path).stem + "_valid_only.csv"))
    with open(valid_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=out_headers, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            email  = row.get("_email_clean", "")
            result = results.get(email)
            if result and result.status == EmailStatus.VALID:
                out_row = {k: row.get(k, "") for k in headers}
                out_row[STATUS_COL] = status_label(result.status)
                writer.writerow(out_row)

    # ── SUMMARY ──────────────────────────────────────────────
    result_list = list(results.values())
    print_summary(result_list, elapsed)

    valid_count = sum(1 for r in result_list if r.status == EmailStatus.VALID)
    print(f"  💾 Full report   → {out_path}")
    print(f"  💾 Valid only    → {valid_path}  ({valid_count} rows)")
    print()

if __name__ == "__main__":
    main()
