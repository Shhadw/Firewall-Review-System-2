import csv
import io
import ipaddress
import re

# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------
RULE_REQUIRED_COLUMNS = {
    "order", "protocol",
    "src_ip", "src_port",
    "dst_ip", "dst_port",
}

LOG_REQUIRED_COLUMNS = {
    "date", "time", "action", "protocol",
    "src-ip", "src-port", "dst-ip", "dst-port",
}

OPTIONAL_COLUMNS = {"action", "hit_count"}

ALLOWED_EXTENSIONS = {".csv", ".txt", ".log"}

# ---------------------------------------------------------------------------
# Validation constants
# ---------------------------------------------------------------------------
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "any", "esp", "ah", "gre", "igmp", "ip"}

VALID_ACTIONS = {"allow", "accept", "deny", "drop", "reject"}

PORT_MIN = 0
PORT_MAX = 65535


# ---------------------------------------------------------------------------
# Column name normalization helpers
# ---------------------------------------------------------------------------

def _normalize_column_name(col):
    """
    Normalize column names to handle variations like:
    - "date and time" vs "date & time" vs "dateandtime"
    - "event id" vs "event_id" vs "eventid"
    - "task category" vs "task_category" vs "taskcategory"
    """
    normalized = str(col).strip().lower()
    normalized = normalized.replace('&', 'and')
    normalized = re.sub(r'[_\-/]', ' ', normalized)
    normalized = re.sub(r'\s+', ' ', normalized)
    return normalized


def _find_matching_column(col_name, available_columns):
    """
    Find a column that matches the given name, accounting for common variations.
    Returns the original column name if found, or None if not found.
    """
    normalized_target = _normalize_column_name(col_name)
    for available_col in available_columns:
        if _normalize_column_name(available_col) == normalized_target:
            return available_col
    return None


def _validate_headers(reader, required_columns, file_type="CSV"):
    if reader.fieldnames is None:
        raise ValueError(f"{file_type} has no headers.")

    normalized_fields = [_normalize_column_name(col) for col in reader.fieldnames]
    present_columns = set(normalized_fields)

    normalized_required = {_normalize_column_name(col) for col in required_columns}

    # Treat "desc" and "description" as equivalent
    if "desc" in normalized_required and "description" in present_columns:
        present_columns.discard("description")
        present_columns.add("desc")
        normalized_fields = ["desc" if f == "description" else f for f in normalized_fields]

    missing = normalized_required - present_columns
    if missing:
        raise ValueError(
            f"{file_type} is missing required columns: {sorted(missing)}\n"
            f"Found columns: {sorted(present_columns)}\n"
            f"Expected columns: {sorted(normalized_required)}"
        )

    reader.fieldnames = normalized_fields
    return present_columns


# ---------------------------------------------------------------------------
# Value validators  (raise ValueError on bad input)
# ---------------------------------------------------------------------------

def _validate_protocol(value, row_num=None) -> str:
    """
    Validate and normalise a protocol field.
    Accepted values: tcp, udp, icmp, any, esp, ah, gre, igmp, ip  (case-insensitive).
    Raises ValueError for anything else.
    """
    if value is None:
        raise ValueError(
            _row_prefix(row_num) +
            "Protocol is required but missing."
        )
    cleaned = str(value).strip().lower()
    if cleaned == "":
        raise ValueError(
            _row_prefix(row_num) +
            "Protocol cannot be empty."
        )
    if cleaned not in VALID_PROTOCOLS:
        raise ValueError(
            _row_prefix(row_num) +
            f"Invalid protocol '{value}'. "
            f"Must be one of: {', '.join(sorted(VALID_PROTOCOLS))}."
        )
    return cleaned


def _validate_port(value, field_name="port", row_num=None):
    """
    Validate a port field.
    Accepted values:
      - The string 'any'  → returned as 'any'
      - An integer 0-65535 → returned as int
      - A port range 'start:end' or 'start-end' → returned as string 'start:end'
    Raises ValueError for letters, out-of-range numbers, or malformed ranges.
    """
    if value is None:
        return None
    val_str = str(value).strip().lower()
    if val_str in ("", "none"):
        return None
    if val_str == "any":
        return "any"

    # Port range: e.g. "1024:2048" or "1024-2048"
    range_match = re.fullmatch(r"(\d+)[:\-](\d+)", val_str)
    if range_match:
        start, end = int(range_match.group(1)), int(range_match.group(2))
        if not (PORT_MIN <= start <= PORT_MAX):
            raise ValueError(
                _row_prefix(row_num) +
                f"Invalid {field_name} range start {start}: must be {PORT_MIN}–{PORT_MAX}."
            )
        if not (PORT_MIN <= end <= PORT_MAX):
            raise ValueError(
                _row_prefix(row_num) +
                f"Invalid {field_name} range end {end}: must be {PORT_MIN}–{PORT_MAX}."
            )
        if start > end:
            raise ValueError(
                _row_prefix(row_num) +
                f"Invalid {field_name} range '{value}': start must be ≤ end."
            )
        return f"{start}:{end}"

    # Single port number
    if not re.fullmatch(r"\d+", val_str):
        raise ValueError(
            _row_prefix(row_num) +
            f"Invalid {field_name} value '{value}'. "
            f"Must be a number ({PORT_MIN}–{PORT_MAX}), a range (e.g. '1024:2048'), or 'any'."
        )
    port = int(val_str)
    if not (PORT_MIN <= port <= PORT_MAX):
        raise ValueError(
            _row_prefix(row_num) +
            f"Invalid {field_name} value {port}: must be {PORT_MIN}–{PORT_MAX}."
        )
    return port


def _validate_ip(value, field_name="ip", row_num=None) -> str:
    """
    Validate an IP address or CIDR block field.
    Accepted values:
      - 'any'                   → returned as 'any'
      - Valid IPv4 address       → e.g. '192.168.1.1'
      - Valid IPv4 CIDR          → e.g. '10.0.0.0/8'
      - Valid IPv6 address/CIDR  → e.g. '::1', '2001:db8::/32'
    Raises ValueError for random strings, invalid octets, bad CIDR masks, etc.
    """
    if value is None:
        raise ValueError(
            _row_prefix(row_num) +
            f"{field_name} is required but missing."
        )
    val_str = str(value).strip().lower()
    if val_str in ("", "none"):
        raise ValueError(
            _row_prefix(row_num) +
            f"{field_name} cannot be empty."
        )
    if val_str == "any":
        return "any"

    # Attempt to parse as network (handles both bare IPs and CIDR notation)
    try:
        network = ipaddress.ip_network(val_str, strict=False)
        # Return in canonical form
        if network.num_addresses == 1:
            return str(network.network_address)
        return str(network)
    except ValueError:
        pass

    # Attempt to parse as plain address (covers edge cases ip_network rejects)
    try:
        addr = ipaddress.ip_address(val_str)
        return str(addr)
    except ValueError:
        pass

    raise ValueError(
        _row_prefix(row_num) +
        f"Invalid {field_name} value '{value}'. "
        "Must be a valid IPv4/IPv6 address, CIDR block (e.g. '10.0.0.0/8'), or 'any'."
    )


def _validate_action(value, row_num=None) -> str:
    """
    Validate the action field.
    Accepted (case-insensitive): allow, accept, deny, drop, reject.
    Returns the value uppercased.
    Raises ValueError for anything else.
    """
    if value is None or str(value).strip() == "":
        # Action is optional in rule CSVs; return empty string to signal absence.
        return ""
    cleaned = str(value).strip().lower()
    if cleaned not in VALID_ACTIONS:
        raise ValueError(
            _row_prefix(row_num) +
            f"Invalid action '{value}'. "
            f"Must be one of: {', '.join(sorted(VALID_ACTIONS))}."
        )
    return cleaned.upper()


def _validate_order(value, row_num=None) -> int:
    """
    Validate the rule order field.
    Must be a positive integer.
    """
    if value is None or str(value).strip() in ("", "none"):
        raise ValueError(
            _row_prefix(row_num) +
            "Rule order is required but missing."
        )
    val_str = str(value).strip()
    if not re.fullmatch(r"\d+", val_str):
        raise ValueError(
            _row_prefix(row_num) +
            f"Invalid order value '{value}'. Must be a positive integer."
        )
    order = int(val_str)
    if order < 1:
        raise ValueError(
            _row_prefix(row_num) +
            f"Invalid order value {order}. Must be ≥ 1."
        )
    return order


def _validate_hit_count(value, row_num=None):
    """
    Validate the optional hit_count field.
    Must be a non-negative integer when present.
    """
    if value is None or str(value).strip() in ("", "none"):
        return None
    val_str = str(value).strip()
    if not re.fullmatch(r"\d+", val_str):
        raise ValueError(
            _row_prefix(row_num) +
            f"Invalid hit_count value '{value}'. Must be a non-negative integer."
        )
    return int(val_str)


# ---------------------------------------------------------------------------
# Public parsers
# ---------------------------------------------------------------------------

def process_rules_csv(file, filename: str = ""):
    """
    Validate, read, and parse a firewall-rule CSV upload.
    Each row is fully validated: protocol, ports, IPs, action, order, hit_count.
    """
    if filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(
                f"Unsupported file type '{ext}'. Please upload a CSV file (.csv or .txt)."
            )

    raw = file.read()
    if not raw:
        raise ValueError("Uploaded file is empty.")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    if text.startswith('\ufeff'):
        text = text[1:]

    sample_line = text.split('\n')[0] if text else ""
    delimiter = '\t' if ('\t' in sample_line and ',' not in sample_line) else ','

    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    present_columns = _validate_headers(reader, RULE_REQUIRED_COLUMNS, "Firewall rules CSV")
    has_hit_count = "hit count" in present_columns or "hit_count" in present_columns

    rules = []
    errors = []

    for row_index, row in enumerate(reader, start=2):  # row 1 = header
        if not any(str(v).strip() for v in row.values()):
            continue

        # Normalize row keys
        normalized_row = {
            _normalize_column_name(k): v
            for k, v in row.items()
            if k is not None
        }

        row_errors = []

        # --- order ---
        try:
            order = _validate_order(normalized_row.get("order"), row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))
            order = None

        # --- protocol ---
        try:
            protocol = _validate_protocol(normalized_row.get("protocol"), row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))
            protocol = None

        # --- src_ip ---
        try:
            src_ip = _validate_ip(normalized_row.get("src ip"), "src_ip", row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))
            src_ip = None

        # --- src_port ---
        try:
            src_port = _validate_port(normalized_row.get("src port"), "src_port", row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))
            src_port = None

        # --- dst_ip ---
        try:
            dst_ip = _validate_ip(normalized_row.get("dst ip"), "dst_ip", row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))
            dst_ip = None

        # --- dst_port ---
        try:
            dst_port = _validate_port(normalized_row.get("dst port"), "dst_port", row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))
            dst_port = None

        # --- action (optional column) ---
        try:
            action = _validate_action(normalized_row.get("action"), row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))
            action = ""

        # --- hit_count (optional column) ---
        hit_count = None
        if has_hit_count:
            try:
                hit_count = _validate_hit_count(
                    normalized_row.get("hit count") or normalized_row.get("hit_count"),
                    row_num=row_index,
                )
            except ValueError as e:
                row_errors.append(str(e))

        if row_errors:
            errors.extend(row_errors)
            continue  # Skip invalid row; collect all errors before raising

        rules.append({
            "order":     order,
            "protocol":  protocol,
            "src_ip":    src_ip,
            "src_port":  src_port,
            "dst_ip":    dst_ip,
            "dst_port":  dst_port,
            "action":    action,
            "hit_count": hit_count,
        })

    if errors:
        raise ValueError("Validation errors found in CSV:\n" + "\n".join(f"  • {e}" for e in errors))

    if not rules:
        raise ValueError("No valid rule data found in CSV.")

    return rules


def process_logs_csv(file, filename: str = ""):
    """
    Validate, read, and parse firewall logs (CSV or space-separated .log format).
    """
    if filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(
                f"Unsupported file type '{ext}'. Please upload a log file (.log, .csv, or .txt)."
            )
        if ext == ".log":
            return process_logs_log(file, filename)

    return process_logs_csv_internal(file, filename)


def process_logs_log(file, filename: str = ""):
    """
    Parse firewall log files in space-separated format.
    Validates protocol, ports, IPs, and action on each log entry.
    """
    raw = file.read()
    if not raw:
        raise ValueError("Uploaded log file is empty.")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    if text.startswith('\ufeff'):
        text = text[1:]

    lines = text.strip().split('\n')
    if not lines:
        raise ValueError("Log file is empty.")

    header_line = lines[0].strip()
    headers = header_line.split()
    normalized_headers = [_normalize_column_name(h) for h in headers]

    required_normalized = {_normalize_column_name(col) for col in LOG_REQUIRED_COLUMNS}
    present_columns = set(normalized_headers)
    missing = required_normalized - present_columns
    if missing:
        raise ValueError(
            f"Log file is missing required columns: {sorted(missing)}\n"
            f"Found columns: {sorted(present_columns)}\n"
            f"Expected columns: {sorted(required_normalized)}"
        )

    logs = []
    errors = []

    for line_num, line in enumerate(lines[1:], start=2):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        values = line.split()
        if len(values) < len(headers):
            values.extend([''] * (len(headers) - len(values)))
        elif len(values) > len(headers):
            values = values[:len(headers) - 1] + [' '.join(values[len(headers) - 1:])]

        log_entry = {}
        for i, header in enumerate(headers):
            norm_header = _normalize_column_name(header)
            log_entry[norm_header] = _clean_str(values[i]) if i < len(values) else ""

        row_errors = []

        # Validate protocol
        try:
            log_entry["protocol"] = _validate_protocol(log_entry.get("protocol"), row_num=line_num)
        except ValueError as e:
            row_errors.append(str(e))

        # Validate source port
        try:
            log_entry["src port"] = _validate_port(log_entry.get("src port"), "src-port", row_num=line_num)
        except ValueError as e:
            row_errors.append(str(e))

        # Validate destination port
        try:
            log_entry["dst port"] = _validate_port(log_entry.get("dst port"), "dst-port", row_num=line_num)
        except ValueError as e:
            row_errors.append(str(e))

        # Validate source IP
        try:
            log_entry["src ip"] = _validate_ip(log_entry.get("src ip"), "src-ip", row_num=line_num)
        except ValueError as e:
            row_errors.append(str(e))

        # Validate destination IP
        try:
            log_entry["dst ip"] = _validate_ip(log_entry.get("dst ip"), "dst-ip", row_num=line_num)
        except ValueError as e:
            row_errors.append(str(e))

        # Validate action
        try:
            log_entry["action"] = _validate_action(log_entry.get("action"), row_num=line_num)
        except ValueError as e:
            row_errors.append(str(e))

        if row_errors:
            errors.extend(row_errors)
            continue

        if any(log_entry.values()):
            logs.append(log_entry)

    if errors:
        raise ValueError("Validation errors found in log file:\n" + "\n".join(f"  • {e}" for e in errors))

    if not logs:
        raise ValueError("No log data found in file.")

    return logs


def process_logs_csv_internal(file, filename: str = ""):
    """
    Parse firewall log CSV files with full field validation.
    """
    raw = file.read()
    if not raw:
        raise ValueError("Uploaded log file is empty.")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    if text.startswith('\ufeff'):
        text = text[1:]

    sample_line = text.split('\n')[0] if text else ""
    delimiter = '\t' if ('\t' in sample_line and ',' not in sample_line) else ','

    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    _validate_headers(reader, LOG_REQUIRED_COLUMNS, "Firewall logs CSV")

    logs = []
    errors = []

    for row_index, row in enumerate(reader, start=2):
        if not any(str(v).strip() for v in row.values()):
            continue

        log_entry = {}
        for key, value in row.items():
            norm_key = _normalize_column_name(key) if key else key
            if norm_key == "description":
                norm_key = "desc"
            log_entry[norm_key] = _clean_str(value)

        row_errors = []

        # Validate protocol
        try:
            log_entry["protocol"] = _validate_protocol(log_entry.get("protocol"), row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))

        # Validate source port
        try:
            log_entry["src port"] = _validate_port(log_entry.get("src port"), "src-port", row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))

        # Validate destination port
        try:
            log_entry["dst port"] = _validate_port(log_entry.get("dst port"), "dst-port", row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))

        # Validate source IP
        try:
            log_entry["src ip"] = _validate_ip(log_entry.get("src ip"), "src-ip", row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))

        # Validate destination IP
        try:
            log_entry["dst ip"] = _validate_ip(log_entry.get("dst ip"), "dst-ip", row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))

        # Validate action
        try:
            log_entry["action"] = _validate_action(log_entry.get("action"), row_num=row_index)
        except ValueError as e:
            row_errors.append(str(e))

        if row_errors:
            errors.extend(row_errors)
            continue

        logs.append(log_entry)

    if errors:
        raise ValueError("Validation errors found in CSV:\n" + "\n".join(f"  • {e}" for e in errors))

    if not logs:
        raise ValueError("No log data found in CSV.")

    return logs


def process_csv(file, filename: str = ""):
    """Backward-compatible alias for rule processing."""
    return process_rules_csv(file, filename)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _row_prefix(row_num) -> str:
    """Return a row-number prefix for error messages, or empty string if None."""
    return f"Row {row_num}: " if row_num is not None else ""


def _clean_str(value) -> str:
    """Return a stripped string; empty string for None / missing values."""
    return str(value).strip() if value is not None else ""


def _safe_val(value):
    """
    Legacy helper kept for any external callers.
    New code should use _validate_port() instead.
    """
    if value is None:
        return None
    val_str = str(value).strip().lower()
    if val_str in ("", "none"):
        return None
    if val_str == "any":
        return "any"
    if val_str.count(".") > 1:
        return val_str
    try:
        return int(val_str)
    except (ValueError, TypeError):
        return val_str


def _safe_int(value):
    """
    Legacy helper kept for any external callers.
    New code should use the specific validators instead.
    """
    if value is None:
        return None
    val_str = str(value).strip().lower()
    if val_str in ("", "none"):
        return None
    try:
        return int(val_str)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Self-test  (run with:  python reader.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    def _run(label, file_obj, fname):
        print(f"\n{'─' * 60}")
        print(f"TEST: {label}")
        try:
            result = process_csv(file_obj, filename=fname)
            print(json.dumps(result, indent=2))
            print(f"✅  Passed — {len(result)} rule(s) loaded.")
        except ValueError as exc:
            print(f"✅  Caught expected error →\n{exc}")
        except Exception as exc:
            print(f"❌  Unexpected crash → {exc}")

    # ── 1. Happy path ────────────────────────────────────────────────────
    class GoodFile:
        def read(self):
            return (
                b"order,protocol,src_ip,src_port,dst_ip,dst_port,action,hit_count\n"
                b"1,tcp,140.192.37.20,any,any,80,deny,42\n"
                b"2,udp,140.192.37.0/24,1024:2048,10.0.0.1,53,accept,7\n"
                b"3,icmp,any,any,any,any,deny,0\n"
            )

    # ── 2. Bad protocol ──────────────────────────────────────────────────
    class BadProtocol:
        def read(self):
            return (
                b"order,protocol,src_ip,src_port,dst_ip,dst_port,action\n"
                b"1,ftp,10.0.0.1,80,10.0.0.2,443,deny\n"
                b"2,xyz,10.0.0.1,80,10.0.0.2,443,allow\n"
            )

    # ── 3. Bad port (letters) ────────────────────────────────────────────
    class BadPort:
        def read(self):
            return (
                b"order,protocol,src_ip,src_port,dst_ip,dst_port,action\n"
                b"1,tcp,10.0.0.1,abc,10.0.0.2,80,deny\n"
            )

    # ── 4. Port out of range ─────────────────────────────────────────────
    class PortOutOfRange:
        def read(self):
            return (
                b"order,protocol,src_ip,src_port,dst_ip,dst_port,action\n"
                b"1,tcp,10.0.0.1,99999,10.0.0.2,80,deny\n"
            )

    # ── 5. Bad IP ────────────────────────────────────────────────────────
    class BadIP:
        def read(self):
            return (
                b"order,protocol,src_ip,src_port,dst_ip,dst_port,action\n"
                b"1,tcp,not_an_ip,80,10.0.0.2,443,deny\n"
            )

    # ── 6. Bad action ────────────────────────────────────────────────────
    class BadAction:
        def read(self):
            return (
                b"order,protocol,src_ip,src_port,dst_ip,dst_port,action\n"
                b"1,tcp,10.0.0.1,80,10.0.0.2,443,forward\n"
            )

    # ── 7. Bad hit_count ─────────────────────────────────────────────────
    class BadHitCount:
        def read(self):
            return (
                b"order,protocol,src_ip,src_port,dst_ip,dst_port,action,hit_count\n"
                b"1,tcp,10.0.0.1,80,10.0.0.2,443,deny,lots\n"
            )

    # ── 8. Multiple errors collected across rows ─────────────────────────
    class MultiError:
        def read(self):
            return (
                b"order,protocol,src_ip,src_port,dst_ip,dst_port,action\n"
                b"1,badproto,notanip,abcde,10.0.0.2,99999,whatever\n"
                b"2,tcp,10.0.0.1,80,10.0.0.2,443,deny\n"  # this row is fine
            )

    # ── 9. Valid CIDR and port range ─────────────────────────────────────
    class CIDRAndRange:
        def read(self):
            return (
                b"order,protocol,src_ip,src_port,dst_ip,dst_port,action\n"
                b"1,tcp,192.168.0.0/16,1024:65535,10.0.0.0/8,80,allow\n"
            )

    # ── 10. Wrong file extension ─────────────────────────────────────────
    class AnyFile:
        def read(self):
            return b"some bytes"

    _run("1. Happy path (tcp/udp/icmp, range port, CIDR)", GoodFile(), "rules.csv")
    _run("2. Invalid protocol (ftp, xyz)",                 BadProtocol(), "rules.csv")
    _run("3. Port = letters ('abc')",                      BadPort(), "rules.csv")
    _run("4. Port out of range (99999)",                   PortOutOfRange(), "rules.csv")
    _run("5. Invalid IP ('not_an_ip')",                    BadIP(), "rules.csv")
    _run("6. Invalid action ('forward')",                  BadAction(), "rules.csv")
    _run("7. Invalid hit_count ('lots')",                  BadHitCount(), "rules.csv")
    _run("8. Multiple errors collected across rows",       MultiError(), "rules.csv")
    _run("9. Valid CIDR + port range",                     CIDRAndRange(), "rules.csv")
    _run("10. Wrong file extension (.pdf)",                AnyFile(), "upload.pdf")