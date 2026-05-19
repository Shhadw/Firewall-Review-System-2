# reader.py
import csv
import io
import re

# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------
# Core columns every valid firewall rule CSV must have.
RULE_REQUIRED_COLUMNS = {
    "order", "protocol",
    "src_ip", "src_port",
    "dst_ip", "dst_port"
}

# Firewall log columns required for audit mapping.
LOG_REQUIRED_COLUMNS = {
    "date", "time", "action", "protocol",
    "src-ip", "src-port", "dst-ip", "dst-port",
}

# Optional columns we capture when present; downstream modules should
# treat a None value here as "not provided / unknown".
OPTIONAL_COLUMNS = {"action", "hit_count"}

# File extensions we accept.  Anything else is rejected before we even
# try to parse bytes, so the app never crashes on a stray .pdf or .exe.
ALLOWED_EXTENSIONS = {".csv", ".txt", ".log"}


def _normalize_column_name(col):
    """
    Normalize column names to handle variations like:
    - "date and time" vs "date & time" vs "dateandtime"
    - "event id" vs "event_id" vs "eventid"
    - "task category" vs "task_category" vs "taskcategory"
    """
    # Convert to lowercase and strip
    normalized = str(col).strip().lower()
    # Replace common separators and abbreviations
    normalized = normalized.replace('&', 'and')      # "date & time" -> "date and time"
    normalized = re.sub(r'[_\-/]', ' ', normalized)  # underscores/dashes/slashes -> space
    # Collapse multiple spaces into single space
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

    # Normalize all column names
    normalized_fields = [_normalize_column_name(col) for col in reader.fieldnames]
    present_columns = set(normalized_fields)
    
    # Also normalize required columns
    normalized_required = {_normalize_column_name(col) for col in required_columns}
    
    # Special handling: treat "desc" and "description" as equivalent for logs
    if "desc" in normalized_required and "description" in present_columns:
        present_columns.discard("description")
        present_columns.add("desc")
        # Update normalized_fields to replace "description" with "desc"
        normalized_fields = ["desc" if f == "description" else f for f in normalized_fields]
    
    missing = normalized_required - present_columns
    if missing:
        # More detailed error message showing what we found vs what we expected
        raise ValueError(
            f"{file_type} is missing required columns: {sorted(missing)}\n"
            f"Found columns: {sorted(present_columns)}\n"
            f"Expected columns: {sorted(normalized_required)}"
        )
    
    # Update reader.fieldnames to use normalized names so DictReader works correctly
    reader.fieldnames = normalized_fields
    return present_columns

    # ------------------------------------------------------------------
    # 1. File-type guard  (Revision 1)
    #    Reject unsupported extensions immediately so we never crash
    #    trying to decode a binary file as UTF-8 text.
    # ------------------------------------------------------------------

def process_rules_csv(file, filename: str = ""):
    """
    Validate, read, and parse a firewall-rule CSV upload.
    """
    if filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(
                f"Unsupported file type '{ext}'. Please upload a CSV file (.csv or .txt)."
            )

    # ------------------------------------------------------------------
    # 2. Read raw bytes
    # ------------------------------------------------------------------

    raw = file.read()
    if not raw:
        raise ValueError("Uploaded file is empty.")

    # ------------------------------------------------------------------
    # 3. Decode — try UTF-8 first, fall back to Latin-1
    # ------------------------------------------------------------------

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    # ------------------------------------------------------------------
    # 4. Parse headers
    # ------------------------------------------------------------------

    # Remove BOM if present
    if text.startswith('\ufeff'):
        text = text[1:]

    # Try to detect delimiter
    sample_line = text.split('\n')[0] if text else ""
    if '\t' in sample_line and ',' not in sample_line:
        delimiter = '\t'
    else:
        delimiter = ','

    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    present_columns = _validate_headers(reader, RULE_REQUIRED_COLUMNS, "Firewall rules CSV")
    has_hit_count = "hit_count" in present_columns

    # ------------------------------------------------------------------
    # 6. Parse rows into dicts  (Revisions 2 & 3)
    # ------------------------------------------------------------------

    rules = []
    for row in reader:
        # Skip blank / all-whitespace rows
        if not any(str(v).strip() for v in row.values()):
            continue
        
        # Normalize row keys to match normalized fieldnames from _validate_headers
        normalized_row = {}
        for key, value in row.items():
            norm_key = _normalize_column_name(key) if key else key
            normalized_row[norm_key] = value
        
        rule = {
            "order":     _safe_int(normalized_row.get("order")),
            "protocol":  _clean_str(normalized_row.get("protocol")).lower(),
            "src_ip":    _clean_str(normalized_row.get("src ip")).lower(),
            "src_port":  _safe_val(normalized_row.get("src port")),
            "dst_ip":    _clean_str(normalized_row.get("dst ip")).lower(),
            "dst_port":  _safe_val(normalized_row.get("dst port")),
            "action":    _clean_str(normalized_row.get("action")).upper() if normalized_row.get("action") is not None else "",
            "hit_count": _safe_int(normalized_row.get("hit count")) if has_hit_count else None,
        }
        rules.append(rule)

    return rules


def process_logs_csv(file, filename: str = ""):
    """
    Validate, read, and parse firewall logs (CSV or space-separated .log format).
    Detects file type and calls appropriate parser.
    """
    if filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(
                f"Unsupported file type '{ext}'. Please upload a log file (.log, .csv, or .txt)."
            )
        # Route to appropriate parser
        if ext == ".log":
            return process_logs_log(file, filename)
    
    # Default: treat as CSV
    return process_logs_csv_internal(file, filename)


def process_logs_log(file, filename: str = ""):
    """
    Validate, read, and parse firewall log files in space-separated format.
    Expected format: date time action protocol src-ip src-port dst-ip dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
    """
    raw = file.read()
    if not raw:
        raise ValueError("Uploaded log file is empty.")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    # Remove BOM if present
    if text.startswith('\ufeff'):
        text = text[1:]

    lines = text.strip().split('\n')
    if not lines:
        raise ValueError("Log file is empty.")

    # Parse header (first line)
    header_line = lines[0].strip()
    headers = header_line.split()
    
    # Normalize header names for easier matching
    normalized_headers = [_normalize_column_name(h) for h in headers]
    
    # Validate required columns
    required_normalized = {_normalize_column_name(col) for col in LOG_REQUIRED_COLUMNS}
    present_columns = set(normalized_headers)
    
    missing = required_normalized - present_columns
    if missing:
        raise ValueError(
            f"Log file is missing required columns: {sorted(missing)}\n"
            f"Found columns: {sorted(present_columns)}\n"
            f"Expected columns: {sorted(required_normalized)}"
        )

    # Parse data lines
    logs = []
    for line_num, line in enumerate(lines[1:], start=2):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        values = line.split()
        
        # Handle lines with fewer values than headers (incomplete entries)
        if len(values) < len(headers):
            # Pad with empty strings
            values.extend([''] * (len(headers) - len(values)))
        elif len(values) > len(headers):
            # Join excess values into the last field (for "info" or "path" fields with spaces)
            values = values[:len(headers) - 1] + [' '.join(values[len(headers) - 1:])]
        
        # Create log entry with original header names as keys
        log_entry = {}
        for i, header in enumerate(headers):
            norm_header = _normalize_column_name(header)
            log_entry[norm_header] = _clean_str(values[i]) if i < len(values) else ""
        
        # Only add non-empty entries
        if any(log_entry.values()):
            logs.append(log_entry)
    
    if not logs:
        raise ValueError("No log data found in file.")

    return logs


def process_logs_csv_internal(file, filename: str = ""):
    """
    Validate, read, and parse firewall log CSV files (legacy support).
    """
    raw = file.read()
    if not raw:
        raise ValueError("Uploaded log file is empty.")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    # Remove BOM if present
    if text.startswith('\ufeff'):
        text = text[1:]

    # Try to detect delimiter
    sample_line = text.split('\n')[0] if text else ""
    if '\t' in sample_line and ',' not in sample_line:
        delimiter = '\t'
    else:
        delimiter = ','

    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    present_columns = _validate_headers(reader, LOG_REQUIRED_COLUMNS, "Firewall logs CSV")

    logs = []
    for row in reader:
        if not any(str(v).strip() for v in row.values()):
            continue
        
        # Normalize keys to match fieldnames from _validate_headers
        log_entry = {}
        for key, value in row.items():
            norm_key = _normalize_column_name(key) if key else key
            # _validate_headers already maps "description" to "desc", but be explicit
            if norm_key == "description":
                norm_key = "desc"
            log_entry[norm_key] = _clean_str(value)
        
        logs.append(log_entry)

    if not logs:
        raise ValueError("No log data found in CSV.")

    return logs


def process_csv(file, filename: str = ""):
    """Backward-compatible alias for rule processing."""
    return process_rules_csv(file, filename)

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _clean_str(value) -> str:
    """Return a stripped string; empty string for None / missing values."""
    return str(value).strip() if value is not None else ""


def _safe_val(value):
    """
    Convert a port / order field to int when possible.
    Keeps 'any' as the string 'any'.
    Keeps CIDR / IP strings intact.
    """
    if value is None:
        return None
    val_str = str(value).strip().lower()

    if val_str in ("", "none"):
        return None
    if val_str == "any":
        return "any"
    # Looks like an IP or CIDR (multiple dots) — keep as string
    if val_str.count(".") > 1:
        return val_str
    try:
        return int(val_str)
    except (ValueError, TypeError):
        return val_str


def _safe_int(value):
    """
    Convert to int when possible; return None for empty / non-numeric values.
    Used for columns that should always be integers (order, hit_count).
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
# Quick self-test  (run with:  python reader.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":

    # ── Test 1: happy path with hit_count ──────────────────────────────
    class GoodFile:
        def read(self):
            return (
                b"order,protocol,src_ip,src_port,dst_ip,dst_port,action,hit_count\n"
                b"1,tcp,140.192.37.20,any,any,80,deny,42\n"
                b"2,tcp,140.192.37.0/24,any,any,80,accept,7\n"
                b"9,tcp,any,any,any,any,deny,0\n"
            )

    # ── Test 2: wrong file type ────────────────────────────────────────
    class PdfFile:
        def read(self):
            return b"%PDF-1.4 fake pdf bytes"

    # ── Test 3: missing required column ───────────────────────────────
    class BadCsv:
        def read(self):
            return (
                b"order,protocol,src_ip,src_port,dst_ip,action\n"   # dst_port missing
                b"1,tcp,10.0.0.1,80,10.0.0.2,deny\n"
            )

    import json

    tests = [
        ("Happy path (with hit_count)", GoodFile(), "rules.csv"),
        ("Wrong file type (.pdf)",      PdfFile(),  "upload.pdf"),
        ("Missing column (dst_port)",   BadCsv(),   "bad.csv"),
    ]

    for label, mock_file, fname in tests:
        print(f"\n{'─'*55}")
        print(f"TEST: {label}")
        try:
            result = process_csv(mock_file, filename=fname)
            print(json.dumps(result, indent=2))
            print(f"✅ Passed — {len(result)} rule(s) loaded.")
        except ValueError as exc:
            print(f"✅ Caught expected error → {exc}")
        except Exception as exc:
            print(f"❌ Unexpected crash → {exc}")