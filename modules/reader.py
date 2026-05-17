# reader.py
import csv
import io

# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------
# Core columns every valid firewall CSV must have.
REQUIRED_COLUMNS = {
    "order", "protocol",
    "src_ip", "src_port",
    "dst_ip", "dst_port",
    "action",
}

# Optional columns we capture when present; downstream modules should
# treat a None value here as "not provided / unknown".
OPTIONAL_COLUMNS = {"hit_count"}

# File extensions we accept.  Anything else is rejected before we even
# try to parse bytes, so the app never crashes on a stray .pdf or .exe.
ALLOWED_EXTENSIONS = {".csv", ".txt"}


def process_csv(file, filename: str = ""):
    """
    Validate, read, and parse a firewall-rule CSV upload.

    Parameters
    ----------
    file     : file-like object with a .read() method (e.g. Flask's request.files entry)
    filename : original filename from the upload (used for extension check)

    Returns
    -------
    list[dict]  – one dict per rule row, ready for the analyzer module.

    Raises
    ------
    ValueError  – on any problem the caller should surface to the user.
    """

    # ------------------------------------------------------------------
    # 1. File-type guard  (Revision 1)
    #    Reject unsupported extensions immediately so we never crash
    #    trying to decode a binary file as UTF-8 text.
    # ------------------------------------------------------------------
    if filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(
                f"Unsupported file type '{ext}'. "
                f"Please upload a CSV file (.csv or .txt)."
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
    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        raise ValueError("CSV has no headers.")

    # Normalise: strip surrounding whitespace, lowercase
    reader.fieldnames = [str(col).strip().lower() for col in reader.fieldnames]
    present_columns = set(reader.fieldnames)

    # ------------------------------------------------------------------
    # 5. Validate required columns
    # ------------------------------------------------------------------
    missing = REQUIRED_COLUMNS - present_columns
    if missing:
        raise ValueError(
            f"CSV is missing required columns: {sorted(missing)}"
        )

    # Detect whether the optional hit_count column was supplied
    has_hit_count = "hit_count" in present_columns

    # ------------------------------------------------------------------
    # 6. Parse rows into dicts  (Revisions 2 & 3)
    # ------------------------------------------------------------------
    rules = []
    for row in reader:
        # Skip blank / all-whitespace rows
        if not any(str(v).strip() for v in row.values()):
            continue

        rule = {
            "order":     _safe_int(row.get("order")),
            "protocol":  _clean_str(row.get("protocol")).lower(),
            "src_ip":    _clean_str(row.get("src_ip")).lower(),
            "src_port":  _safe_val(row.get("src_port")),
            "dst_ip":    _clean_str(row.get("dst_ip")).lower(),
            "dst_port":  _safe_val(row.get("dst_port")),
            "action":    _clean_str(row.get("action")).upper(),
            # hit_count: integer when present, None when column is absent,
            # 0 when the cell exists but is empty — all safe for the analyzer.
            "hit_count": _safe_int(row.get("hit_count")) if has_hit_count else None,
        }
        rules.append(rule)

    if not rules:
        raise ValueError("No rule data found in CSV.")

    return rules


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
