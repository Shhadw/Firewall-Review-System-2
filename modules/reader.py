#reader.py
import csv
import io

# Updated to match the "Pro" industry-standard headers
REQUIRED_COLUMNS = {"order", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "action"}

def process_csv(file):
    """
    Reads the 7-column CSV and converts it into a structured list of dictionaries.
    """
    raw = file.read()
    if not raw:
        raise ValueError("Uploaded file is empty.")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        raise ValueError("CSV has no headers.")

    # Clean and standardize headers (strip spaces, lowercase)
    reader.fieldnames = [str(col).strip().lower() for col in reader.fieldnames]

    # Validate columns
    missing = REQUIRED_COLUMNS - set(reader.fieldnames)
    if missing:
        raise ValueError(f"CSV is missing required columns: {missing}")

    rules = []
    for row in reader:
        if not any(row.values()):
            continue

        rules.append({
            "order":    _safe_val(row.get("order")),
            "protocol": str(row.get("protocol", "")).strip().lower(),
            "src_ip":   str(row.get("src_ip", "")).strip().lower(),
            "src_port": _safe_val(row.get("src_port")),
            "dst_ip":   str(row.get("dst_ip", "")).strip().lower(),
            "dst_port": _safe_val(row.get("dst_port")),
            "action":   str(row.get("action", "")).strip().upper(),
        })

    if not rules:
        raise ValueError("No rule data found in CSV.")

    return rules

def _safe_val(value):
    if value is None: 
        return None
    val_str = str(value).strip().lower()
    
    if val_str == "any":
        return "any"
    
    # If it's an IP (contains more than one dot), keep it as a string
    if val_str.count('.') > 1:
        return val_str 

    try:
        return int(val_str)
    except (ValueError, TypeError):
        return val_str

# --- Quick Test Block ---
if __name__ == "__main__":
    class MockFile:
        def read(self):
            # This is exactly what your CSV should look like
            return (
                b"order,protocol,src_ip,src_port,dst_ip,dst_port,action\n"
                b"1,tcp,140.192.37.20,any,any,80,deny\n"
                b"2,tcp,140.192.37.0/24,any,any,80,accept\n"
                b"9,tcp,any,any,any,any,deny"
            )
                
    try:
        parsed_rules = process_csv(MockFile())
        import json
        print(json.dumps(parsed_rules, indent=2))
        print(f"\n✅ Reader Test Passed: {len(parsed_rules)} rules loaded.")
    except Exception as e:
        print(f"❌ Reader Test Error: {e}")
