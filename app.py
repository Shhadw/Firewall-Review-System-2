# app.py
import os
import sys
import random
import re
from flask import Flask, render_template, request, jsonify, session, redirect

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))
from analyzer import analyze_rule
from reader import process_logs_csv, process_rules_csv

app = Flask(__name__)
app.secret_key = 'plm_defense_super_secret_key'

def simulate_live_traffic(parsed_rules):
    if 'rule_history_memory' not in session:
        session['rule_history_memory'] = {}

    for rule in parsed_rules:
        rule_id = rule.get('order', 'unknown_id')

        # 🟢 THE FIX: Safely handle empty CSV cells (NoneType)
        raw_hits = rule.get('hit_count', 0)
        try:
            current_csv_hits = int(raw_hits) if raw_hits is not None else 0
        except (ValueError, TypeError):
            current_csv_hits = 0

        if current_csv_hits == 0:
            rule['hit_count'] = 0
            continue

        if rule_id in session['rule_history_memory']:
            simulated_new_traffic = random.randint(12, 85)
            new_total = session['rule_history_memory'][rule_id] + simulated_new_traffic
            rule['hit_count'] = new_total
        else:
            rule['hit_count'] = current_csv_hits

        session['rule_history_memory'][rule_id] = rule['hit_count']

    return parsed_rules


def _normalize_value(value):
    if value is None:
        return ''
    return str(value).strip().lower()


def _normalize_port(port_value):
    """Normalize port value, handling 'any' and converting to int if applicable."""
    normalized = _normalize_value(port_value)
    if normalized in ('any', ''):
        return 'any'
    try:
        return int(normalized)
    except (ValueError, TypeError):
        return normalized


def _normalize_ip(ip_value):
    """Normalize IP address, handling 'any' and CIDR notation."""
    normalized = _normalize_value(ip_value)
    if normalized in ('any', '', '0.0.0.0/0'):
        return 'any'
    return normalized


    """
    Simple IP matching: check if ip matches cidr_or_ip.
    Handles exact match or CIDR notation (basic check).
    """
    if cidr_or_ip == 'any':
        return True
    if ip == cidr_or_ip:
        return True
    # Basic CIDR check: if cidr contains /, assume it's a network
    if '/' in cidr_or_ip:
        # For simplicity, just check if IP starts with the network portion
        network_part = cidr_or_ip.split('/')[0]
        return ip.startswith(network_part)
    return False

def _ip_in_range(ip, cidr_or_ip):
    """
    Simple IP matching: check if ip matches cidr_or_ip.
    Handles exact match or CIDR notation (basic check).
    """
    if cidr_or_ip == 'any':
        return True
    if ip == cidr_or_ip:
        return True
    # Basic CIDR check: if cidr contains /, assume it's a network
    if '/' in cidr_or_ip:
        try:
            network_part = cidr_or_ip.split('/')[0]
            prefix_len = int(cidr_or_ip.split('/')[1])
            
            # Convert IPs to integers for comparison
            ip_parts = ip.split('.')
            network_parts = network_part.split('.')
            
            if len(ip_parts) != 4 or len(network_parts) != 4:
                return False
            
            ip_int = sum(int(p) << (8 * (3 - i)) for i, p in enumerate(ip_parts))
            network_int = sum(int(p) << (8 * (3 - i)) for i, p in enumerate(network_parts))
            
            # Create mask for prefix length
            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
            
            return (ip_int & mask) == (network_int & mask)
        except (ValueError, IndexError):
            return False
    return False

def _rule_matches_log(rule, log):
    """
    Check if a log entry matches a firewall rule.
    Matches on: src_ip, src_port, dst_ip, dst_port
    """
    rule_src_ip = _normalize_ip(rule.get('src_ip', 'any'))
    rule_src_port = _normalize_port(rule.get('src_port', 'any'))
    rule_dst_ip = _normalize_ip(rule.get('dst_ip', 'any'))
    rule_dst_port = _normalize_port(rule.get('dst_port', 'any'))
    
    log_src_ip = _normalize_ip(log.get('src ip', 'any'))
    log_src_port = _normalize_port(log.get('src port', 'any'))
    log_dst_ip = _normalize_ip(log.get('dst ip', 'any'))
    log_dst_port = _normalize_port(log.get('dst port', 'any'))
    
    # All four fields must match
    src_ip_match = _ip_in_range(log_src_ip, rule_src_ip)
    src_port_match = rule_src_port == 'any' or log_src_port == 'any' or rule_src_port == log_src_port
    dst_ip_match = _ip_in_range(log_dst_ip, rule_dst_ip)
    dst_port_match = rule_dst_port == 'any' or log_dst_port == 'any' or rule_dst_port == log_dst_port
    
    return src_ip_match and src_port_match and dst_ip_match and dst_port_match


def aggregate_rule_hits_from_logs(parsed_rules, logs):
    """
    Count hits for each rule by matching against log entries.
    A rule gets a hit when a log matches on src_ip, src_port, dst_ip, dst_port.
    """
    hit_counts = {rule.get('order', 'unknown_id'): 0 for rule in parsed_rules}

    for log in logs:
        for rule in parsed_rules:
            if _rule_matches_log(rule, log):
                rule_id = rule.get('order', 'unknown_id')
                hit_counts[rule_id] = hit_counts.get(rule_id, 0) + 1

    return hit_counts


def normalize_and_save_logs(logs):
    """
    Normalize log data for consistent storage and processing.
    Returns a list of normalized log entries.
    """
    normalized_logs = []
    for log in logs:
        normalized_entry = {
            'date': _clean_str(log.get('date', '')),
            'time': _clean_str(log.get('time', '')),
            'action': _clean_str(log.get('action', '')).lower(),
            'protocol': _clean_str(log.get('protocol', '')).lower(),
            'src_ip': _normalize_ip(log.get('src ip', 'any')),
            'src_port': _normalize_port(log.get('src port', 'any')),
            'dst_ip': _normalize_ip(log.get('dst ip', 'any')),
            'dst_port': _normalize_port(log.get('dst port', 'any')),
            'size': _clean_str(log.get('size', '')),
            'tcpflags': _clean_str(log.get('tcpflags', '')),
            'tcpsyn': _clean_str(log.get('tcpsyn', '')),
            'tcpack': _clean_str(log.get('tcpack', '')),
            'tcpwin': _clean_str(log.get('tcpwin', '')),
            'icmptype': _clean_str(log.get('icmptype', '')),
            'icmpcode': _clean_str(log.get('icmpcode', '')),
            'info': _clean_str(log.get('info', '')),
            'path': _clean_str(log.get('path', ''))
        }
        normalized_logs.append(normalized_entry)
    return normalized_logs


def _clean_str(value) -> str:
    """Return a stripped string; empty string for None / missing values."""
    return str(value).strip() if value is not None else ""

@app.route('/')
def index():
    session.clear()
    return render_template('homepage.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/reports')
def reports():
    history = session.get('history', [])
    decisions = session.get('decisions', {})
    return render_template('reports.html', history=history, decisions=decisions)

@app.route('/credits')
def credits():
    return render_template('credits.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'GET':
        return render_template('upload.html')

    if request.method == 'POST':
        rules_file = request.files.get('rules_file')
        logs_file = request.files.get('logs_file')

        if not rules_file or rules_file.filename == '':
            return jsonify({"error": "No firewall rules file provided"}), 400

        try:
            raw_rules = process_rules_csv(rules_file, filename=rules_file.filename)
            raw_logs = []
            if logs_file and logs_file.filename != '':
                raw_logs = process_logs_csv(logs_file, filename=logs_file.filename)

            if raw_logs:
                hit_counts = aggregate_rule_hits_from_logs(raw_rules, raw_logs)
                for rule in raw_rules:
                    rule_id = rule.get('order', 'unknown_id')
                    csv_hits = rule.get('hit_count') or 0
                    rule['hit_count'] = max(csv_hits, hit_counts.get(rule_id, 0))
            else:
                raw_rules = simulate_live_traffic(raw_rules)

            # Normalize and save logs
            normalized_logs = normalize_and_save_logs(raw_logs) if raw_logs else []

            analyzed_rules = []
            summary = {"total_rules": len(raw_rules), "critical": 0, "high": 0, "medium": 0, "low": 0}

            for rule in raw_rules:
                result = analyze_rule(rule)

                frontend_rule = {
                    "rule_id": f"FW-R-{result.get('order', '000')}",
                    "src_ip": result.get('src_ip', 'any'),
                    "dst_ip": result.get('dst_ip', 'any'),
                    "dst_port": result.get('dst_port', 'any'),
                    "protocol": result.get('protocol', 'any').upper(),
                    "hit_count": result.get('hit_count', 0),
                    "status": result.get('status', 'OK'),
                    "findings": result.get('findings', [])
                }
                analyzed_rules.append(frontend_rule)

                status = frontend_rule["status"]
                if status == "CRITICAL": summary["critical"] += 1
                elif status == "HIGH": summary["high"] += 1
                elif status == "MEDIUM": summary["medium"] += 1
                elif status == "LOW": summary["low"] += 1

            session['current_scan'] = {
                "filename": rules_file.filename,
                "summary": summary,
                "rules": analyzed_rules,
                "logs": normalized_logs
            }

            history = session.get('history', [])
            history = [h for h in history if h['filename'] != rules_file.filename]

            history_entry = {
                'filename': rules_file.filename,
                'summary': summary,
                'rules': analyzed_rules,
                'logs': normalized_logs
            }
            history.insert(0, history_entry)
            session['history'] = history[:10]

            return jsonify({"message": "Success"}), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/api/get_analysis_results', methods=['GET'])
def get_analysis_results():
    scan_data = session.get('current_scan')
    if not scan_data:
        return jsonify({"error": "No scan data found."}), 404
    scan_data['decisions'] = session.get('decisions', {})
    return jsonify(scan_data)

@app.route('/decide', methods=['POST'])
def decide():
    data = request.get_json()
    rule_id = str(data.get('rule_id'))
    decision = data.get('decision')

    if decision not in ["Keep", "Remove"]:
        return jsonify({"error": "Invalid decision"}), 400

    decisions = session.get('decisions', {})
    decisions[rule_id] = decision
    session['decisions'] = decisions
    session.modified = True

    return jsonify({"status": "ok", "rule_id": rule_id, "decision": decision})

@app.route('/api/load_report', methods=['POST'])
def load_report():
    """Swaps the current dashboard scan to a historical report."""
    data = request.get_json()
    filename = data.get('filename')
    history = session.get('history', [])

    for entry in history:
        if entry['filename'] == filename:
            session['current_scan'] = entry
            return jsonify({"status": "success"}), 200

    return jsonify({"error": "Report not found"}), 404

if __name__ == '__main__':
    app.run(debug=True)