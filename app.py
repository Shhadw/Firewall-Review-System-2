# app.py
import os
import sys
import random
from flask import Flask, render_template, request, jsonify, session, redirect

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))
from analyzer import analyze_rule
from reader import process_csv

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

@app.route('/')
def index():
    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/reports')
def reports():
    history = session.get('history', [])
    return render_template('reports.html', history=history)

@app.route('/credits')
def credits():
    return render_template('credits.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'GET':
        return render_template('upload.html')

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        try:
            raw_rules = process_csv(file, filename=file.filename)
            simulated_rules = simulate_live_traffic(raw_rules)

            analyzed_rules = []
            summary = {"total_rules": len(simulated_rules), "critical": 0, "high": 0, "medium": 0, "low": 0}

            for rule in simulated_rules:
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
                "filename": file.filename,
                "summary": summary,
                "rules": analyzed_rules
            }

            history = session.get('history', [])
            history_entry = {
                'filename': file.filename,
                'summary': summary,
                'rules': analyzed_rules
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

if __name__ == '__main__':
    app.run(debug=True)