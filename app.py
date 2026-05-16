from flask import Flask, render_template, request, jsonify, session, redirect
import csv
import io
import os
import sys

# Ensure backend modules are correctly accessible
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))
from reader import process_csv
from analyzer import analyze_rules
from reporter import generate_summary

app = Flask(__name__)
app.secret_key = 'firewall-review-secret-key' # Required for session-based history [cite: 1029]

@app.route('/') 
def dashboard():
    """Main dashboard view following progressive disclosure."""
    # Retrieves raw rows for table and report summary for cards [cite: 1029]
    csv_data = session.get('csv_data', [])
    report = session.get('report', None)
    filename = session.get('filename', None)
    return render_template('dashboard.html', csv_data=csv_data, report=report, filename=filename)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """Handles AJAX-based file uploads and dual-pipeline analysis."""
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "No file received"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"status": "error", "message": "No selected file"}), 400

        try:
            # --- 1. CAPTURE RAW DATA FOR UI TABLE (LIST OF LISTS) ---
            # Resetting pointer ensures we read from the start of the file [cite: 1083]
            file.seek(0)
            content = file.read().decode('utf-8-sig', errors='ignore')            
            raw_reader = csv.reader(io.StringIO(content))
            csv_raw_rows = list(raw_reader) # [cite: 1083]

            # --- 2. CAPTURE STRUCTURED DATA FOR ANALYZER (LIST OF DICTS) ---
            # Reset again for the standardized modular reader [cite: 1083]
            file.seek(0)
            rules_list = process_csv(file)
            
            # --- 3. ANALYZE AND SUMMARIZE ---
            # analyzer.py uses 'dst_port' key provided by the reader [cite: 1057, 1059]
            findings = analyze_rules(rules_list)
            
            # reporter.py categorizes results into DANGER, WARNING, or SECURE [cite: 1031]
            report = generate_summary(findings)
            report['findings'] = findings # For detailed finding loops [cite: 1032]
            
            # --- 4. PERSIST IN SESSION ---
            session['csv_data'] = csv_raw_rows # Fixes header-repetition error [cite: 1083]
            session['filename'] = file.filename
            session['report'] = report
            
            # Update History Audit Log [cite: 1032]
            history = session.get('history', [])
            history_entry = {
                'filename': file.filename,
                'report': report,
                'csv_data': csv_raw_rows
            }
            history = [h for h in history if h.get('filename') != file.filename]
            history.insert(0, history_entry)
            session['history'] = history[:10]

            return jsonify({
                "status": "success",
                "message": f"Analysis Complete: Found {len(findings)} risks.",
                "report": report
            })
            
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    return render_template('upload.html')     

@app.route('/reports')
def reports():
    """Renders the Past Reports audit page."""
    history = session.get('history', [])
    return render_template('reports.html', history=history)

@app.route('/select/<int:index>')
def select_history(index):
    """Reloads selected history back to the main dashboard."""
    history = session.get('history', [])
    if 0 <= index < len(history):
        entry = history[index]
        session['csv_data'] = entry.get('csv_data', [])
        session['report'] = entry.get('report', None)
        session['filename'] = entry.get('filename', None)
    return redirect('/')

@app.route('/credits')
def credits():
    return render_template('credits.html')

if __name__ == '__main__':    
    app.run(debug=True)