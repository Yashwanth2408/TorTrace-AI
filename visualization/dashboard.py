from flask import Flask, render_template, jsonify, send_file, request
import joblib
import pandas as pd
import json
import csv
import os
from datetime import datetime
import io
import random
from flask import Response
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)

# Paths based on your structure
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BATCH_RESULTS_DIR = os.path.join(PROJECT_ROOT, '..', 'data', 'batch_results')
SUMMARY_CSV = os.path.join(BATCH_RESULTS_DIR, 'batch_summary.csv')

# Model and metrics files (adjust if moved)
MODEL_FILE = os.path.join(BATCH_RESULTS_DIR, "tor_detection_model.pkl")
METRICS_FILE = os.path.join(BATCH_RESULTS_DIR, "evaluation_results.json")
ROC_CURVE_FILE = os.path.join(BATCH_RESULTS_DIR, "roc_curve_balanced.png")

# Load model and metrics at startup
if os.path.exists(MODEL_FILE):
    model = joblib.load(MODEL_FILE)
else:
    model = None

FEATURES_FILE = os.path.join(BATCH_RESULTS_DIR, "model_features.json")

if os.path.exists(FEATURES_FILE):
    with open(FEATURES_FILE, 'r') as f:
        REQUIRED_FEATURES = json.load(f)
else:
    REQUIRED_FEATURES = []

if os.path.exists(METRICS_FILE):
    with open(METRICS_FILE, "r") as f:
        eval_metrics = json.load(f)
else:
    eval_metrics = {}

def load_batch_summary():
    """Load batch summary CSV"""
    results = []
    if os.path.exists(SUMMARY_CSV):
        with open(SUMMARY_CSV, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                results.append(row)
    return results

def get_statistics():
    """Calculate statistics from batch results"""
    summary = load_batch_summary()
    unique_pcaps = set(row['PCAP'] for row in summary)
    unique_guards = set(row['Relay Nickname'] for row in summary)
    analysis_files = [f for f in os.listdir(BATCH_RESULTS_DIR) if f.endswith('_analysis.json')]
    return {
        'total_pcaps': len(unique_pcaps),
        'total_guards': len(unique_guards),
        'total_analyses': len(analysis_files),
        'success_rate': 100 if len(summary) > 0 else 0
    }

def get_top_guards(limit=10):
    """Get top guard nodes by frequency"""
    summary = load_batch_summary()
    guard_counts = {}
    for row in summary:
        nickname = row['Relay Nickname']
        if nickname in guard_counts:
            guard_counts[nickname]['count'] += 1
        else:
            guard_counts[nickname] = {
                'nickname': nickname,
                'ip': row['IP Address'],
                'confidence': row['Confidence'],
                'method': row['Method'],
                'count': 1
            }
    sorted_guards = sorted(guard_counts.values(), key=lambda x: x['count'], reverse=True)
    return sorted_guards[:limit]

def get_alert_log_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'alert_log.json'))

@app.route('/')
def index():
    """Main dashboard page"""
    stats = get_statistics()
    top_guards = get_top_guards(10)
    recent_results = load_batch_summary()[-20:]  # Last 20 results
    return render_template('dashboard.html',
                           stats=stats,
                           top_guards=top_guards,
                           recent_results=recent_results)

@app.route('/api/stats')
def api_stats():
    """API endpoint for statistics"""
    return jsonify(get_statistics())

@app.route('/api/guards')
def api_guards():
    """API endpoint for top guards"""
    return jsonify(get_top_guards(10))

@app.route('/download/csv')
def download_csv():
    """Download batch summary CSV"""
    return send_file(SUMMARY_CSV, as_attachment=True, download_name='tortrace_results.csv')

@app.route('/map')
def map_view():
    """Display geographic map"""
    map_file = 'templates/tor_map.html'
    if not os.path.exists(map_file):
        import subprocess
        subprocess.run(['python3', 'map_generator.py'], cwd='visualization')
    return send_file(map_file)

@app.route('/alerts')
def show_alerts():
    alert_file = get_alert_log_path()
    if os.path.exists(alert_file):
        with open(alert_file, 'r') as f:
            alerts = json.load(f)
    else:
        alerts = []
    return render_template('alerts.html', alerts=alerts)

@app.route('/alert_summary')
def alert_summary():
    alert_file = get_alert_log_path()
    if os.path.exists(alert_file):
        with open(alert_file, 'r') as f:
            alerts = json.load(f)
    else:
        alerts = []
    return jsonify(alerts[-1] if alerts else {})

@app.route('/clear_alerts', methods=['POST'])
def clear_alerts():
    alert_file = get_alert_log_path()
    with open(alert_file, 'w') as f:
        f.write('[]')
    return ('', 204)

@app.route('/metrics')
def metrics():
    metrics_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'perf_metrics.json'))
    if os.path.exists(metrics_file):
        with open(metrics_file, 'r') as f:
            metrics = json.load(f)
    else:
        metrics = {}
    return render_template('metrics.html', metrics=metrics)

# ---------- NEW SECTIONS FOR MODEL INTEGRATION ----------

@app.route('/model_metrics')
def model_metrics():
    """Serve evaluation results and ROC curve for the trained model."""
    response = {
        "metrics": eval_metrics,
        "roc_curve_url": "/model_roc_curve"
    }
    return jsonify(response)

@app.route('/model_roc_curve')
def model_roc_curve():
    """Serve the ROC curve image for the model."""
    return send_file(ROC_CURVE_FILE, mimetype='image/png')

@app.route('/predict_tor', methods=['POST'])
def predict_tor():
    """
    Predict Tor/nonTor for a single flow.
    Requires a JSON POST body with feature values matching those used by the model.
    """
    request_json = request.json
    if not request_json:
        return jsonify({"error": "Empty request."}), 400

    # Validate keys
    missing = [f for f in REQUIRED_FEATURES if f not in request_json]
    extra = [k for k in request_json if k not in REQUIRED_FEATURES]

    if missing:
        return jsonify({"error": f"Missing features: {missing}"}), 400
    if extra:
        return jsonify({"error": f"Extra unexpected features: {extra}"}), 400

    # proceed with prediction
    try:
        df = pd.DataFrame([request_json])[REQUIRED_FEATURES]
        prediction = int(model.predict(df)[0])
        probability = float(model.predict_proba(df)[0][1])
        return jsonify({
            "prediction": prediction,
            "probability_tor": probability
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/batch_upload')
def batch_upload():
    return render_template('batch_upload.html', required_features=REQUIRED_FEATURES)


MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

@app.route('/batch_predict', methods=['POST'])
def batch_predict():
    if 'file' not in request.files:
        return render_template('batch_upload.html', 
                               message='<span style="color:#ff0000;">❌ No file selected. Please choose a CSV file.</span>')

    file = request.files['file']

    # Check file size
    file.seek(0, 2)  # Move pointer to end to get size
    size = file.tell()
    file.seek(0)  # Reset pointer to beginning

    if size > MAX_FILE_SIZE:
        return render_template('batch_upload.html',
                               message=f'<span style="color:#ff0000;">❌ File too large ({size // 1024 // 1024}MB). Max: 50MB.</span>')
    if file.filename == '':
        return render_template('batch_upload.html', 
                               message='<span style="color:#ff0000;">❌ No file selected.</span>')

    if file and file.filename.endswith('.csv'):
        try:
            # Read CSV to DataFrame
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            df = pd.read_csv(stream)

            # Progress logging
            print(f"📊 Processing {len(df)} rows...")

            # Validate columns
            missing = [f for f in REQUIRED_FEATURES if f not in df.columns]
            extra = [c for c in df.columns if c not in REQUIRED_FEATURES]

            if missing:
                missing_list = '<br>• '.join(missing[:10])  # Show up to first 10 missing
                return render_template('batch_upload.html', 
                                       message=f'<span style="color:#ff0000;">❌ Missing columns:<br>• {missing_list}</span>')

            if extra:
                extra_list = '<br>• '.join(extra[:10])  # Show up to first 10 extra
                return render_template('batch_upload.html', 
                                       message=f'<span style="color:#ff0000;">⚠️ Extra columns present:<br>• {extra_list}</span>')

            # Reorder columns for model
            df = df[REQUIRED_FEATURES]

            # Predict
            predictions = model.predict(df)
            probabilities = model.predict_proba(df)[:, 1]

            # Add predictions to dataframe
            df['prediction'] = predictions
            df['probability_tor'] = probabilities

            # Save CSV to string buffer
            output = io.StringIO()
            df.to_csv(output, index=False)
            output.seek(0)

            # Save to disk for download
            filename = f"batch_prediction_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            save_path = os.path.join(BATCH_RESULTS_DIR, filename)
            with open(save_path, 'w') as f:
                f.write(output.getvalue())

            # Progress logging
            print(f"✅ Completed {len(df)} predictions")

            download_link = f'<a target="_blank" class="download-link" href="/download/batch/{filename}" style="color:#ff0000; font-weight:700;">Download batch results CSV</a>'

            return render_template('batch_upload.html', message=f"Batch prediction completed! {download_link}")

        except Exception as e:
            return render_template('batch_upload.html', message=f"<span style='color:#ff0000;'>Error processing file: {str(e)}</span>")

    else:
        return render_template('batch_upload.html', 
                               message='<span style="color:#ff0000;">Please upload a CSV file.</span>')


@app.route('/download/batch/<filename>')
def download_batch_file(filename):
    filepath = os.path.join(BATCH_RESULTS_DIR, filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True, download_name=filename)
    else:
        return f"File {filename} not found", 404

@app.route('/generate_sample_csv')
def generate_sample_csv():
    SAMPLE_ROWS = 5  # Change as needed

    # Adjust according to your exact feature names and ranges
    headers = REQUIRED_FEATURES  # This uses your loaded feature list (with exact spaces)
    rows = []
    for _ in range(SAMPLE_ROWS):
        row = [
            random.randint(1024, 65535),    # Source Port
            random.randint(1, 65535),       # Destination Port
            random.choice([1,6,17]),        # Protocol (ICMP, TCP, UDP)
            random.randint(1000, 50000),    # Flow Duration
            round(random.uniform(100, 100000), 3),   # Flow Bytes/s
            round(random.uniform(10, 10000), 3),     # Flow Packets/s
            random.randint(1, 20000),       # Flow IAT Mean
            random.randint(1, 5000),        # Flow IAT Std
            random.randint(10, 20000),      # Flow IAT Max
            random.randint(1, 1000),        # Flow IAT Min
            random.randint(1, 20000),       # Fwd IAT Mean
            random.randint(1, 5000),        # Fwd IAT Std
            random.randint(10, 20000),      # Fwd IAT Max
            random.randint(1, 1000),        # Fwd IAT Min
            random.randint(1, 20000),       # Bwd IAT Mean
            random.randint(1, 5000),        # Bwd IAT Std
            random.randint(10, 20000),      # Bwd IAT Max
            random.randint(1, 1000),        # Bwd IAT Min
            random.randint(1, 10000),       # Active Mean
            random.randint(1, 2000),        # Active Std
            random.randint(1, 20000),       # Active Max
            random.randint(1, 1000),        # Active Min
            random.randint(1, 8000),        # Idle Mean
            random.randint(1, 2000),        # Idle Std
            random.randint(1, 20000),       # Idle Max
            random.randint(1, 1000),        # Idle Min
        ]
        rows.append(row)
    # If your feature count or orders are different, update accordingly

    # Assemble CSV
    output = io.StringIO()
    output.write(",".join(headers) + "\n")
    for row in rows:
        output.write(",".join(map(str, row)) + "\n")
    output.seek(0)
    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=sample_batch.csv"})

@app.route('/generate_large_sample')
def generate_large_sample():
    SAMPLE_ROWS = 1000  # Large test

    # Adjust according to your exact feature names and ranges
    headers = REQUIRED_FEATURES  # This uses your loaded feature list (with exact spaces)
    rows = []
    for _ in range(SAMPLE_ROWS):
        row = [
            random.randint(1024, 65535),    # Source Port
            random.randint(1, 65535),       # Destination Port
            random.choice([1,6,17]),        # Protocol (ICMP, TCP, UDP)
            random.randint(1000, 50000),    # Flow Duration
            round(random.uniform(100, 100000), 3),   # Flow Bytes/s
            round(random.uniform(10, 10000), 3),     # Flow Packets/s
            random.randint(1, 20000),       # Flow IAT Mean
            random.randint(1, 5000),        # Flow IAT Std
            random.randint(10, 20000),      # Flow IAT Max
            random.randint(1, 1000),        # Flow IAT Min
            random.randint(1, 20000),       # Fwd IAT Mean
            random.randint(1, 5000),        # Fwd IAT Std
            random.randint(10, 20000),      # Fwd IAT Max
            random.randint(1, 1000),        # Fwd IAT Min
            random.randint(1, 20000),       # Bwd IAT Mean
            random.randint(1, 5000),        # Bwd IAT Std
            random.randint(10, 20000),      # Bwd IAT Max
            random.randint(1, 1000),        # Bwd IAT Min
            random.randint(1, 10000),       # Active Mean
            random.randint(1, 2000),        # Active Std
            random.randint(1, 20000),       # Active Max
            random.randint(1, 1000),        # Active Min
            random.randint(1, 8000),        # Idle Mean
            random.randint(1, 2000),        # Idle Std
            random.randint(1, 20000),       # Idle Max
            random.randint(1, 1000),        # Idle Min
        ]
        rows.append(row)
    # If your feature count or orders are different, update accordingly

    # Assemble CSV
    output = io.StringIO()
    output.write(",".join(headers) + "\n")
    for row in rows:
        output.write(",".join(map(str, row)) + "\n")
    output.seek(0)
    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=sample_batch.csv"})


if __name__ == '__main__':
    print("\n" + "="*70)
    print("TorTrace-AI Dashboard")
    print("="*70)
    print("Starting server on http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("="*70 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
