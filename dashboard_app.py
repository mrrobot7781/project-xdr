from flask import Flask, request, jsonify, render_template_string, Response
from kubernetes import client, config
import datetime
from functools import wraps

app = Flask(__name__)
alerts = []
latest_ai_report = None  # Global variable to store the latest AI summary

ADMIN_USER = "admin"
ADMIN_PASS = "AstraXdr@2026"

def check_auth(username, password):
    return username == ADMIN_USER and password == ADMIN_PASS

def authenticate():
    return Response(
        'Could not verify your access level for this URL.\n'
        'You have to log in with proper credentials.', 401,
        {'WWW-Authenticate': 'Basic realm="ASTRA-XDR SOC Access Required"'}
    )

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# Load Kubernetes Configuration
try:
    config.load_incluster_config()
    k8s_v1 = client.CoreV1Api()
    k8s_custom = client.CustomObjectsApi()
    k8s_enabled = True
except Exception as e:
    print(f"[ASTRA-XDR] K8s Config issue: {e}")
    k8s_enabled = False

def get_pod_metrics():
    """Fetch individual running pods and their live CPU/Memory utilization."""
    if not k8s_enabled:
        return []
    
    pod_data = []
    try:
        pods = k8s_v1.list_namespaced_pod(namespace="default")
        
        # Pull live pod metrics from K8s Metrics Server API
        metrics_dict = {}
        try:
            pod_metrics = k8s_custom.list_namespaced_custom_object(
                group="metrics.k8s.io", version="v1beta1", namespace="default", plural="pods"
            )
            for m in pod_metrics.get('items', []):
                metrics_dict[m['metadata']['name']] = m
        except Exception:
            pass # Metrics server might be syncing

        for pod in pods.items:
            pod_name = pod.metadata.name
            status = pod.status.phase
            cpu_val = 0
            mem_val = 0
            
            if pod_name in metrics_dict:
                for container in metrics_dict[pod_name]['containers']:
                    cpu_str = container['usage']['cpu']
                    mem_str = container['usage']['memory']
                    
                    # Parse CPU (convert cores/nanocores to millicores)
                    if cpu_str.endswith('n'):
                        cpu_val += int(cpu_str[:-1]) // 1000000
                    elif cpu_str.endswith('m'):
                        cpu_val += int(cpu_str[:-1])
                    
                    # Parse Memory (convert Ki/Mi to MB)
                    if mem_str.endswith('Ki'):
                        mem_val += int(mem_str[:-2]) // 1024
                    elif mem_str.endswith('Mi'):
                        mem_val += int(mem_str[:-2])

            # Calculate width percentages for the UI visual bars
            # Assuming 500mCPU and 512MiB as a "full" bar for visual scaling purposes
            cpu_pct = min((cpu_val / 500) * 100, 100) if cpu_val > 0 else 0
            mem_pct = min((mem_val / 512) * 100, 100) if mem_val > 0 else 0

            pod_data.append({
                "name": pod_name,
                "status": status,
                "cpu": cpu_val,
                "mem": mem_val,
                "cpu_pct": cpu_pct,
                "mem_pct": mem_pct
            })
            
    except Exception as e:
        print(f"[ASTRA-XDR] Error fetching pod metrics: {e}")
        
    return pod_data

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ASTRA-XDR | SOC Threat Center</title>
    <meta http-equiv="refresh" content="10">
    <link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        * {
            box-sizing: border-box;
        }

        :root {
            --bg-primary: #0a0e1a;
            --bg-secondary: #101621;
            --card-bg: rgba(20, 28, 44, 0.6);
            --card-border: rgba(255, 255, 255, 0.05);
            --card-border-hover: rgba(0, 242, 254, 0.2);
            
            --accent-cyan: #00f2fe;
            --accent-cyan-dim: rgba(0, 242, 254, 0.1);
            --accent-green: #00e676;
            --accent-green-dim: rgba(0, 230, 118, 0.1);
            --accent-red: #ff5252;
            --accent-red-dim: rgba(255, 82, 82, 0.1);
            --accent-orange: #ff9100;
            --accent-orange-dim: rgba(255, 145, 0, 0.1);
            --accent-purple: #d946ef;
            
            --text-primary: #f3f4f6;
            --text-secondary: #d1d5db;
            --text-muted: #9ca3af;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 100%);
            background-attachment: fixed;
            color: var(--text-primary);
            margin: 0;
            padding: 40px;
            min-height: 100vh;
        }

        /* Glassmorphic cards */
        .card {
            background: var(--card-bg);
            backdrop-filter: blur(20px);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .card:hover {
            border-color: var(--card-border-hover);
            box-shadow: 0 12px 48px rgba(0, 242, 254, 0.1);
        }

        /* Header with threat level indicator */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 40px;
            gap: 30px;
            flex-wrap: wrap;
        }

        .header-left h1 {
            font-size: 32px;
            font-weight: 700;
            margin: 0 0 8px 0;
            background: linear-gradient(135deg, #00f2fe 0%, #4facfe 50%, #d946ef 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
        }

        .header-left p {
            margin: 0;
            font-size: 14px;
            color: var(--text-muted);
            font-weight: 500;
        }

        .threat-indicator {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .threat-gauge {
            width: 180px;
            padding: 16px;
            background: var(--card-bg);
            backdrop-filter: blur(20px);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            text-align: center;
        }

        .threat-level {
            font-size: 28px;
            font-weight: 700;
            font-family: 'Space Mono', monospace;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .threat-level.critical { color: var(--accent-red); }
        .threat-level.high { color: var(--accent-orange); }
        .threat-level.medium { color: #fbbf24; }
        .threat-level.low { color: var(--accent-green); }

        .threat-label {
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: var(--accent-green-dim);
            color: var(--accent-green);
            border: 1px solid rgba(0, 230, 118, 0.3);
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .pulse {
            width: 6px;
            height: 6px;
            background: var(--accent-green);
            border-radius: 50%;
            animation: pulse 2s infinite;
            box-shadow: 0 0 10px var(--accent-green);
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        /* Pod Grid */
        .section-title {
            font-size: 16px;
            font-weight: 700;
            margin: 40px 0 20px 0;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .pod-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .pod-card {
            padding: 20px;
            position: relative;
            overflow: hidden;
        }

        .pod-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-cyan), transparent);
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .pod-card:hover::before {
            opacity: 1;
        }

        .pod-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
        }

        .pod-name {
            font-size: 13px;
            font-family: 'Space Mono', monospace;
            color: var(--accent-cyan);
            font-weight: 700;
            word-break: break-all;
            flex: 1;
            margin-right: 12px;
        }

        .pod-status-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
            flex-shrink: 0;
        }

        .status-running {
            background: var(--accent-green-dim);
            color: var(--accent-green);
            border: 1px solid rgba(0, 230, 118, 0.3);
        }

        .status-pending {
            background: var(--accent-orange-dim);
            color: var(--accent-orange);
            border: 1px solid rgba(255, 145, 0, 0.3);
        }

        .status-error {
            background: var(--accent-red-dim);
            color: var(--accent-red);
            border: 1px solid rgba(255, 82, 82, 0.3);
        }

        .metric-row {
            margin-bottom: 18px;
        }

        .metric-row:last-child {
            margin-bottom: 0;
        }

        .metric-header {
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            margin-bottom: 8px;
        }

        .metric-label {
            font-size: 12px;
            color: var(--text-muted);
            font-weight: 500;
        }

        .metric-value {
            font-family: 'Space Mono', monospace;
            font-size: 13px;
            font-weight: 700;
            color: var(--text-primary);
        }

        .metric-bar {
            width: 100%;
            height: 8px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 6px;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }

        .metric-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .metric-fill.cpu {
            background: linear-gradient(90deg, #00e676, #00b0ff);
        }

        .metric-fill.mem {
            background: linear-gradient(90deg, #00f2fe, #d946ef);
        }

        /* Alerts Table */
        .table-card {
            padding: 28px;
        }

        .table-card h3 {
            margin-top: 0;
            margin-bottom: 20px;
            font-size: 16px;
            font-weight: 700;
            color: var(--text-primary);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        th {
            text-align: left;
            padding: 12px 16px;
            color: var(--text-muted);
            font-weight: 600;
            border-bottom: 1px solid var(--card-border);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
        }

        td {
            padding: 14px 16px;
            border-bottom: 1px solid var(--card-border);
            color: var(--text-secondary);
        }

        tr:hover {
            background: rgba(0, 242, 254, 0.02);
        }

        .time-cell {
            font-family: 'Space Mono', monospace;
            color: var(--text-muted);
            font-size: 12px;
        }

        .priority-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-weight: 700;
            text-transform: uppercase;
            font-size: 10px;
            letter-spacing: 0.5px;
        }

        .priority-critical {
            background: var(--accent-red-dim);
            color: var(--accent-red);
            border: 1px solid rgba(255, 82, 82, 0.3);
        }

        .priority-warning {
            background: var(--accent-orange-dim);
            color: var(--accent-orange);
            border: 1px solid rgba(255, 145, 0, 0.3);
        }

        .priority-low {
            background: rgba(100, 200, 255, 0.1);
            color: #64c8ff;
            border: 1px solid rgba(100, 200, 255, 0.3);
        }

        .pod-name-cell {
            font-family: 'Space Mono', monospace;
            color: var(--accent-cyan);
            font-weight: 600;
        }

        .rule-cell {
            font-family: 'Space Mono', monospace;
            font-size: 12px;
            color: var(--text-secondary);
        }

        .rule-name {
            color: var(--text-primary);
            font-weight: 600;
            display: block;
            margin-bottom: 4px;
        }

        .remediation-action {
            display: flex;
            gap: 8px;
        }

        .btn-isolate {
            background: linear-gradient(135deg, var(--accent-red) 0%, #d50000 100%);
            color: white;
            border: none;
            padding: 8px 14px;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.2s ease;
            box-shadow: 0 4px 12px rgba(255, 82, 82, 0.25);
        }

        .btn-isolate:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(255, 82, 82, 0.4);
        }

        .btn-isolate:active {
            transform: translateY(0);
        }

        .isolated-tag {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: var(--accent-green);
            font-weight: 700;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
        }

        .checkmark {
            display: inline-block;
            width: 16px;
            height: 16px;
            background: var(--accent-green);
            border-radius: 3px;
            color: var(--bg-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            font-weight: 700;
        }

        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: var(--text-muted);
        }

        .empty-state-icon {
            font-size: 40px;
            margin-bottom: 12px;
        }

        /* AI Report */
        .ai-report-body {
            line-height: 1.7;
            font-size: 13px;
            color: var(--text-secondary);
        }

        .ai-report-body h1,
        .ai-report-body h2,
        .ai-report-body h3 {
            color: var(--accent-cyan);
            margin-top: 16px;
            margin-bottom: 10px;
            font-weight: 700;
        }

        .ai-report-body h1 { font-size: 18px; }
        .ai-report-body h2 { font-size: 15px; }
        .ai-report-body h3 { font-size: 13px; }

        .ai-report-body code {
            font-family: 'Space Mono', monospace;
            background: rgba(0, 0, 0, 0.3);
            padding: 2px 6px;
            border-radius: 4px;
            color: var(--accent-orange);
            font-size: 12px;
        }

        .ai-report-body pre {
            background: rgba(0, 0, 0, 0.4);
            padding: 12px 16px;
            border-radius: 8px;
            overflow-x: auto;
            border: 1px solid var(--card-border);
            font-size: 12px;
            font-family: 'Space Mono', monospace;
            color: #64ff64;
            line-height: 1.5;
        }

        .ai-report-body ul,
        .ai-report-body ol {
            padding-left: 20px;
            margin: 10px 0;
        }

        .ai-report-body li {
            margin-bottom: 6px;
        }

        /* Responsive */
        @media (max-width: 1024px) {
            .pod-grid {
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            }
        }

        @media (max-width: 768px) {
            body {
                padding: 20px;
            }

            .header {
                flex-direction: column;
            }

            .header-left h1 {
                font-size: 24px;
            }

            .pod-grid {
                grid-template-columns: 1fr;
            }

            .threat-gauge {
                width: 100%;
            }

            table {
                font-size: 12px;
            }

            td, th {
                padding: 10px 12px;
            }

            .btn-isolate {
                padding: 6px 10px;
                font-size: 11px;
            }
        }

        /* Empty state animation */
        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-8px); }
        }

        .empty-state-icon {
            animation: float 3s ease-in-out infinite;
        }
    </style>
    <script>
        function getThreatLevel() {
            const alerts_count = {{ alerts | length }};
            if (alerts_count > 10) return 'critical';
            if (alerts_count > 5) return 'high';
            if (alerts_count > 2) return 'medium';
            return 'low';
        }

        function remediatePod(podName, alertIndex) {
            if (confirm("Execute remediation: Terminate and isolate pod [" + podName + "]?")) {
                fetch('/api/pod/remediate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pod_name: podName, alert_id: alertIndex })
                })
                .then(res => res.json())
                .then(data => {
                    alert(data.message);
                    location.reload();
                });
            }
        }
    </script>
</head>
<body>

    <div class="header">
        <div class="header-left">
            <h1>🛡️ ASTRA-XDR</h1>
            <p>Extended Detection & Response · Real-Time Threat Operations</p>
        </div>
        <div class="threat-indicator">
            <div class="threat-gauge">
                {% set threat_level = 'critical' if alerts | length > 10 else 'high' if alerts | length > 5 else 'medium' if alerts | length > 2 else 'low' %}
                <p class="threat-level {{ threat_level }}">
                    {% if threat_level == 'critical' %}
                        🔴 CRITICAL
                    {% elif threat_level == 'high' %}
                        🟠 HIGH
                    {% elif threat_level == 'medium' %}
                        🟡 MEDIUM
                    {% else %}
                        🟢 LOW
                    {% endif %}
                </p>
                <p class="threat-label">Threat Level</p>
            </div>
            <div class="status-badge">
                <span class="pulse"></span>
                Live Monitoring
            </div>
        </div>
    </div>

    <!-- Pod Telemetry -->
    <h2 class="section-title">📦 Cluster Health</h2>
    <div class="pod-grid">
        {% for pod in pods %}
        <div class="card pod-card">
            <div class="pod-header">
                <div class="pod-name">{{ pod.name }}</div>
                <div class="pod-status-badge status-{{ pod.status|lower }}">{{ pod.status }}</div>
            </div>
            
            <div class="metric-row">
                <div class="metric-header">
                    <span class="metric-label">CPU</span>
                    <span class="metric-value">{{ pod.cpu }} mC</span>
                </div>
                <div class="metric-bar">
                    <div class="metric-fill cpu" style="width: {{ pod.cpu_pct }}%;"></div>
                </div>
            </div>

            <div class="metric-row">
                <div class="metric-header">
                    <span class="metric-label">Memory</span>
                    <span class="metric-value">{{ pod.mem }} MiB</span>
                </div>
                <div class="metric-bar">
                    <div class="metric-fill mem" style="width: {{ pod.mem_pct }}%;"></div>
                </div>
            </div>
        </div>
        {% else %}
        <div style="grid-column: 1/-1;">
            <div class="card" style="padding: 40px; text-align: center;">
                <div class="empty-state">
                    <div class="empty-state-icon">📭</div>
                    <p>No active pods detected in cluster</p>
                </div>
            </div>
        </div>
        {% endfor %}
    </div>

    <!-- Security Incidents -->
    <h2 class="section-title">⚠️ Runtime Security Events</h2>
    <div class="card table-card">
        <h3>Detected Anomalies & SOAR Actions</h3>
        <table>
            <thead>
                <tr>
                    <th style="width: 15%;">Timestamp</th>
                    <th style="width: 10%;">Priority</th>
                    <th style="width: 15%;">Target</th>
                    <th style="width: 40%;">Security Rule & Context</th>
                    <th style="width: 20%;">Action</th>
                </tr>
            </thead>
            <tbody>
                {% for a in alerts %}
                <tr>
                    <td class="time-cell">{{ a.time }}</td>
                    <td>
                        <span class="priority-badge {% if a.priority in ['Critical', 'Error'] %}priority-critical{% elif a.priority == 'Warning' %}priority-warning{% else %}priority-low{% endif %}">
                            {{ a.priority }}
                        </span>
                    </td>
                    <td class="pod-name-cell">{{ a.pod or '—' }}</td>
                    <td class="rule-cell">
                        <span class="rule-name">{{ a.rule }}</span>
                        {{ a.output }}
                    </td>
                    <td>
                        {% if a.remediated %}
                            <span class="isolated-tag">
                                <span class="checkmark">✓</span> ISOLATED
                            </span>
                        {% elif a.pod and a.pod != 'Unknown' %}
                            <button class="btn-isolate" onclick="remediatePod('{{ a.pod }}', {{ loop.index0 }})">Isolate</button>
                        {% else %}
                            <span style="color: var(--text-muted); font-size: 12px;">—</span>
                        {% endif %}
                    </td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="5">
                        <div class="empty-state">
                            <div class="empty-state-icon">✓</div>
                            <p>No threats detected. Cluster operating in secure state.</p>
                        </div>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <!-- AI Report -->
    <h2 class="section-title">🤖 AI Security Analysis</h2>
    <div class="card table-card">
        <h3>Automated DevSecOps Scan Results</h3>
        {% if ai_report %}
            <div id="ai-report-content" class="ai-report-body"></div>
            <script>
                const rawMarkdown = {{ ai_report | tojson }};
                document.getElementById('ai-report-content').innerHTML = marked.parse(rawMarkdown);
            </script>
        {% else %}
            <div class="empty-state" style="padding: 30px;">
                <div class="empty-state-icon">📊</div>
                <p>No scan reports received yet. Integrate Trivy, SonarQube, and OWASP ZAP via CI/CD pipeline.</p>
            </div>
        {% endif %}
    </div>

</body>
</html>
"""

@app.route('/')
@requires_auth
def index():
    pods = get_pod_metrics()
    return render_template_string(
        HTML_TEMPLATE,
        alerts=list(reversed(alerts)),
        pods=pods,
        ai_report=latest_ai_report
    )

@app.route('/api/falco/events', methods=['POST'])
def receive_falco_event():
    data = request.get_json(force=True)
    if data:
        output_fields = data.get('output_fields', {})
        pod_name = output_fields.get('k8s.pod.name', 'Unknown')

        alert = {
            'time': data.get('time', str(datetime.datetime.now())),
            'rule': data.get('rule', 'Unknown Rule'),
            'priority': data.get('priority', 'Notice'),
            'output': data.get('output', 'No message body'),
            'pod': pod_name,
            'remediated': False
        }
        alerts.append(alert)
        return jsonify({"status": "received"}), 200
    return jsonify({"error": "invalid payload"}), 400

@app.route('/api/ai-report', methods=['POST'])
def receive_ai_report():
    global latest_ai_report
    data = request.get_json(force=True)
    if data and 'report' in data:
        latest_ai_report = data.get('report')
        return jsonify({"status": "received"}), 200
    return jsonify({"error": "invalid payload"}), 400

@app.route('/api/pod/remediate', methods=['POST'])
@requires_auth
def remediate_pod():
    req_data = request.get_json(force=True)
    pod_name = req_data.get('pod_name')
    alert_id = req_data.get('alert_id')

    if not k8s_enabled:
        return jsonify({"message": "Kubernetes API client unavailable"}), 500

    try:
        k8s_v1.delete_namespaced_pod(name=pod_name, namespace="default")

        rev_index = len(alerts) - 1 - alert_id
        if 0 <= rev_index < len(alerts):
            alerts[rev_index]['remediated'] = True

        return jsonify({"message": f"SOAR SUCCESS: Pod [{pod_name}] terminated. Kubernetes auto-healing initiated clean instance."}), 200
    except Exception as e:
        return jsonify({"message": f"Error terminating pod: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
