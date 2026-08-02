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
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(22, 31, 48, 0.7);
            --card-border: rgba(255, 255, 255, 0.08);
            --accent-cyan: #00f2fe;
            --accent-green: #00e676;
            --accent-red: #ff5252;
            --accent-orange: #ff9100;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 30px;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 20px;
            margin-bottom: 25px;
        }

        .header h1 {
            font-size: 26px;
            margin: 0;
            background: linear-gradient(90deg, #00f2fe 0%, #4facfe 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .badge-live {
            background: rgba(0, 230, 118, 0.15);
            color: var(--accent-green);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            border: 1px solid rgba(0, 230, 118, 0.3);
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .dot {
            width: 8px;
            height: 8px;
            background-color: var(--accent-green);
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 8px var(--accent-green);
        }

        /* New Pod Grid Styling */
        .pod-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .pod-card {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }

        .pod-card h3 {
            margin-top: 0;
            font-size: 14px;
            color: var(--accent-cyan);
            margin-bottom: 12px;
            word-break: break-all;
            font-family: 'JetBrains Mono', monospace;
        }

        .pod-status {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            margin-bottom: 15px;
            letter-spacing: 1px;
        }
        .status-running { background: rgba(0, 230, 118, 0.15); color: var(--accent-green); border: 1px solid rgba(0, 230, 118, 0.4); }
        .status-pending { background: rgba(255, 145, 0, 0.15); color: var(--accent-orange); border: 1px solid rgba(255, 145, 0, 0.4); }
        .status-error { background: rgba(255, 82, 82, 0.15); color: var(--accent-red); border: 1px solid rgba(255, 82, 82, 0.4); }

        .metric-row {
            margin-bottom: 15px;
        }

        .metric-labels {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }

        .metric-val {
            font-family: 'JetBrains Mono', monospace;
            color: #fff;
            font-weight: 700;
        }

        .bar-bg {
            width: 100%;
            height: 6px;
            background: rgba(255,255,255,0.08);
            border-radius: 4px;
            overflow: hidden;
        }

        .bar-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.5s ease;
        }

        .cpu-fill { background: linear-gradient(90deg, #00e676, #00b0ff); }
        .mem-fill { background: linear-gradient(90deg, #00f2fe, #4facfe); }

        .table-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 30px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-family: 'Inter', sans-serif;
            font-size: 14px;
        }

        th {
            text-align: left;
            padding: 14px 16px;
            color: var(--text-muted);
            font-weight: 600;
            border-bottom: 1px solid var(--card-border);
            text-transform: uppercase;
            font-size: 12px;
        }

        td {
            padding: 16px;
            border-bottom: 1px solid var(--card-border);
            color: var(--text-main);
        }

        .font-mono {
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }

        .priority-high {
            color: var(--accent-red);
            background: rgba(255, 82, 82, 0.1);
            padding: 4px 10px;
            border-radius: 6px;
            font-weight: 600;
            display: inline-block;
        }

        .priority-warn {
            color: var(--accent-orange);
            background: rgba(255, 145, 0, 0.1);
            padding: 4px 10px;
            border-radius: 6px;
            font-weight: 600;
            display: inline-block;
        }

        .btn-isolate {
            background: linear-gradient(135deg, #ff5252 0%, #d50000 100%);
            color: white;
            border: none;
            padding: 8px 14px;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 12px rgba(255, 82, 82, 0.3);
        }

        .btn-isolate:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(255, 82, 82, 0.5);
        }

        .remediated-tag {
            color: var(--accent-green);
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        /* AI Markdown Report Styling */
        .ai-report-body { line-height: 1.6; font-size: 14px; color: #e5e7eb; }
        .ai-report-body h1, .ai-report-body h2, .ai-report-body h3 { color: var(--accent-cyan); margin-top: 15px; margin-bottom: 10px; }
        .ai-report-body code { font-family: 'JetBrains Mono', monospace; background: rgba(0, 0, 0, 0.4); padding: 2px 6px; border-radius: 4px; color: var(--accent-orange); }
        .ai-report-body pre { background: rgba(0, 0, 0, 0.5); padding: 12px; border-radius: 8px; overflow-x: auto; border: 1px solid var(--card-border); }
        .ai-report-body ul, .ai-report-body ol { padding-left: 20px; }
    </style>
    <script>
        function remediatePod(podName, alertIndex) {
            if (confirm("SOAR ACTION: Terminate and isolate compromised pod [" + podName + "]?")) {
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
        <div>
            <h1>🛡️ ASTRA-XDR SOC Platform</h1>
            <div style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Extended Detection & Automated Incident Response</div>
        </div>
        <div class="badge-live">
            <span class="dot"></span> LIVE MONITORING
        </div>
    </div>

    <!-- NEW: Dynamic Pod Telemetry Cards -->
    <div class="pod-grid">
        {% for pod in pods %}
        <div class="pod-card">
            <h3>📦 {{ pod.name }}</h3>
            <div class="pod-status status-{{ pod.status|lower }}">{{ pod.status }}</div>
            
            <div class="metric-row">
                <div class="metric-labels">
                    <span>CPU Utilization</span>
                    <span class="metric-val">{{ pod.cpu }} mCPU</span>
                </div>
                <div class="bar-bg">
                    <div class="bar-fill cpu-fill" style="width: {{ pod.cpu_pct }}%;"></div>
                </div>
            </div>

            <div class="metric-row">
                <div class="metric-labels">
                    <span>Memory Utilization</span>
                    <span class="metric-val">{{ pod.mem }} MiB</span>
                </div>
                <div class="bar-bg">
                    <div class="bar-fill mem-fill" style="width: {{ pod.mem_pct }}%;"></div>
                </div>
            </div>
        </div>
        {% else %}
        <div class="pod-card" style="text-align: center; color: var(--text-muted);">
            No active pods detected in the cluster.
        </div>
        {% endfor %}
    </div>

    <!-- Table 1: Runtime Security Incidents -->
    <div class="table-card">
        <h3 style="margin-top:0; margin-bottom: 20px; color: var(--text-main);">Runtime Security Incidents & SOAR Actions</h3>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Priority</th>
                    <th>Target Pod</th>
                    <th>Security Rule & Context Payload</th>
                    <th>SOAR Remediation</th>
                </tr>
            </thead>
            <tbody>
                {% for a in alerts %}
                <tr>
                    <td class="font-mono" style="color: var(--text-muted);">{{ a.time }}</td>
                    <td>
                        <span class="{% if a.priority in ['Critical', 'Error', 'Warning'] %}priority-high{% else %}priority-warn{% endif %}">
                            {{ a.priority }}
                        </span>
                    </td>
                    <td class="font-mono"><strong>{{ a.pod or 'Unknown' }}</strong></td>
                    <td class="font-mono" style="font-size: 12px; color: #d1d5db;">
                        <strong style="color: #fff;">{{ a.rule }}</strong> — {{ a.output }}
                    </td>
                    <td>
                        {% if a.remediated %}
                            <span class="remediated-tag">✅ ISOLATED</span>
                        {% elif a.pod and a.pod != 'Unknown' %}
                            <button class="btn-isolate" onclick="remediatePod('{{ a.pod }}', {{ loop.index0 }})">⚠️ Isolate Pod</button>
                        {% else %}
                            <span style="color: var(--text-muted);">N/A</span>
                        {% endif %}
                    </td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="5" style="text-align: center; padding: 30px; color: var(--text-muted);">
                        No threat vectors detected. Cluster operating in secure state.
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <!-- Section 2: AI DevSecOps Remediation Summary -->
    <div class="table-card">
        <h3 style="margin-top:0; margin-bottom: 15px; color: var(--accent-cyan);">🤖 AI DevSecOps Remediation Summary (CI/CD Scan)</h3>
        {% if ai_report %}
            <div id="ai-report-content" class="ai-report-body"></div>
            <script>
                const rawMarkdown = {{ ai_report | tojson }};
                document.getElementById('ai-report-content').innerHTML = marked.parse(rawMarkdown);
            </script>
        {% else %}
            <p style="color: var(--text-muted); font-size: 14px; margin: 0; padding: 10px 0;">
                No AI remediation scans received yet. Run your GitHub Actions pipeline to populate Trivy, SonarQube, and OWASP ZAP automated analysis.
            </p>
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
