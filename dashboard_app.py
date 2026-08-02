from flask import Flask, request, jsonify, render_template_string, Response
from kubernetes import client, config
import datetime
from functools import wraps

app = Flask(__name__)
alerts = []
latest_ai_report = None

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

try:
    config.load_incluster_config()
    k8s_v1 = client.CoreV1Api()
    k8s_custom = client.CustomObjectsApi()
    k8s_enabled = True
except Exception as e:
    print(f"[ASTRA-XDR] K8s Config issue: {e}")
    k8s_enabled = False

def get_pod_metrics():
    if not k8s_enabled:
        return []
    
    pod_data = []
    try:
        pods = k8s_v1.list_namespaced_pod(namespace="default")
        
        metrics_dict = {}
        try:
            pod_metrics = k8s_custom.list_namespaced_custom_object(
                group="metrics.k8s.io", version="v1beta1", namespace="default", plural="pods"
            )
            for m in pod_metrics.get('items', []):
                metrics_dict[m['metadata']['name']] = m
        except Exception:
            pass

        for pod in pods.items:
            pod_name = pod.metadata.name
            status = pod.status.phase
            cpu_val = 0
            mem_val = 0
            
            if pod_name in metrics_dict:
                for container in metrics_dict[pod_name]['containers']:
                    cpu_str = container['usage']['cpu']
                    mem_str = container['usage']['memory']
                    
                    if cpu_str.endswith('n'):
                        cpu_val += int(cpu_str[:-1]) // 1000000
                    elif cpu_str.endswith('m'):
                        cpu_val += int(cpu_str[:-1])
                    
                    if mem_str.endswith('Ki'):
                        mem_val += int(mem_str[:-2]) // 1024
                    elif mem_str.endswith('Mi'):
                        mem_val += int(mem_str[:-2])

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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASTRA-XDR | SOC Threat Center</title>
    <meta http-equiv="refresh" content="10">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg-dark: #0d1117;
            --bg-darker: #010409;
            --surface: #161b22;
            --surface-light: #21262d;
            --border: #30363d;
            --border-light: #444c56;
            
            --brand-primary: #58a6ff;
            --brand-secondary: #1f6feb;
            --success: #3fb950;
            --danger: #da3633;
            --warning: #d29922;
            --info: #58a6ff;
            
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --text-tertiary: #6e7681;
        }

        html {
            font-size: 16px;
        }

        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, var(--bg-darker) 0%, var(--bg-dark) 100%);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }

        /* Utilities */
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 1rem;
        }

        @media (min-width: 768px) {
            .container {
                padding: 2rem;
            }
        }

        @media (min-width: 1024px) {
            .container {
                padding: 2.5rem;
            }
        }

        /* Header */
        .header {
            margin-bottom: 2rem;
        }

        .header__top {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        @media (min-width: 768px) {
            .header__top {
                flex-direction: row;
                justify-content: space-between;
                align-items: flex-start;
                gap: 2rem;
            }
        }

        .header__title {
            flex: 1;
        }

        .header__title h1 {
            font-size: 1.75rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #58a6ff 0%, #1f6feb 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        @media (min-width: 768px) {
            .header__title h1 {
                font-size: 2.5rem;
            }
        }

        .header__subtitle {
            font-size: 0.875rem;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .header__stats {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
        }

        @media (min-width: 768px) {
            .header__stats {
                grid-template-columns: auto auto;
                gap: 2rem;
                flex-shrink: 0;
            }
        }

        .stat-box {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.25rem;
            text-align: center;
            transition: all 0.3s ease;
        }

        .stat-box:hover {
            border-color: var(--brand-primary);
            box-shadow: 0 0 20px rgba(88, 166, 255, 0.15);
        }

        .stat-label {
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.5px;
            margin-bottom: 0.5rem;
        }

        .stat-value {
            font-size: 1.75rem;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--success);
            animation: pulse 2s infinite;
            box-shadow: 0 0 8px var(--success);
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .stat-value.critical { color: var(--danger); }
        .stat-value.warning { color: var(--warning); }
        .stat-value.success { color: var(--success); }

        /* Section Title */
        .section-title {
            font-size: 1.25rem;
            font-weight: 700;
            margin: 2rem 0 1.5rem 0;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        @media (min-width: 768px) {
            .section-title {
                font-size: 1.5rem;
                margin-top: 2.5rem;
                margin-bottom: 1.75rem;
            }
        }

        /* Pod Grid */
        .pod-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 1.25rem;
            margin-bottom: 2rem;
        }

        @media (min-width: 640px) {
            .pod-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (min-width: 1024px) {
            .pod-grid {
                grid-template-columns: repeat(3, 1fr);
            }
        }

        @media (min-width: 1400px) {
            .pod-grid {
                grid-template-columns: repeat(4, 1fr);
            }
        }

        /* Card */
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            transition: all 0.3s ease;
        }

        .card:hover {
            border-color: var(--border-light);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }

        /* Pod Card */
        .pod-card__header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }

        .pod-card__name {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--brand-primary);
            word-break: break-all;
            flex: 1;
            min-width: 0;
        }

        .pod-card__status {
            display: inline-block;
            padding: 0.375rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }

        .pod-card__status.running {
            background: rgba(63, 185, 80, 0.15);
            color: var(--success);
            border: 1px solid rgba(63, 185, 80, 0.3);
        }

        .pod-card__status.pending {
            background: rgba(210, 153, 34, 0.15);
            color: var(--warning);
            border: 1px solid rgba(210, 153, 34, 0.3);
        }

        .pod-card__status.error {
            background: rgba(218, 54, 51, 0.15);
            color: var(--danger);
            border: 1px solid rgba(218, 54, 51, 0.3);
        }

        .metric {
            margin-bottom: 1.5rem;
        }

        .metric:last-child {
            margin-bottom: 0;
        }

        .metric__header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .metric__label {
            font-size: 0.875rem;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .metric__value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--brand-primary);
        }

        .metric__bar {
            width: 100%;
            height: 6px;
            background: var(--border);
            border-radius: 6px;
            overflow: hidden;
        }

        .metric__fill {
            height: 100%;
            border-radius: 6px;
            transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .metric__fill.cpu {
            background: linear-gradient(90deg, #3fb950, #1f6feb);
        }

        .metric__fill.memory {
            background: linear-gradient(90deg, #58a6ff, #da3633);
        }

        /* Table */
        .table-wrapper {
            overflow-x: auto;
            margin-bottom: 2rem;
        }

        .card-table {
            padding: 1.5rem;
        }

        .card-table h3 {
            font-size: 1.125rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            color: var(--text-primary);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }

        thead {
            background: var(--surface-light);
            border-bottom: 2px solid var(--border);
        }

        th {
            text-align: left;
            padding: 1rem;
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
        }

        td {
            padding: 1rem;
            border-bottom: 1px solid var(--border);
            color: var(--text-primary);
        }

        tbody tr:hover {
            background: rgba(88, 166, 255, 0.05);
        }

        .cell-time {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--text-secondary);
        }

        .cell-priority {
            display: inline-block;
        }

        .priority-badge {
            display: inline-block;
            padding: 0.375rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .priority-badge.critical {
            background: rgba(218, 54, 51, 0.15);
            color: var(--danger);
            border: 1px solid rgba(218, 54, 51, 0.3);
        }

        .priority-badge.warning {
            background: rgba(210, 153, 34, 0.15);
            color: var(--warning);
            border: 1px solid rgba(210, 153, 34, 0.3);
        }

        .priority-badge.notice {
            background: rgba(88, 166, 255, 0.15);
            color: var(--brand-primary);
            border: 1px solid rgba(88, 166, 255, 0.3);
        }

        .cell-pod {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: var(--brand-primary);
            font-weight: 600;
        }

        .cell-rule {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }

        .rule-name {
            color: var(--text-primary);
            font-weight: 600;
            display: block;
            margin-bottom: 0.25rem;
        }

        .cell-action {
            text-align: center;
        }

        .btn-isolate {
            background: linear-gradient(135deg, var(--danger), #9e2c2c);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
            cursor: pointer;
            transition: all 0.2s ease;
            letter-spacing: 0.5px;
        }

        .btn-isolate:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(218, 54, 51, 0.3);
        }

        .btn-isolate:active {
            transform: translateY(0);
        }

        .isolated-tag {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--success);
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .checkmark {
            width: 16px;
            height: 16px;
            background: var(--success);
            border-radius: 3px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--bg-dark);
            font-size: 0.75rem;
            font-weight: 700;
        }

        .empty-state {
            text-align: center;
            padding: 2rem 1rem;
            color: var(--text-secondary);
        }

        .empty-state__icon {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            display: block;
            animation: float 3s ease-in-out infinite;
        }

        .empty-state__text {
            font-size: 0.95rem;
            margin: 0;
        }

        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }

        /* AI Report */
        .ai-report {
            line-height: 1.8;
            font-size: 0.95rem;
            color: var(--text-primary);
        }

        .ai-report h1 {
            font-size: 1.5rem;
            color: var(--brand-primary);
            margin: 1.5rem 0 1rem 0;
            font-weight: 700;
        }

        .ai-report h2 {
            font-size: 1.25rem;
            color: var(--brand-primary);
            margin: 1.25rem 0 0.75rem 0;
            font-weight: 700;
        }

        .ai-report h3 {
            font-size: 1.1rem;
            color: var(--brand-primary);
            margin: 1rem 0 0.5rem 0;
            font-weight: 700;
        }

        .ai-report code {
            font-family: 'JetBrains Mono', monospace;
            background: var(--surface-light);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            color: var(--brand-primary);
            font-size: 0.85rem;
        }

        .ai-report pre {
            background: var(--surface-light);
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            border: 1px solid var(--border);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: var(--success);
            line-height: 1.5;
        }

        .ai-report ul,
        .ai-report ol {
            padding-left: 1.5rem;
            margin: 0.75rem 0;
        }

        .ai-report li {
            margin-bottom: 0.5rem;
        }

        .ai-report p {
            margin: 0.75rem 0;
        }

        /* Responsive Table */
        @media (max-width: 768px) {
            table {
                font-size: 0.75rem;
            }

            th, td {
                padding: 0.75rem;
            }

            .btn-isolate {
                padding: 0.375rem 0.75rem;
                font-size: 0.7rem;
            }

            .cell-rule {
                max-width: 150px;
                word-break: break-word;
            }
        }

        /* No pods state */
        .pod-grid.empty {
            grid-template-columns: 1fr;
        }

        /* Spacing adjustments */
        .no-bottom-margin {
            margin-bottom: 0;
        }
    </style>
    <script>
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
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="header__top">
                <div class="header__title">
                    <h1>🛡️ ASTRA-XDR</h1>
                    <p class="header__subtitle">Extended Detection & Response | Real-Time Security Operations</p>
                </div>
                <div class="header__stats">
                    {% set threat_level = 'critical' if alerts | length > 10 else 'warning' if alerts | length > 5 else 'success' %}
                    <div class="stat-box">
                        <div class="stat-label">Threat Level</div>
                        <div class="stat-value {{ threat_level }}">
                            {% if threat_level == 'critical' %}🔴 CRITICAL
                            {% elif threat_level == 'warning' %}🟠 HIGH
                            {% else %}🟢 LOW
                            {% endif %}
                        </div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-label">System Status</div>
                        <div class="stat-value">
                            <span class="status-dot"></span>
                            <span>LIVE</span>
                        </div>
                    </div>
                </div>
            </div>
        </header>

        <!-- Cluster Health Section -->
        <section>
            <h2 class="section-title">📦 Cluster Health</h2>
            <div class="pod-grid {% if not pods %}empty{% endif %}">
                {% for pod in pods %}
                <div class="card">
                    <div class="pod-card__header">
                        <div class="pod-card__name">{{ pod.name }}</div>
                        <div class="pod-card__status {{ pod.status|lower }}">{{ pod.status }}</div>
                    </div>
                    
                    <div class="metric">
                        <div class="metric__header">
                            <span class="metric__label">CPU Utilization</span>
                            <span class="metric__value">{{ pod.cpu }} mC</span>
                        </div>
                        <div class="metric__bar">
                            <div class="metric__fill cpu" style="width: {{ pod.cpu_pct }}%"></div>
                        </div>
                    </div>

                    <div class="metric">
                        <div class="metric__header">
                            <span class="metric__label">Memory Usage</span>
                            <span class="metric__value">{{ pod.mem }} MB</span>
                        </div>
                        <div class="metric__bar">
                            <div class="metric__fill memory" style="width: {{ pod.mem_pct }}%"></div>
                        </div>
                    </div>
                </div>
                {% else %}
                <div class="card empty">
                    <div class="empty-state">
                        <span class="empty-state__icon">📭</span>
                        <p class="empty-state__text">No active pods in cluster</p>
                    </div>
                </div>
                {% endfor %}
            </div>
        </section>

        <!-- Security Incidents Section -->
        <section>
            <h2 class="section-title">⚠️ Runtime Security Events</h2>
            <div class="table-wrapper">
                <div class="card card-table">
                    <h3>Detected Anomalies & Remediation Actions</h3>
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 15%;">Timestamp</th>
                                <th style="width: 10%;">Priority</th>
                                <th style="width: 15%;">Target Pod</th>
                                <th style="width: 40%;">Rule & Context</th>
                                <th style="width: 20%;">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for a in alerts %}
                            <tr>
                                <td class="cell-time">{{ a.time }}</td>
                                <td class="cell-priority">
                                    <span class="priority-badge {% if a.priority == 'Critical' or a.priority == 'Error' %}critical{% elif a.priority == 'Warning' %}warning{% else %}notice{% endif %}">
                                        {{ a.priority }}
                                    </span>
                                </td>
                                <td class="cell-pod">{{ a.pod or '—' }}</td>
                                <td class="cell-rule">
                                    <span class="rule-name">{{ a.rule }}</span>
                                    {{ a.output }}
                                </td>
                                <td class="cell-action">
                                    {% if a.remediated %}
                                        <span class="isolated-tag">
                                            <span class="checkmark">✓</span>
                                            ISOLATED
                                        </span>
                                    {% elif a.pod and a.pod != 'Unknown' %}
                                        <button class="btn-isolate" onclick="remediatePod('{{ a.pod }}', {{ loop.index0 }})">Isolate</button>
                                    {% else %}
                                        <span style="color: var(--text-tertiary); font-size: 0.75rem;">N/A</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% else %}
                            <tr>
                                <td colspan="5">
                                    <div class="empty-state">
                                        <span class="empty-state__icon">✓</span>
                                        <p class="empty-state__text">No threats detected. Cluster in secure state.</p>
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- AI Analysis Section -->
        <section>
            <h2 class="section-title">🤖 AI Security Analysis</h2>
            <div class="card card-table">
                <h3>Automated DevSecOps Scan Results</h3>
                {% if ai_report %}
                    <div id="ai-report-content" class="ai-report"></div>
                    <script>
                        const rawMarkdown = {{ ai_report | tojson }};
                        document.getElementById('ai-report-content').innerHTML = marked.parse(rawMarkdown);
                    </script>
                {% else %}
                    <div class="empty-state">
                        <span class="empty-state__icon">📊</span>
                        <p class="empty-state__text">No scan reports received. Integrate Trivy, SonarQube, OWASP ZAP via CI/CD pipeline.</p>
                    </div>
                {% endif %}
            </div>
        </section>
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
