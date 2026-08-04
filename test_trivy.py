import json

with open('trivy-results.json', 'r') as f:
    data = json.load(f)

for result in data.get('Results', []):
    vulns = result.get('Vulnerabilities', [])
    print(f"Target: {result.get('Target')}")
    print(f"Total Vulns: {len(vulns)}")
    if vulns:
        print(f"First Vuln ID: {vulns[0].get('VulnerabilityID')}")
    print("-" * 20)
