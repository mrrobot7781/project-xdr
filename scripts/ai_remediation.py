import json
import os
import requests
from google import genai
from google.genai import types

def load_json(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"error": f"{filepath} not found"}

def load_text(filepath):
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return f"Error: {filepath} not found"

def generate_ai_summary(trivy_data, sonar_data, zap_data):
    # Initialize the Google Gen AI client
    # The client automatically picks up the GEMINI_API_KEY environment variable
    client = genai.Client()
    
    prompt = f"""
    You are an expert DevSecOps engineer. Review the following security scan results from Trivy, SonarQube, and OWASP ZAP.
    Provide a short, prioritized executive summary of the critical vulnerabilities and write clear, step-by-step remediation instructions for the development team. 
    Format the output in strict Markdown.

    Trivy Data:
    {str(trivy_data)[:1500]}...

    SonarQube Data:
    {str(sonar_data)[:1500]}...

    OWASP ZAP Data:
    {str(zap_data)[:1500]}...
    """

    # Generate the content using the Gemini 3.5 Flash model
    try:
        response = client.models.generate_content(
            model="gemini-3.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2, # Lower temperature for more deterministic/factual output
            )
        )
        return response.text
    except Exception as e:
        return f"## Error generating AI summary\n\n```\n{e}\n```"

def write_to_step_summary(markdown_report):
    # Retrieve the GITHUB_STEP_SUMMARY environment variable
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    
    if not summary_file:
        print("GITHUB_STEP_SUMMARY environment variable not found. Printing to stdout instead.")
        print(markdown_report)
        return

    # Append the markdown report to the GitHub Step Summary file
    with open(summary_file, "a") as f:
        f.write(markdown_report)

def send_to_dashboard(markdown_report):
    # Define your dashboard's webhook URL
    # Replace <EC2_PUBLIC_IP> with the actual IP/domain of your ASTRA-XDR EC2 instance
    webhook_url = "http://18.206.240.100:30081/api/ai-report" 

    # Prepare the JSON payload containing the report
    payload = {
        "event_type": "security_scan_completed",
        "report": markdown_report
    }

    try:
        # Use requests.post to send the JSON payload
        response = requests.post(webhook_url, json=payload, timeout=10)
        
        # Check if the request was successful
        if response.status_code == 200:
            print("Successfully sent report to dashboard!")
        else:
            print(f"Failed to send report. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
         print(f"Error sending webhook: {e}")

if __name__ == "__main__":
    print("Loading scan reports...")
    trivy = load_text('trivy-report.txt') 
    sonar = load_text('sonar-report.json') 
    zap = load_json('report_json.json')
    
    print("Generating AI summary...")
    report = generate_ai_summary(trivy, sonar, zap)
    
    print("Writing to GitHub Step Summary...")
    write_to_step_summary(report)
    
    print("Sending report to dashboard via webhook...")
    send_to_dashboard(report)
    
    print("AI Remediation Report generated successfully.")
