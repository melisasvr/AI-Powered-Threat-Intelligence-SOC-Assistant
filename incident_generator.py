"""
Incident Generator - Creates incidents from anomalies and generates AI summaries
"""

from datetime import datetime
from typing import Dict, List

class IncidentGenerator:
    def __init__(self, db_manager):
        self.db = db_manager
    
    def create_incident(self, anomaly: Dict) -> int:
        """Create an incident from an anomaly"""
        
        # Generate description
        description = self._generate_description(anomaly)
        
        # Generate AI summary (placeholder for LLM integration)
        ai_summary = self._generate_ai_summary(anomaly)
        
        incident_data = {
            'severity': anomaly['severity'],
            'ip_address': anomaly['ip_address'],
            'anomaly_type': anomaly['anomaly_type'],
            'timestamp': anomaly['timestamp'],
            'description': description,
            'details': anomaly.get('details', {}),
            'ai_summary': ai_summary
        }
        
        return self.db.insert_incident(incident_data)
    
    def _generate_description(self, anomaly: Dict) -> str:
        """Generate human-readable description"""
        anom_type = anomaly['anomaly_type']
        ip = anomaly['ip_address']
        details = anomaly.get('details', {})
        
        if anom_type == 'High Error Rate':
            return f"IP {ip} is experiencing an unusually high error rate of {details.get('error_rate', 0):.1%}, significantly above the expected rate of {details.get('expected_error_rate', 0):.1%}."
        
        elif anom_type == 'Unusual Request Volume':
            return f"IP {ip} generated {details.get('request_count', 0)} requests, which is {details.get('z_score', 0):.1f} standard deviations above normal."
        
        elif anom_type == 'Multiple Country Access':
            countries = ', '.join(details.get('countries', []))
            return f"IP {ip} accessed the system from {details.get('country_count', 0)} different countries: {countries}. This may indicate credential sharing or compromise."
        
        elif anom_type == 'Sensitive Endpoint Access':
            endpoints = ', '.join(details.get('sensitive_endpoints', []))
            return f"IP {ip} accessed {len(details.get('sensitive_endpoints', []))} sensitive endpoints: {endpoints}."
        
        elif anom_type == 'Off-Hours Activity':
            return f"IP {ip} showed unusual off-hours activity with {details.get('percentage', 0)}% of requests occurring between 2-6 AM."
        
        return f"Anomaly detected for IP {ip}: {anom_type}"
    
    def _generate_ai_summary(self, anomaly: Dict) -> str:
        """Generate AI-powered summary and recommendations"""
        # This is a placeholder. In production, you would call an LLM API here
        # For example: OpenAI, Anthropic Claude, or a local model
        
        anom_type = anomaly['anomaly_type']
        severity = anomaly['severity']
        
        summaries = {
            'High Error Rate': {
                'HIGH': "CRITICAL: Potential brute-force attack or system misconfiguration. Recommended actions: (1) Temporarily block IP, (2) Review authentication logs, (3) Implement rate limiting, (4) Alert security team immediately.",
                'MEDIUM': "WARNING: Elevated error rates detected. Recommended actions: (1) Monitor IP activity closely, (2) Check for application errors, (3) Review recent configuration changes.",
                'LOW': "INFO: Slight increase in error rate. Recommended actions: (1) Continue monitoring, (2) Document pattern for trend analysis."
            },
            'Unusual Request Volume': {
                'HIGH': "CRITICAL: Possible DDoS attack or aggressive scraping. Recommended actions: (1) Implement rate limiting immediately, (2) Consider temporary IP block, (3) Analyze traffic patterns, (4) Check system resources.",
                'MEDIUM': "WARNING: Unusual traffic spike detected. Recommended actions: (1) Verify legitimate use case, (2) Monitor resource utilization, (3) Consider rate limiting.",
                'LOW': "INFO: Moderate traffic increase. Recommended actions: (1) Document pattern, (2) Continue observation."
            },
            'Multiple Country Access': {
                'HIGH': "CRITICAL: Likely account compromise or credential sharing. Recommended actions: (1) Force password reset, (2) Enable MFA if not active, (3) Review access logs, (4) Contact account owner.",
                'MEDIUM': "WARNING: Suspicious geographic pattern. Recommended actions: (1) Verify with account owner, (2) Enable additional authentication, (3) Monitor for other anomalies.",
                'LOW': "INFO: Multiple geographic locations detected. Recommended actions: (1) Verify if VPN or legitimate travel, (2) Document pattern."
            },
            'Sensitive Endpoint Access': {
                'HIGH': "CRITICAL: Unauthorized admin panel access attempt. Recommended actions: (1) Block IP immediately, (2) Audit admin accounts, (3) Review access controls, (4) Check for data exfiltration.",
                'MEDIUM': "WARNING: Access to sensitive endpoints. Recommended actions: (1) Verify authorization level, (2) Review audit logs, (3) Enhance monitoring.",
                'LOW': "INFO: Sensitive endpoint access logged. Recommended actions: (1) Verify legitimate access, (2) Maintain audit trail."
            },
            'Off-Hours Activity': {
                'HIGH': "CRITICAL: Significant off-hours activity suggesting automated attack or insider threat. Recommended actions: (1) Investigate immediately, (2) Review all actions taken, (3) Check for data access.",
                'MEDIUM': "WARNING: Unusual activity timing. Recommended actions: (1) Verify with account owner, (2) Check for automation, (3) Review activity logs.",
                'LOW': "INFO: Off-hours access detected. Recommended actions: (1) Document pattern, (2) Verify work schedule."
            }
        }
        
        return summaries.get(anom_type, {}).get(severity, "Anomaly detected. Review and investigate as appropriate.")
    
    def generate_report(self, time_range_hours: int = 24) -> str:
        """Generate a comprehensive incident report"""
        incidents = self.db.get_incidents(limit=100)
        
        if not incidents:
            return "No incidents to report."
        
        # Group by severity
        high = [i for i in incidents if i['severity'] == 'HIGH']
        medium = [i for i in incidents if i['severity'] == 'MEDIUM']
        low = [i for i in incidents if i['severity'] == 'LOW']
        
        report = f"""
SECURITY INCIDENT REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Time Range: Last {time_range_hours} hours
{'=' * 60}

EXECUTIVE SUMMARY
Total Incidents: {len(incidents)}
  • Critical (HIGH):  {len(high)}
  • Warning (MEDIUM): {len(medium)}
  • Info (LOW):       {len(low)}

{'=' * 60}

CRITICAL INCIDENTS (HIGH PRIORITY)
"""
        
        for idx, incident in enumerate(high[:5], 1):
            report += f"""
{idx}. {incident['anomaly_type']} - {incident['ip_address']}
   Time: {incident['timestamp']}
   Description: {incident['description']}
   Recommendation: {incident['ai_summary']}
"""
        
        report += f"""
{'=' * 60}

WARNING INCIDENTS (MEDIUM PRIORITY)
"""
        
        for idx, incident in enumerate(medium[:5], 1):
            report += f"""
{idx}. {incident['anomaly_type']} - {incident['ip_address']}
   Time: {incident['timestamp']}
   Description: {incident['description']}
"""
        
        report += f"""
{'=' * 60}

RECOMMENDATIONS
1. Review and triage all HIGH severity incidents immediately
2. Implement recommended mitigations for critical findings
3. Monitor flagged IPs for continued suspicious activity
4. Update detection rules based on findings
5. Schedule security team review for patterns

{'=' * 60}
End of Report
"""
        
        return report
    
    def suggest_mitigation(self, incident_id: int) -> Dict:
        """Suggest mitigation strategies for an incident"""
        incident = self.db.get_incident_by_id(incident_id)
        
        if not incident:
            return {"error": "Incident not found"}
        
        # Generate mitigation suggestions based on anomaly type
        mitigations = {
            'High Error Rate': [
                "Implement rate limiting for this IP",
                "Temporarily block IP if attack is confirmed",
                "Review authentication mechanisms",
                "Enable CAPTCHA for failed login attempts"
            ],
            'Unusual Request Volume': [
                "Apply rate limiting rules",
                "Add IP to watchlist",
                "Verify traffic legitimacy",
                "Consider CDN/DDoS protection"
            ],
            'Multiple Country Access': [
                "Force password reset",
                "Enable multi-factor authentication",
                "Review recent account activity",
                "Notify account owner"
            ],
            'Sensitive Endpoint Access': [
                "Block IP immediately",
                "Audit access controls",
                "Review logs for data exfiltration",
                "Enable additional authentication for admin endpoints"
            ],
            'Off-Hours Activity': [
                "Verify with account owner",
                "Review all actions taken during off-hours",
                "Implement time-based access controls",
                "Enable alerts for off-hours access"
            ]
        }
        
        return {
            'incident_id': incident_id,
            'anomaly_type': incident['anomaly_type'],
            'suggested_actions': mitigations.get(incident['anomaly_type'], ["Review and investigate"])
        }