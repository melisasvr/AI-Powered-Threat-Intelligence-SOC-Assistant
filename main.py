"""
AI-Powered Threat Intelligence & SOC Assistant
Main application file with FastAPI backend
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime, timedelta
import uvicorn

from db_manager import DatabaseManager
from log_processor import LogProcessor
from anomaly_detector import AnomalyDetector
from incident_generator import IncidentGenerator

app = FastAPI(title="SOC Assistant", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
db = DatabaseManager("soc_data.db")
log_processor = LogProcessor(db)
anomaly_detector = AnomalyDetector(db)
incident_generator = IncidentGenerator(db)

# Pydantic models
class LogEntry(BaseModel):
    timestamp: str
    ip_address: str
    endpoint: str
    status_code: int
    user_agent: Optional[str] = None
    country: Optional[str] = None
    method: str = "GET"
    response_time: Optional[float] = None

class DetectionRule(BaseModel):
    name: str
    description: str
    condition: str
    severity: str
    enabled: bool = True

class IncidentResponse(BaseModel):
    incident_id: int
    severity: str
    ip_address: str
    anomaly_type: str
    timestamp: str
    description: str
    details: Dict
    ai_summary: Optional[str] = None

# API Endpoints

@app.get("/")
async def root():
    """Dashboard HTML"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SOC Assistant Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 1400px; margin: 0 auto; }
            .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 20px; }
            .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .stat-value { font-size: 2em; font-weight: bold; color: #3498db; }
            .stat-label { color: #7f8c8d; margin-top: 5px; }
            .incidents { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .incident { border-left: 4px solid #e74c3c; padding: 15px; margin-bottom: 15px; background: #fef5f5; }
            .incident.medium { border-color: #f39c12; background: #fef9f3; }
            .incident.low { border-color: #3498db; background: #f3f9fe; }
            .controls { margin-bottom: 20px; }
            button { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin-right: 10px; }
            button:hover { background: #2980b9; }
            .severity-high { color: #e74c3c; font-weight: bold; }
            .severity-medium { color: #f39c12; font-weight: bold; }
            .severity-low { color: #3498db; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ SOC Assistant Dashboard</h1>
                <p>AI-Powered Threat Intelligence & Security Operations Center</p>
            </div>
            
            <div class="controls">
                <button onclick="runDetection()">🔍 Run Anomaly Detection</button>
                <button onclick="loadIncidents()">🔄 Refresh Incidents</button>
                <button onclick="simulateLogs()">📊 Simulate Sample Logs</button>
                <button onclick="exportReport()">📥 Export Report</button>
            </div>
            
            <div class="stats" id="stats">
                <div class="stat-card">
                    <div class="stat-value" id="total-logs">0</div>
                    <div class="stat-label">Total Logs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="total-incidents">0</div>
                    <div class="stat-label">Active Incidents</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="unique-ips">0</div>
                    <div class="stat-label">Unique IPs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="detection-rate">0%</div>
                    <div class="stat-label">Detection Rate</div>
                </div>
            </div>
            
            <div class="incidents">
                <h2>Recent Incidents</h2>
                <div id="incidents-list">Loading...</div>
            </div>
        </div>
        
        <script>
            async function loadStats() {
                const response = await fetch('/api/stats');
                const data = await response.json();
                document.getElementById('total-logs').textContent = data.total_logs;
                document.getElementById('total-incidents').textContent = data.total_incidents;
                document.getElementById('unique-ips').textContent = data.unique_ips;
                document.getElementById('detection-rate').textContent = data.detection_rate + '%';
            }
            
            async function loadIncidents() {
                const response = await fetch('/api/incidents?limit=10');
                const incidents = await response.json();
                const container = document.getElementById('incidents-list');
                
                if (incidents.length === 0) {
                    container.innerHTML = '<p>No incidents detected yet.</p>';
                    return;
                }
                
                container.innerHTML = incidents.map(inc => `
                    <div class="incident ${inc.severity.toLowerCase()}">
                        <h3>
                            <span class="severity-${inc.severity.toLowerCase()}">[${inc.severity}]</span>
                            ${inc.anomaly_type} - ${inc.ip_address}
                        </h3>
                        <p><strong>Time:</strong> ${inc.timestamp}</p>
                        <p><strong>Description:</strong> ${inc.description}</p>
                        ${inc.ai_summary ? `<p><strong>AI Analysis:</strong> ${inc.ai_summary}</p>` : ''}
                    </div>
                `).join('');
            }
            
            async function runDetection() {
                document.querySelector('button').disabled = true;
                document.querySelector('button').textContent = '⏳ Detecting...';
                
                const response = await fetch('/api/detect-anomalies', { method: 'POST' });
                const result = await response.json();
                
                alert(`Detection complete! Found ${result.anomalies_detected} anomalies.`);
                
                document.querySelector('button').disabled = false;
                document.querySelector('button').textContent = '🔍 Run Anomaly Detection';
                
                loadStats();
                loadIncidents();
            }
            
            async function simulateLogs() {
                const response = await fetch('/api/simulate-logs', { method: 'POST' });
                const result = await response.json();
                alert(result.message);
                loadStats();
            }
            
            async function exportReport() {
                window.open('/api/export-report', '_blank');
            }
            
            // Load data on page load
            loadStats();
            loadIncidents();
            
            // Auto-refresh every 30 seconds
            setInterval(() => {
                loadStats();
                loadIncidents();
            }, 30000);
        </script>
    </body>
    </html>
    """)

@app.post("/api/logs/ingest")
async def ingest_log(log: LogEntry, background_tasks: BackgroundTasks):
    """Ingest a single log entry"""
    try:
        log_processor.ingest_log(log.model_dump())
        return {"status": "success", "message": "Log ingested successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/logs/ingest-batch")
async def ingest_logs_batch(logs: List[LogEntry]):
    """Ingest multiple log entries"""
    try:
        count = log_processor.ingest_logs_batch([log.model_dump() for log in logs])
        return {"status": "success", "message": f"{count} logs ingested successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/detect-anomalies")
async def detect_anomalies():
    """Run anomaly detection on recent logs"""
    try:
        anomalies = anomaly_detector.detect_anomalies()
        
        # Generate incidents from anomalies
        incidents_created = 0
        for anomaly in anomalies:
            incident_generator.create_incident(anomaly)
            incidents_created += 1
        
        return {
            "status": "success",
            "anomalies_detected": len(anomalies),
            "incidents_created": incidents_created
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/incidents")
async def get_incidents(
    limit: int = 50,
    severity: Optional[str] = None,
    ip_address: Optional[str] = None
):
    """Get list of incidents with optional filtering"""
    try:
        incidents = db.get_incidents(limit=limit, severity=severity, ip_address=ip_address)
        return incidents
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: int):
    """Get detailed information about a specific incident"""
    try:
        incident = db.get_incident_by_id(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/rules")
async def create_rule(rule: DetectionRule):
    """Create a new detection rule"""
    try:
        rule_id = db.create_rule(rule.model_dump())
        return {"status": "success", "rule_id": rule_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/rules")
async def get_rules():
    """Get all detection rules"""
    try:
        rules = db.get_rules()
        return rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
async def get_stats():
    """Get dashboard statistics"""
    try:
        stats = db.get_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/export-report")
async def export_report():
    """Export incidents as a report"""
    try:
        report = incident_generator.generate_report()
        return {"report": report, "timestamp": datetime.now().isoformat()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/simulate-logs")
async def simulate_logs():
    """Generate simulated log data for testing"""
    try:
        import random
        from datetime import datetime, timedelta
        
        ips = ["192.168.1.100", "10.0.0.50", "172.16.0.200", "203.0.113.45", "198.51.100.78"]
        endpoints = ["/api/login", "/api/data", "/admin/dashboard", "/api/users", "/api/config"]
        countries = ["US", "GB", "DE", "CN", "RU"]
        
        logs = []
        for _ in range(100):
            log = {
                "timestamp": (datetime.now() - timedelta(hours=random.randint(0, 24))).isoformat(),
                "ip_address": random.choice(ips),
                "endpoint": random.choice(endpoints),
                "status_code": random.choice([200, 200, 200, 401, 403, 500]),
                "country": random.choice(countries),
                "method": random.choice(["GET", "POST", "PUT", "DELETE"]),
                "response_time": random.uniform(0.1, 2.0)
            }
            logs.append(log)
        
        count = log_processor.ingest_logs_batch(logs)
        return {"status": "success", "message": f"Generated {count} simulated logs"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🛡️  SOC Assistant Starting...")
    print("="*60)
    print("📊 Dashboard URL: http://localhost:8000")
    print("📡 API Docs: http://localhost:8000/docs")
    print("⚡ Press CTRL+C to stop the server")
    print("="*60 + "\n")
    uvicorn.run(app, host="127.0.0.1", port=8000)