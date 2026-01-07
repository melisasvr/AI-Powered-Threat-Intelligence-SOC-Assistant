"""
Database Manager - Handles SQLite database operations
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional

class DatabaseManager:
    def __init__(self, db_path: str = "soc_data.db"):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_database(self):
        """Initialize database schema"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                status_code INTEGER,
                user_agent TEXT,
                country TEXT,
                method TEXT,
                response_time REAL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Aggregated features table (for anomaly detection)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_features (
                ip_address TEXT PRIMARY KEY,
                request_count INTEGER,
                unique_endpoints INTEGER,
                error_rate REAL,
                avg_response_time REAL,
                countries TEXT,
                first_seen TEXT,
                last_seen TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Incidents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                severity TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                anomaly_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                description TEXT,
                details TEXT,
                ai_summary TEXT,
                status TEXT DEFAULT 'open',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Detection rules table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                condition TEXT NOT NULL,
                severity TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)")
        
        conn.commit()
        conn.close()
    
    def insert_log(self, log_data: Dict):
        """Insert a single log entry"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO logs (timestamp, ip_address, endpoint, status_code, 
                            user_agent, country, method, response_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log_data.get('timestamp'),
            log_data.get('ip_address'),
            log_data.get('endpoint'),
            log_data.get('status_code'),
            log_data.get('user_agent'),
            log_data.get('country'),
            log_data.get('method'),
            log_data.get('response_time')
        ))
        
        conn.commit()
        log_id = cursor.lastrowid
        conn.close()
        return log_id
    
    def insert_logs_batch(self, logs: List[Dict]):
        """Insert multiple log entries"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        log_tuples = [
            (
                log.get('timestamp'),
                log.get('ip_address'),
                log.get('endpoint'),
                log.get('status_code'),
                log.get('user_agent'),
                log.get('country'),
                log.get('method'),
                log.get('response_time')
            )
            for log in logs
        ]
        
        cursor.executemany("""
            INSERT INTO logs (timestamp, ip_address, endpoint, status_code, 
                            user_agent, country, method, response_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, log_tuples)
        
        conn.commit()
        count = cursor.rowcount
        conn.close()
        return count
    
    def get_logs(self, limit: int = 100, ip_address: Optional[str] = None):
        """Retrieve logs with optional filtering"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = "SELECT * FROM logs"
        params = []
        
        if ip_address:
            query += " WHERE ip_address = ?"
            params.append(ip_address)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return logs
    
    def update_ip_features(self, ip_address: str, features: Dict):
        """Update aggregated features for an IP"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO ip_features 
            (ip_address, request_count, unique_endpoints, error_rate, 
             avg_response_time, countries, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip_address,
            features.get('request_count'),
            features.get('unique_endpoints'),
            features.get('error_rate'),
            features.get('avg_response_time'),
            json.dumps(features.get('countries', [])),
            features.get('first_seen'),
            features.get('last_seen')
        ))
        
        conn.commit()
        conn.close()
    
    def get_ip_features(self, ip_address: Optional[str] = None):
        """Get IP feature data"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if ip_address:
            cursor.execute("SELECT * FROM ip_features WHERE ip_address = ?", (ip_address,))
            result = cursor.fetchone()
            conn.close()
            return dict(result) if result else None
        else:
            cursor.execute("SELECT * FROM ip_features")
            features = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return features
    
    def insert_incident(self, incident_data: Dict):
        """Create a new incident"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO incidents (severity, ip_address, anomaly_type, 
                                 timestamp, description, details, ai_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            incident_data.get('severity'),
            incident_data.get('ip_address'),
            incident_data.get('anomaly_type'),
            incident_data.get('timestamp'),
            incident_data.get('description'),
            json.dumps(incident_data.get('details', {})),
            incident_data.get('ai_summary')
        ))
        
        conn.commit()
        incident_id = cursor.lastrowid
        conn.close()
        return incident_id
    
    def get_incidents(self, limit: int = 50, severity: Optional[str] = None, 
                     ip_address: Optional[str] = None):
        """Get incidents with optional filtering"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if ip_address:
            query += " AND ip_address = ?"
            params.append(ip_address)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        incidents = []
        for row in cursor.fetchall():
            incident = dict(row)
            incident['details'] = json.loads(incident['details'])
            incidents.append(incident)
        
        conn.close()
        return incidents
    
    def get_incident_by_id(self, incident_id: int):
        """Get a specific incident"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()
        
        if row:
            incident = dict(row)
            incident['details'] = json.loads(incident['details'])
            conn.close()
            return incident
        
        conn.close()
        return None
    
    def create_rule(self, rule_data: Dict):
        """Create a detection rule"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO rules (name, description, condition, severity, enabled)
            VALUES (?, ?, ?, ?, ?)
        """, (
            rule_data.get('name'),
            rule_data.get('description'),
            rule_data.get('condition'),
            rule_data.get('severity'),
            1 if rule_data.get('enabled', True) else 0
        ))
        
        conn.commit()
        rule_id = cursor.lastrowid
        conn.close()
        return rule_id
    
    def get_rules(self):
        """Get all detection rules"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM rules ORDER BY created_at DESC")
        rules = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rules
    
    def get_statistics(self):
        """Get dashboard statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Total logs
        cursor.execute("SELECT COUNT(*) as count FROM logs")
        total_logs = cursor.fetchone()['count']
        
        # Total incidents
        cursor.execute("SELECT COUNT(*) as count FROM incidents WHERE status = 'open'")
        total_incidents = cursor.fetchone()['count']
        
        # Unique IPs
        cursor.execute("SELECT COUNT(DISTINCT ip_address) as count FROM logs")
        unique_ips = cursor.fetchone()['count']
        
        # Detection rate
        cursor.execute("SELECT COUNT(DISTINCT ip_address) as count FROM incidents")
        flagged_ips = cursor.fetchone()['count']
        detection_rate = round((flagged_ips / unique_ips * 100) if unique_ips > 0 else 0, 1)
        
        conn.close()
        
        return {
            "total_logs": total_logs,
            "total_incidents": total_incidents,
            "unique_ips": unique_ips,
            "detection_rate": detection_rate
        }