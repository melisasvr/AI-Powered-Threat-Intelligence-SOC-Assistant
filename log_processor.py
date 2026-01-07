"""
Log Processor - Ingests and aggregates log data
"""

from datetime import datetime
from typing import Dict, List
from collections import defaultdict
import json

class LogProcessor:
    def __init__(self, db_manager):
        self.db = db_manager
    
    def ingest_log(self, log_data: Dict):
        """Ingest a single log entry and update aggregated features"""
        # Insert log
        log_id = self.db.insert_log(log_data)
        
        # Update IP features
        self.update_ip_features(log_data['ip_address'])
        
        return log_id
    
    def ingest_logs_batch(self, logs: List[Dict]):
        """Ingest multiple logs and update features"""
        # Insert all logs
        count = self.db.insert_logs_batch(logs)
        
        # Update features for all affected IPs
        unique_ips = set(log['ip_address'] for log in logs)
        for ip in unique_ips:
            self.update_ip_features(ip)
        
        return count
    
    def update_ip_features(self, ip_address: str):
        """Calculate and update aggregated features for an IP"""
        # Get all logs for this IP
        logs = self.db.get_logs(limit=10000, ip_address=ip_address)
        
        if not logs:
            return
        
        # Calculate features
        request_count = len(logs)
        unique_endpoints = len(set(log['endpoint'] for log in logs))
        
        # Error rate
        error_count = sum(1 for log in logs if log['status_code'] >= 400)
        error_rate = error_count / request_count if request_count > 0 else 0
        
        # Average response time
        response_times = [log['response_time'] for log in logs if log['response_time']]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Countries
        countries = list(set(log['country'] for log in logs if log['country']))
        
        # Time range
        timestamps = [log['timestamp'] for log in logs]
        first_seen = min(timestamps)
        last_seen = max(timestamps)
        
        features = {
            'request_count': request_count,
            'unique_endpoints': unique_endpoints,
            'error_rate': error_rate,
            'avg_response_time': avg_response_time,
            'countries': countries,
            'first_seen': first_seen,
            'last_seen': last_seen
        }
        
        self.db.update_ip_features(ip_address, features)
    
    def get_session_features(self, time_window_hours: int = 24):
        """Get session-based features for all IPs in a time window"""
        # This would analyze logs within a specific time window
        # For now, return all IP features
        return self.db.get_ip_features()
    
    def featurize_ip(self, ip_address: str) -> Dict:
        """Get feature vector for a specific IP"""
        features = self.db.get_ip_features(ip_address)
        
        if not features:
            return {}
        
        # Parse countries if stored as JSON string
        countries = features.get('countries', [])
        if isinstance(countries, str):
            try:
                countries = json.loads(countries)
            except:
                countries = []
        
        # Convert to numerical features for ML
        return {
            'request_count': features['request_count'],
            'unique_endpoints': features['unique_endpoints'],
            'error_rate': features['error_rate'],
            'avg_response_time': features['avg_response_time'],
            'country_count': len(countries) if countries else 0
        }
    
    def get_ip_timeline(self, ip_address: str) -> List[Dict]:
        """Get chronological timeline of activity for an IP"""
        logs = self.db.get_logs(limit=1000, ip_address=ip_address)
        
        timeline = []
        for log in logs:
            timeline.append({
                'timestamp': log['timestamp'],
                'endpoint': log['endpoint'],
                'status_code': log['status_code'],
                'method': log['method'],
                'country': log.get('country', 'Unknown')
            })
        
        return sorted(timeline, key=lambda x: x['timestamp'])
    
    def analyze_endpoint_patterns(self, ip_address: str) -> Dict:
        """Analyze endpoint access patterns for an IP"""
        logs = self.db.get_logs(limit=1000, ip_address=ip_address)
        
        endpoint_counts = defaultdict(int)
        endpoint_errors = defaultdict(int)
        
        for log in logs:
            endpoint = log['endpoint']
            endpoint_counts[endpoint] += 1
            if log['status_code'] >= 400:
                endpoint_errors[endpoint] += 1
        
        # Find most accessed endpoints
        most_accessed = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Find endpoints with most errors
        most_errors = sorted(endpoint_errors.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'total_unique_endpoints': len(endpoint_counts),
            'most_accessed': [{'endpoint': ep, 'count': count} for ep, count in most_accessed],
            'most_errors': [{'endpoint': ep, 'errors': count} for ep, count in most_errors]
        }
    
    def get_temporal_distribution(self, ip_address: str) -> Dict:
        """Analyze temporal patterns of requests"""
        logs = self.db.get_logs(limit=1000, ip_address=ip_address)
        
        hour_distribution = defaultdict(int)
        day_distribution = defaultdict(int)
        
        for log in logs:
            try:
                timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                hour_distribution[timestamp.hour] += 1
                day_distribution[timestamp.strftime('%A')] += 1
            except:
                continue
        
        return {
            'hour_distribution': dict(hour_distribution),
            'day_distribution': dict(day_distribution),
            'peak_hour': max(hour_distribution.items(), key=lambda x: x[1])[0] if hour_distribution else None,
            'peak_day': max(day_distribution.items(), key=lambda x: x[1])[0] if day_distribution else None
        }
    
    def calculate_request_rate(self, ip_address: str, minutes: int = 60) -> float:
        """Calculate requests per minute for an IP"""
        logs = self.db.get_logs(limit=1000, ip_address=ip_address)
        
        if not logs:
            return 0.0
        
        try:
            # Get time range
            timestamps = [datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00')) for log in logs]
            earliest = min(timestamps)
            latest = max(timestamps)
            
            time_span_minutes = (latest - earliest).total_seconds() / 60
            
            if time_span_minutes < 1:
                return len(logs)  # All requests within a minute
            
            return len(logs) / time_span_minutes
        except:
            return 0.0
    
    def detect_burst_patterns(self, ip_address: str) -> List[Dict]:
        """Detect sudden bursts of activity"""
        logs = self.db.get_logs(limit=1000, ip_address=ip_address)
        
        if len(logs) < 10:
            return []
        
        # Group logs by minute
        minute_counts = defaultdict(int)
        
        for log in logs:
            try:
                timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                minute_key = timestamp.strftime('%Y-%m-%d %H:%M')
                minute_counts[minute_key] += 1
            except:
                continue
        
        # Calculate average and detect bursts
        counts = list(minute_counts.values())
        if not counts:
            return []
        
        avg_per_minute = sum(counts) / len(counts)
        std_dev = (sum((x - avg_per_minute) ** 2 for x in counts) / len(counts)) ** 0.5
        
        bursts = []
        for minute, count in minute_counts.items():
            if std_dev > 0 and count > avg_per_minute + 2 * std_dev:
                bursts.append({
                    'timestamp': minute,
                    'request_count': count,
                    'average': round(avg_per_minute, 2),
                    'deviation': round((count - avg_per_minute) / std_dev, 2)
                })
        
        return sorted(bursts, key=lambda x: x['request_count'], reverse=True)
    
    def get_user_agent_analysis(self, ip_address: str) -> Dict:
        """Analyze user agent patterns"""
        logs = self.db.get_logs(limit=1000, ip_address=ip_address)
        
        user_agents = defaultdict(int)
        
        for log in logs:
            ua = log.get('user_agent', 'Unknown')
            if ua:
                user_agents[ua] += 1
        
        # Detect bot-like behavior
        bot_indicators = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python', 'java']
        likely_bot = any(indicator in ua.lower() for ua in user_agents.keys() for indicator in bot_indicators)
        
        return {
            'unique_user_agents': len(user_agents),
            'most_common': sorted(user_agents.items(), key=lambda x: x[1], reverse=True)[:3],
            'likely_bot': likely_bot
        }
    
    def get_country_transitions(self, ip_address: str) -> List[Dict]:
        """Track country transitions for geographic anomaly detection"""
        logs = self.db.get_logs(limit=1000, ip_address=ip_address)
        
        # Sort by timestamp
        sorted_logs = sorted(logs, key=lambda x: x['timestamp'])
        
        transitions = []
        prev_country = None
        
        for log in sorted_logs:
            country = log.get('country')
            if country and country != prev_country:
                transitions.append({
                    'timestamp': log['timestamp'],
                    'from_country': prev_country,
                    'to_country': country
                })
                prev_country = country
        
        return transitions
    
    def export_ip_summary(self, ip_address: str) -> Dict:
        """Export comprehensive summary for an IP"""
        features = self.db.get_ip_features(ip_address)
        
        if not features:
            return {'error': 'IP not found'}
        
        return {
            'ip_address': ip_address,
            'basic_features': features,
            'endpoint_patterns': self.analyze_endpoint_patterns(ip_address),
            'temporal_distribution': self.get_temporal_distribution(ip_address),
            'request_rate': self.calculate_request_rate(ip_address),
            'burst_patterns': self.detect_burst_patterns(ip_address),
            'user_agent_analysis': self.get_user_agent_analysis(ip_address),
            'country_transitions': self.get_country_transitions(ip_address)
        }