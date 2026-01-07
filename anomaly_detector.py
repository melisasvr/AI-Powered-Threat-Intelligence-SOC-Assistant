"""
Anomaly Detector - Uses clustering and statistical methods to detect anomalies
"""

import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import json
from collections import defaultdict

class AnomalyDetector:
    def __init__(self, db_manager):
        self.db = db_manager
        self.anomaly_threshold = 2.5  # Standard deviations for z-score
        self.high_threshold = 3.0      # Threshold for HIGH severity
        self.medium_threshold = 2.0    # Threshold for MEDIUM severity
    
    def detect_anomalies(self) -> List[Dict]:
        """Main anomaly detection method - runs all detection algorithms"""
        anomalies = []
        
        # Get all IP features
        all_features = self.db.get_ip_features()
        
        if not all_features or len(all_features) < 3:
            return anomalies
        
        # Run different detection methods
        anomalies.extend(self._detect_high_error_rate(all_features))
        anomalies.extend(self._detect_unusual_request_volume(all_features))
        anomalies.extend(self._detect_new_country_access(all_features))
        anomalies.extend(self._detect_endpoint_anomalies())
        anomalies.extend(self._detect_time_based_anomalies())
        anomalies.extend(self._detect_rapid_fire_requests())
        anomalies.extend(self._detect_scanning_behavior())
        
        # Remove duplicates (same IP, same anomaly type)
        unique_anomalies = self._deduplicate_anomalies(anomalies)
        
        return unique_anomalies
    
    def _detect_high_error_rate(self, features: List[Dict]) -> List[Dict]:
        """Detect IPs with unusually high error rates"""
        anomalies = []
        error_rates = [f['error_rate'] for f in features if f['error_rate'] is not None]
        
        if not error_rates or len(error_rates) < 2:
            return anomalies
        
        mean_error = np.mean(error_rates)
        std_error = np.std(error_rates)
        
        for feature in features:
            error_rate = feature.get('error_rate', 0)
            if error_rate is None:
                continue
            
            if std_error > 0:
                z_score = (error_rate - mean_error) / std_error
                
                # Only flag if error rate is above 20% and significantly above average
                if error_rate > 0.2 and z_score > self.medium_threshold:
                    severity = self._calculate_severity(z_score)
                    
                    anomalies.append({
                        'ip_address': feature['ip_address'],
                        'anomaly_type': 'High Error Rate',
                        'severity': severity,
                        'score': error_rate,
                        'threshold': mean_error + self.anomaly_threshold * std_error,
                        'timestamp': datetime.now().isoformat(),
                        'details': {
                            'error_rate': round(error_rate, 3),
                            'request_count': feature['request_count'],
                            'expected_error_rate': round(mean_error, 3),
                            'z_score': round(z_score, 2)
                        }
                    })
        
        return anomalies
    
    def _detect_unusual_request_volume(self, features: List[Dict]) -> List[Dict]:
        """Detect IPs with unusual request volumes"""
        anomalies = []
        request_counts = [f['request_count'] for f in features if f['request_count'] is not None]
        
        if not request_counts or len(request_counts) < 2:
            return anomalies
        
        mean_requests = np.mean(request_counts)
        std_requests = np.std(request_counts)
        
        for feature in features:
            request_count = feature.get('request_count', 0)
            
            # Check for abnormally high volumes only
            if std_requests > 0 and request_count > mean_requests:
                z_score = (request_count - mean_requests) / std_requests
                
                if z_score > self.medium_threshold:
                    severity = self._calculate_severity(z_score)
                    
                    anomalies.append({
                        'ip_address': feature['ip_address'],
                        'anomaly_type': 'Unusual Request Volume',
                        'severity': severity,
                        'score': z_score,
                        'threshold': self.anomaly_threshold,
                        'timestamp': datetime.now().isoformat(),
                        'details': {
                            'request_count': request_count,
                            'expected_count': round(mean_requests, 0),
                            'z_score': round(z_score, 2),
                            'deviation_percentage': round((request_count - mean_requests) / mean_requests * 100, 1)
                        }
                    })
        
        return anomalies
    
    def _detect_new_country_access(self, features: List[Dict]) -> List[Dict]:
        """Detect IPs accessing from multiple countries"""
        anomalies = []
        
        for feature in features:
            countries_data = feature.get('countries', [])
            
            # Parse if JSON string
            if isinstance(countries_data, str):
                try:
                    countries = json.loads(countries_data)
                except:
                    countries = []
            else:
                countries = countries_data
            
            # Filter out None and empty strings
            countries = [c for c in countries if c]
            
            if len(countries) > 2:  # Multiple countries is suspicious
                severity = 'HIGH' if len(countries) >= 4 else 'MEDIUM'
                
                anomalies.append({
                    'ip_address': feature['ip_address'],
                    'anomaly_type': 'Multiple Country Access',
                    'severity': severity,
                    'score': len(countries),
                    'threshold': 2,
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'countries': countries,
                        'country_count': len(countries)
                    }
                })
        
        return anomalies
    
    def _detect_endpoint_anomalies(self) -> List[Dict]:
        """Detect unusual endpoint access patterns"""
        anomalies = []
        
        # Get recent logs
        logs = self.db.get_logs(limit=2000)
        
        # Group by IP
        ip_endpoints = defaultdict(set)
        for log in logs:
            ip = log['ip_address']
            ip_endpoints[ip].add(log['endpoint'])
        
        # Check for sensitive endpoint access
        sensitive_endpoints = ['/admin', '/config', '/api/users', '/api/admin', '/dashboard', 
                             '/settings', '/api/config', '/api/keys', '/api/secrets']
        
        for ip, endpoints in ip_endpoints.items():
            accessed_sensitive = []
            for endpoint in endpoints:
                if any(sens in endpoint.lower() for sens in sensitive_endpoints):
                    accessed_sensitive.append(endpoint)
            
            if accessed_sensitive:
                severity = 'HIGH' if len(accessed_sensitive) >= 3 else 'MEDIUM'
                
                anomalies.append({
                    'ip_address': ip,
                    'anomaly_type': 'Sensitive Endpoint Access',
                    'severity': severity,
                    'score': len(accessed_sensitive),
                    'threshold': 0,
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'sensitive_endpoints': list(accessed_sensitive),
                        'total_endpoints': len(endpoints)
                    }
                })
        
        return anomalies
    
    def _detect_time_based_anomalies(self) -> List[Dict]:
        """Detect unusual activity based on time patterns"""
        anomalies = []
        
        # Get recent logs
        logs = self.db.get_logs(limit=2000)
        
        # Group by IP and hour
        ip_hour_counts = defaultdict(lambda: defaultdict(int))
        
        for log in logs:
            try:
                timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                hour = timestamp.hour
                ip = log['ip_address']
                ip_hour_counts[ip][hour] += 1
            except:
                continue
        
        # Detect off-hours activity (e.g., 2-6 AM)
        off_hours = range(2, 6)
        
        for ip, hour_counts in ip_hour_counts.items():
            off_hour_requests = sum(hour_counts.get(h, 0) for h in off_hours)
            total_requests = sum(hour_counts.values())
            
            if total_requests > 20 and off_hour_requests / total_requests > 0.5:
                percentage = off_hour_requests / total_requests
                severity = 'HIGH' if percentage > 0.8 else 'MEDIUM'
                
                anomalies.append({
                    'ip_address': ip,
                    'anomaly_type': 'Off-Hours Activity',
                    'severity': severity,
                    'score': percentage,
                    'threshold': 0.5,
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'off_hour_requests': off_hour_requests,
                        'total_requests': total_requests,
                        'percentage': round(percentage * 100, 1)
                    }
                })
        
        return anomalies
    
    def _detect_rapid_fire_requests(self) -> List[Dict]:
        """Detect rapid-fire request patterns (potential automated attacks)"""
        anomalies = []
        
        logs = self.db.get_logs(limit=2000)
        
        # Group by IP and minute
        ip_minute_counts = defaultdict(lambda: defaultdict(int))
        
        for log in logs:
            try:
                timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                minute_key = timestamp.strftime('%Y-%m-%d %H:%M')
                ip = log['ip_address']
                ip_minute_counts[ip][minute_key] += 1
            except:
                continue
        
        # Detect IPs with very high requests per minute
        for ip, minute_counts in ip_minute_counts.items():
            max_per_minute = max(minute_counts.values()) if minute_counts else 0
            
            # Flag if more than 50 requests in a single minute
            if max_per_minute > 50:
                severity = 'HIGH' if max_per_minute > 100 else 'MEDIUM'
                
                anomalies.append({
                    'ip_address': ip,
                    'anomaly_type': 'Rapid Fire Requests',
                    'severity': severity,
                    'score': max_per_minute,
                    'threshold': 50,
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'max_requests_per_minute': max_per_minute,
                        'total_minutes': len(minute_counts)
                    }
                })
        
        return anomalies
    
    def _detect_scanning_behavior(self) -> List[Dict]:
        """Detect port scanning or endpoint enumeration behavior"""
        anomalies = []
        
        logs = self.db.get_logs(limit=2000)
        
        # Group by IP
        ip_endpoints = defaultdict(set)
        ip_404_count = defaultdict(int)
        
        for log in logs:
            ip = log['ip_address']
            ip_endpoints[ip].add(log['endpoint'])
            if log['status_code'] == 404:
                ip_404_count[ip] += 1
        
        # Detect scanning: many unique endpoints + many 404s
        for ip, endpoints in ip_endpoints.items():
            unique_endpoint_count = len(endpoints)
            not_found_count = ip_404_count.get(ip, 0)
            
            # Flag if accessing many unique endpoints with high 404 rate
            if unique_endpoint_count > 20 and not_found_count > 10:
                not_found_rate = not_found_count / unique_endpoint_count
                
                if not_found_rate > 0.3:  # More than 30% 404 rate
                    severity = 'HIGH' if unique_endpoint_count > 50 else 'MEDIUM'
                    
                    anomalies.append({
                        'ip_address': ip,
                        'anomaly_type': 'Scanning Behavior',
                        'severity': severity,
                        'score': unique_endpoint_count,
                        'threshold': 20,
                        'timestamp': datetime.now().isoformat(),
                        'details': {
                            'unique_endpoints': unique_endpoint_count,
                            '404_count': not_found_count,
                            '404_rate': round(not_found_rate * 100, 1)
                        }
                    })
        
        return anomalies
    
    def _calculate_severity(self, z_score: float) -> str:
        """Calculate severity based on z-score"""
        if z_score >= self.high_threshold:
            return 'HIGH'
        elif z_score >= self.medium_threshold:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _deduplicate_anomalies(self, anomalies: List[Dict]) -> List[Dict]:
        """Remove duplicate anomalies for same IP and type"""
        seen = set()
        unique = []
        
        for anomaly in anomalies:
            key = (anomaly['ip_address'], anomaly['anomaly_type'])
            if key not in seen:
                seen.add(key)
                unique.append(anomaly)
        
        return unique
    
    def calculate_anomaly_score(self, features: Dict) -> float:
        """Calculate overall anomaly score for an IP (0-10 scale)"""
        score = 0
        
        # High request count (up to 2 points)
        if features.get('request_count', 0) > 100:
            score += min(2, features['request_count'] / 100)
        
        # High error rate (up to 3 points)
        error_rate = features.get('error_rate', 0)
        if error_rate > 0.1:
            score += min(3, error_rate * 10)
        
        # Multiple countries (up to 2 points)
        country_count = features.get('country_count', 0)
        if country_count > 1:
            score += min(2, country_count * 0.5)
        
        # Many unique endpoints (up to 2 points)
        unique_endpoints = features.get('unique_endpoints', 0)
        if unique_endpoints > 10:
            score += min(2, unique_endpoints / 20)
        
        # Slow response time (up to 1 point)
        avg_response_time = features.get('avg_response_time', 0)
        if avg_response_time > 1.0:
            score += min(1, avg_response_time / 5)
        
        return min(10, round(score, 2))
    
    def analyze_ip_risk(self, ip_address: str) -> Dict:
        """Comprehensive risk analysis for a specific IP"""
        features = self.db.get_ip_features(ip_address)
        
        if not features:
            return {'error': 'IP not found', 'risk_level': 'UNKNOWN'}
        
        # Parse countries
        countries = features.get('countries', [])
        if isinstance(countries, str):
            try:
                countries = json.loads(countries)
            except:
                countries = []
        
        # Calculate individual risk factors
        risk_factors = {
            'high_request_volume': features['request_count'] > 200,
            'high_error_rate': features['error_rate'] > 0.3,
            'multiple_countries': len(countries) > 2,
            'many_endpoints': features['unique_endpoints'] > 30,
            'slow_response': features.get('avg_response_time', 0) > 2.0
        }
        
        # Calculate overall risk
        risk_count = sum(risk_factors.values())
        
        if risk_count >= 4:
            risk_level = 'CRITICAL'
        elif risk_count >= 3:
            risk_level = 'HIGH'
        elif risk_count >= 2:
            risk_level = 'MEDIUM'
        elif risk_count >= 1:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'ip_address': ip_address,
            'risk_level': risk_level,
            'risk_score': self.calculate_anomaly_score(features),
            'risk_factors': risk_factors,
            'features': features,
            'recommendation': self._get_risk_recommendation(risk_level)
        }
    
    def _get_risk_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level"""
        recommendations = {
            'CRITICAL': 'Immediate action required: Block IP and investigate all activity',
            'HIGH': 'Priority investigation: Review logs and consider temporary restrictions',
            'MEDIUM': 'Monitor closely: Set up alerts for continued suspicious activity',
            'LOW': 'Continue monitoring: Document patterns for trend analysis',
            'MINIMAL': 'Normal activity: No immediate action required'
        }
        return recommendations.get(risk_level, 'Review and assess')
    
    def get_anomaly_trends(self, hours: int = 24) -> Dict:
        """Analyze anomaly trends over time"""
        incidents = self.db.get_incidents(limit=500)
        
        if not incidents:
            return {'total': 0, 'by_severity': {}, 'by_type': {}}
        
        # Count by severity
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        by_hour = defaultdict(int)
        
        for incident in incidents:
            by_severity[incident['severity']] += 1
            by_type[incident['anomaly_type']] += 1
            
            try:
                timestamp = datetime.fromisoformat(incident['timestamp'])
                hour_key = timestamp.strftime('%Y-%m-%d %H:00')
                by_hour[hour_key] += 1
            except:
                continue
        
        return {
            'total': len(incidents),
            'by_severity': dict(by_severity),
            'by_type': dict(by_type),
            'hourly_distribution': dict(sorted(by_hour.items()))
        }
    
    def detect_coordinated_attacks(self) -> List[Dict]:
        """Detect potential coordinated attacks from multiple IPs"""
        logs = self.db.get_logs(limit=2000)
        
        # Group by endpoint and time window
        endpoint_ips = defaultdict(lambda: defaultdict(set))
        
        for log in logs:
            try:
                timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                time_window = timestamp.strftime('%Y-%m-%d %H:%M')  # 1-minute windows
                endpoint = log['endpoint']
                ip = log['ip_address']
                
                endpoint_ips[time_window][endpoint].add(ip)
            except:
                continue
        
        coordinated = []
        
        # Find endpoints accessed by multiple IPs in same time window
        for time_window, endpoints in endpoint_ips.items():
            for endpoint, ips in endpoints.items():
                if len(ips) >= 3:  # 3 or more IPs hitting same endpoint
                    coordinated.append({
                        'time_window': time_window,
                        'endpoint': endpoint,
                        'ip_count': len(ips),
                        'ips': list(ips),
                        'severity': 'HIGH' if len(ips) >= 5 else 'MEDIUM'
                    })
        
        return sorted(coordinated, key=lambda x: x['ip_count'], reverse=True)
    
    def export_anomaly_report(self) -> Dict:
        """Export comprehensive anomaly detection report"""
        all_features = self.db.get_ip_features()
        anomalies = self.detect_anomalies()
        trends = self.get_anomaly_trends()
        coordinated = self.detect_coordinated_attacks()
        
        return {
            'generated_at': datetime.now().isoformat(),
            'total_ips_monitored': len(all_features),
            'anomalies_detected': len(anomalies),
            'anomaly_breakdown': {
                'by_severity': self._count_by_field(anomalies, 'severity'),
                'by_type': self._count_by_field(anomalies, 'anomaly_type')
            },
            'trends': trends,
            'coordinated_attacks': len(coordinated),
            'top_anomalies': anomalies[:10]
        }
    
    def _count_by_field(self, items: List[Dict], field: str) -> Dict:
        """Helper to count items by a specific field"""
        counts = defaultdict(int)
        for item in items:
            counts[item.get(field, 'Unknown')] += 1
        return dict(counts)