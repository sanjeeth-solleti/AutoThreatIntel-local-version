from datetime import datetime
from typing import Dict, List
import uuid

class ReportGenerator:
    """Generate structured threat intelligence reports"""
    
    def __init__(self):
        pass
    
    def calculate_risk_score(self, threat_data: Dict, gemini_analysis: Dict) -> int:
        """
        Calculate overall risk score based on threat intelligence
        
        Args:
            threat_data: Threat intelligence data from APIs
            gemini_analysis: Analysis from Gemini AI
            
        Returns:
            Risk score from 0-100
        """
        score = 0
        
        # Base score from Gemini
        score = gemini_analysis.get('risk_score', 50)
        
        # Adjust based on malicious IOC counts
        summary = threat_data.get('summary', {})
        score += min(summary.get('total_malicious_ips', 0) * 5, 20)
        score += min(summary.get('total_malicious_domains', 0) * 5, 15)
        score += min(summary.get('total_malicious_urls', 0) * 5, 10)
        score += min(summary.get('total_malicious_hashes', 0) * 10, 15)
        
        # Cap at 100
        return min(score, 100)
    
    def determine_threat_level(self, risk_score: int) -> str:
        """Determine threat level from risk score"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def format_ioc_details(self, iocs: Dict, threat_data: Dict) -> Dict:
        """
        Format IOC details with threat intelligence
        
        Args:
            iocs: Extracted IOCs
            threat_data: Threat intelligence data
            
        Returns:
            Formatted IOC details
        """
        formatted = {
            'ips': [],
            'domains': [],
            'urls': [],
            'hashes': [],
            'cves': []
        }
        
        # Format IPs
        for ip in iocs.get('ipv4', []):
            ip_intel = threat_data.get('ips', {}).get(ip, {})
            
            vt_data = ip_intel.get('virustotal', {})
            abuse_data = ip_intel.get('abuseipdb', {})
            
            malicious_count = vt_data.get('malicious', 0)
            abuse_score = abuse_data.get('abuse_confidence_score', 0)
            
            threat_level = "CRITICAL" if (malicious_count > 5 or abuse_score > 80) else \
                          "HIGH" if (malicious_count > 2 or abuse_score > 50) else \
                          "MEDIUM" if (malicious_count > 0 or abuse_score > 20) else "LOW"
            
            formatted['ips'].append({
                'value': ip,
                'threat_level': threat_level,
                'malicious_detections': malicious_count,
                'abuse_confidence': abuse_score,
                'country': vt_data.get('country') or abuse_data.get('country', 'Unknown'),
                'isp': abuse_data.get('isp', 'Unknown'),
                'reports': abuse_data.get('total_reports', 0)
            })
        
        # Format Domains
        for domain in iocs.get('domains', []):
            domain_intel = threat_data.get('domains', {}).get(domain, {})
            vt_data = domain_intel.get('virustotal', {})
            
            malicious_count = vt_data.get('malicious', 0)
            
            threat_level = "CRITICAL" if malicious_count > 5 else \
                          "HIGH" if malicious_count > 2 else \
                          "MEDIUM" if malicious_count > 0 else "LOW"
            
            formatted['domains'].append({
                'value': domain,
                'threat_level': threat_level,
                'malicious_detections': malicious_count,
                'categories': vt_data.get('categories', {}),
                'reputation': vt_data.get('reputation', 0)
            })
        
        # Format URLs
        for url in iocs.get('urls', []):
            url_intel = threat_data.get('urls', {}).get(url, {})
            vt_data = url_intel.get('virustotal', {})
            urlhaus_data = url_intel.get('urlhaus', {})
            
            malicious_count = vt_data.get('malicious', 0)
            
            threat_level = "CRITICAL" if malicious_count > 5 else \
                          "HIGH" if malicious_count > 2 else \
                          "MEDIUM" if malicious_count > 0 else "LOW"
            
            formatted['urls'].append({
                'value': url,
                'threat_level': threat_level,
                'malicious_detections': malicious_count,
                'threat_type': urlhaus_data.get('threat', 'Unknown'),
                'tags': urlhaus_data.get('tags', [])
            })
        
        # Format Hashes
        all_hashes = (iocs.get('hashes', {}).get('md5', []) + 
                     iocs.get('hashes', {}).get('sha1', []) + 
                     iocs.get('hashes', {}).get('sha256', []))
        
        for file_hash in all_hashes:
            hash_intel = threat_data.get('hashes', {}).get(file_hash, {})
            vt_data = hash_intel.get('virustotal', {})
            
            malicious_count = vt_data.get('malicious', 0)
            
            threat_level = "CRITICAL" if malicious_count > 10 else \
                          "HIGH" if malicious_count > 5 else \
                          "MEDIUM" if malicious_count > 0 else "LOW"
            
            formatted['hashes'].append({
                'value': file_hash,
                'threat_level': threat_level,
                'malicious_detections': malicious_count,
                'file_type': vt_data.get('file_type', 'Unknown'),
                'file_name': vt_data.get('file_name', 'Unknown'),
                'tags': vt_data.get('tags', [])
            })
        
        # Format CVEs
        for cve in iocs.get('cves', []):
            formatted['cves'].append({
                'value': cve,
                'threat_level': "HIGH",  # CVEs are generally high priority
                'description': f"Known vulnerability {cve}"
            })
        
        return formatted
    
    def generate_report(self, alert_text: str, iocs: Dict, 
                       alert_context: Dict, threat_data: Dict, 
                       gemini_analysis: Dict) -> Dict:
        """
        Generate complete threat intelligence report
        
        Args:
            alert_text: Original alert text
            iocs: Extracted IOCs
            alert_context: Initial alert parsing from Gemini
            threat_data: Threat intelligence from APIs
            gemini_analysis: Final analysis from Gemini
            
        Returns:
            Complete structured report
        """
        analysis_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        risk_score = self.calculate_risk_score(threat_data, gemini_analysis)
        threat_level = self.determine_threat_level(risk_score)
        
        formatted_iocs = self.format_ioc_details(iocs, threat_data)
        
        # Get malicious IOCs for firewall rules
        malicious_ips = [ip['value'] for ip in formatted_iocs['ips'] 
                        if ip['threat_level'] in ['CRITICAL', 'HIGH']]
        malicious_domains = [domain['value'] for domain in formatted_iocs['domains'] 
                            if domain['threat_level'] in ['CRITICAL', 'HIGH']]
        
        report = {
            'metadata': {
                'analysis_id': analysis_id,
                'timestamp': timestamp,
                'analyst': 'ThreatLens AI',
                'version': '1.0.0'
            },
            'summary': {
                'threat_level': threat_level,
                'risk_score': risk_score,
                'confidence': gemini_analysis.get('confidence_level', 0.0),
                'alert_type': alert_context.get('alert_type', 'Unknown'),
                'threat_classification': gemini_analysis.get('threat_classification', 'Unknown'),
                'executive_summary': gemini_analysis.get('executive_summary', ''),
                'key_findings': [
                    f"Detected {len(formatted_iocs['ips'])} IP addresses",
                    f"Detected {len(formatted_iocs['domains'])} domains",
                    f"Detected {len(formatted_iocs['hashes'])} file hashes",
                    f"{threat_data.get('summary', {}).get('total_malicious_ips', 0)} malicious IPs identified",
                    f"{threat_data.get('summary', {}).get('total_malicious_domains', 0)} malicious domains identified"
                ]
            },
            'alert_details': {
                'original_alert': alert_text[:500] + ('...' if len(alert_text) > 500 else ''),
                'severity': alert_context.get('severity', 'Medium'),
                'attack_vector': alert_context.get('attack_vector', 'Unknown'),
                'affected_systems': alert_context.get('affected_systems', []),
                'context': alert_context.get('context', '')
            },
            'indicators': formatted_iocs,
            'threat_intelligence': {
                'mitre_attack': gemini_analysis.get('mitre_attack_techniques', []),
                'threat_actor': gemini_analysis.get('threat_actor', 'Unknown'),
                'attack_timeline': gemini_analysis.get('attack_timeline', 'Unknown'),
                'lateral_movement_risk': gemini_analysis.get('lateral_movement_risk', 'Unknown'),
                'data_exfiltration_risk': gemini_analysis.get('data_exfiltration_risk', 'Unknown'),
                'technical_details': gemini_analysis.get('technical_details', '')
            },
            'recommendations': {
                'immediate_actions': gemini_analysis.get('immediate_actions', []),
                'investigation_steps': gemini_analysis.get('investigation_steps', []),
                'remediation_steps': gemini_analysis.get('remediation_steps', []),
                'prevention_measures': gemini_analysis.get('prevention_measures', [])
            },
            'blocking_rules': {
                'malicious_ips': malicious_ips,
                'malicious_domains': malicious_domains
            }
        }
        
        return report
