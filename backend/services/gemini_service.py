import google.generativeai as genai
from typing import Dict, List, Optional
import json
import re

class GeminiService:
    """Service for Gemini AI integration"""
    
    def __init__(self, api_key: str):
        """
        Initialize Gemini service
        
        Args:
            api_key: Google Gemini API key
        """
        if not api_key:
            raise ValueError("Gemini API key is required")
        
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.5-flash')
    
    def parse_alert(self, alert_text: str, extracted_iocs: Dict) -> Dict:
        """
        Use Gemini to parse and understand the alert context
        
        Args:
            alert_text: Raw alert text
            extracted_iocs: IOCs extracted by regex
            
        Returns:
            Parsed alert information with context
        """
        prompt = f"""
You are a cybersecurity threat intelligence analyst. Analyze this security alert and provide structured information.

ALERT TEXT:
{alert_text}

EXTRACTED IOCs:
- IPs: {', '.join(extracted_iocs.get('ipv4', []))}
- Domains: {', '.join(extracted_iocs.get('domains', []))}
- Hashes: {', '.join(extracted_iocs.get('hashes', {}).get('md5', []) + extracted_iocs.get('hashes', {}).get('sha1', []) + extracted_iocs.get('hashes', {}).get('sha256', []))}
- CVEs: {', '.join(extracted_iocs.get('cves', []))}

Provide a JSON response with:
1. alert_type: Type of security event (e.g., "Malware Detection", "Intrusion Attempt", "DDoS Attack", "Phishing", etc.)
2. severity: Initial severity assessment (Critical, High, Medium, Low)
3. attack_vector: How the attack is being executed
4. affected_systems: Systems or assets potentially affected
5. brief_summary: 2-3 sentence summary of what's happening
6. key_iocs: The most critical IOCs from the list
7. context: Any additional context about the alert

Return ONLY valid JSON, no markdown formatting.
"""
        
        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            
            # Remove markdown code blocks if present
            text = re.sub(r'^```json\s*', '', text)
            text = re.sub(r'\s*```$', '', text)
            
            return json.loads(text)
        except Exception as e:
            print(f"Gemini parsing error: {e}")
            return {
                "alert_type": "Unknown",
                "severity": "Medium",
                "attack_vector": "Unknown",
                "affected_systems": [],
                "brief_summary": "Unable to parse alert details",
                "key_iocs": [],
                "context": str(e)
            }
    
    def analyze_threat_intelligence(self, iocs: Dict, threat_data: Dict) -> Dict:
        """
        Use Gemini to correlate and analyze all threat intelligence data
        
        Args:
            iocs: Extracted IOCs
            threat_data: Threat intelligence from various APIs
            
        Returns:
            Comprehensive analysis with recommendations
        """
        prompt = f"""
You are an expert cybersecurity analyst. Analyze this threat intelligence data and provide a comprehensive assessment.

THREAT INTELLIGENCE DATA:
{json.dumps(threat_data, indent=2)}

Provide a JSON response with:
1. risk_score: Overall risk score (0-100)
2. confidence_level: Confidence in analysis (0.0-1.0)
3. threat_classification: Primary threat type
4. threat_actor: Suspected threat actor or group (if identifiable)
5. attack_timeline: Estimated attack timeline/stages
6. mitre_attack_techniques: Relevant MITRE ATT&CK techniques (array of technique IDs like "T1566")
7. indicators_analysis: Analysis of key indicators
8. lateral_movement_risk: Risk of lateral movement (Low/Medium/High)
9. data_exfiltration_risk: Risk of data theft (Low/Medium/High)
10. executive_summary: 3-4 sentence executive summary
11. technical_details: Detailed technical analysis (1 paragraph)
12. immediate_actions: Array of immediate actions to take
13. investigation_steps: Array of investigation steps
14. remediation_steps: Array of remediation actions
15. prevention_measures: Long-term prevention recommendations

Return ONLY valid JSON, no markdown formatting.
"""
        
        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            
            # Remove markdown code blocks if present
            text = re.sub(r'^```json\s*', '', text)
            text = re.sub(r'\s*```$', '', text)
            
            return json.loads(text)
        except Exception as e:
            print(f"Gemini analysis error: {e}")
            return {
                "risk_score": 50,
                "confidence_level": 0.5,
                "threat_classification": "Unknown",
                "threat_actor": "Unknown",
                "attack_timeline": "Unknown",
                "mitre_attack_techniques": [],
                "indicators_analysis": "Unable to complete analysis",
                "lateral_movement_risk": "Medium",
                "data_exfiltration_risk": "Medium",
                "executive_summary": "Analysis could not be completed due to an error.",
                "technical_details": str(e),
                "immediate_actions": ["Review alert manually", "Investigate affected systems"],
                "investigation_steps": ["Manual review required"],
                "remediation_steps": ["Follow standard incident response procedures"],
                "prevention_measures": ["Enhance monitoring"]
            }
    
    def generate_firewall_rules(self, malicious_ips: List[str], malicious_domains: List[str]) -> Dict[str, List[str]]:
        """
        Generate firewall rules for blocking malicious IOCs
        
        Args:
            malicious_ips: List of malicious IP addresses
            malicious_domains: List of malicious domains
            
        Returns:
            Dictionary with firewall rules for different platforms
        """
        if not malicious_ips and not malicious_domains:
            return {}
        
        prompt = f"""
Generate firewall blocking rules for these malicious indicators:

IPs to block: {', '.join(malicious_ips[:10])}  # Limit to first 10
Domains to block: {', '.join(malicious_domains[:10])}

Provide rules for:
1. iptables (Linux)
2. Windows Firewall (PowerShell)
3. Cisco ASA
4. pfSense

Return as JSON with keys: iptables, windows_firewall, cisco_asa, pfsense
Each value should be an array of command strings.

Return ONLY valid JSON, no markdown formatting.
"""
        
        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            
            # Remove markdown code blocks if present
            text = re.sub(r'^```json\s*', '', text)
            text = re.sub(r'\s*```$', '', text)
            
            return json.loads(text)
        except Exception as e:
            print(f"Gemini firewall rules error: {e}")
            # Provide basic rules if Gemini fails
            rules = {
                "iptables": [f"iptables -A INPUT -s {ip} -j DROP" for ip in malicious_ips[:5]],
                "windows_firewall": [f"New-NetFirewallRule -DisplayName 'Block {ip}' -Direction Inbound -RemoteAddress {ip} -Action Block" for ip in malicious_ips[:5]],
                "cisco_asa": [f"access-list BLOCK_LIST deny ip host {ip} any" for ip in malicious_ips[:5]],
                "pfsense": [f"# Block {ip} via pfSense Firewall Rules interface" for ip in malicious_ips[:5]]
            }
            return rules
