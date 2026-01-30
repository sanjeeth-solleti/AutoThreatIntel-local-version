import requests
from typing import Dict, List, Optional
import time

class ThreatIntelligence:
    """Service for querying threat intelligence APIs"""
    
    def __init__(self, config):
        """
        Initialize threat intelligence service
        
        Args:
            config: Configuration object with API keys
        """
        self.vt_api_key = config.VIRUSTOTAL_API_KEY
        self.abuseipdb_api_key = config.ABUSEIPDB_API_KEY
        self.shodan_api_key = config.SHODAN_API_KEY
        
        self.vt_base_url = config.VIRUSTOTAL_BASE_URL
        self.abuseipdb_base_url = config.ABUSEIPDB_BASE_URL
        self.urlhaus_base_url = config.URLHAUS_BASE_URL
        
        self.timeout = config.TIMEOUT_SECONDS
    
    def check_ip_virustotal(self, ip: str) -> Optional[Dict]:
        """Check IP reputation on VirusTotal"""
        if not self.vt_api_key:
            return None
        
        try:
            headers = {'x-apikey': self.vt_api_key}
            response = requests.get(
                f"{self.vt_base_url}/ip_addresses/{ip}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0),
                    'country': data.get('data', {}).get('attributes', {}).get('country', 'Unknown')
                }
            return None
        except Exception as e:
            print(f"VirusTotal IP check error: {e}")
            return None
    
    def check_ip_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Check IP reputation on AbuseIPDB"""
        if not self.abuseipdb_api_key:
            return None
        
        try:
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            
            response = requests.get(
                f"{self.abuseipdb_base_url}/check",
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'country': data.get('countryCode', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'usage_type': data.get('usageType', 'Unknown')
                }
            return None
        except Exception as e:
            print(f"AbuseIPDB check error: {e}")
            return None
    
    def check_domain_virustotal(self, domain: str) -> Optional[Dict]:
        """Check domain reputation on VirusTotal"""
        if not self.vt_api_key:
            return None
        
        try:
            headers = {'x-apikey': self.vt_api_key}
            response = requests.get(
                f"{self.vt_base_url}/domains/{domain}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0),
                    'categories': data.get('data', {}).get('attributes', {}).get('categories', {})
                }
            return None
        except Exception as e:
            print(f"VirusTotal domain check error: {e}")
            return None
    
    def check_url_virustotal(self, url: str) -> Optional[Dict]:
        """Check URL reputation on VirusTotal"""
        if not self.vt_api_key:
            return None
        
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {'x-apikey': self.vt_api_key}
            response = requests.get(
                f"{self.vt_base_url}/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0)
                }
            return None
        except Exception as e:
            print(f"VirusTotal URL check error: {e}")
            return None
    
    def check_hash_virustotal(self, file_hash: str) -> Optional[Dict]:
        """Check file hash on VirusTotal"""
        if not self.vt_api_key:
            return None
        
        try:
            headers = {'x-apikey': self.vt_api_key}
            response = requests.get(
                f"{self.vt_base_url}/files/{file_hash}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'file_type': attrs.get('type_description', 'Unknown'),
                    'file_name': attrs.get('meaningful_name', 'Unknown'),
                    'tags': attrs.get('tags', [])
                }
            return None
        except Exception as e:
            print(f"VirusTotal hash check error: {e}")
            return None
    
    def check_url_urlhaus(self, url: str) -> Optional[Dict]:
        """Check URL on URLhaus"""
        try:
            data = {'url': url}
            response = requests.post(
                f"{self.urlhaus_base_url}/url/",
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    return {
                        'threat': result.get('threat', 'Unknown'),
                        'tags': result.get('tags', []),
                        'url_status': result.get('url_status', 'Unknown'),
                        'date_added': result.get('date_added', 'Unknown')
                    }
            return None
        except Exception as e:
            print(f"URLhaus check error: {e}")
            return None
    
    def analyze_iocs(self, iocs: Dict) -> Dict:
        """
        Analyze all IOCs against threat intelligence sources
        
        Args:
            iocs: Dictionary of extracted IOCs
            
        Returns:
            Comprehensive threat intelligence data
        """
        results = {
            'ips': {},
            'domains': {},
            'urls': {},
            'hashes': {},
            'summary': {
                'total_malicious_ips': 0,
                'total_malicious_domains': 0,
                'total_malicious_urls': 0,
                'total_malicious_hashes': 0
            }
        }
        
        # Analyze IPs
        for ip in iocs.get('ipv4', [])[:10]:  # Limit to 10 IPs to avoid rate limits
            ip_data = {}
            
            vt_result = self.check_ip_virustotal(ip)
            if vt_result:
                ip_data['virustotal'] = vt_result
                if vt_result['malicious'] > 0:
                    results['summary']['total_malicious_ips'] += 1
            
            abuseipdb_result = self.check_ip_abuseipdb(ip)
            if abuseipdb_result:
                ip_data['abuseipdb'] = abuseipdb_result
                if abuseipdb_result['abuse_confidence_score'] > 50:
                    results['summary']['total_malicious_ips'] += 1
            
            if ip_data:
                results['ips'][ip] = ip_data
            
            time.sleep(0.5)  # Rate limiting
        
        # Analyze Domains
        for domain in iocs.get('domains', [])[:10]:
            domain_data = {}
            
            vt_result = self.check_domain_virustotal(domain)
            if vt_result:
                domain_data['virustotal'] = vt_result
                if vt_result['malicious'] > 0:
                    results['summary']['total_malicious_domains'] += 1
            
            if domain_data:
                results['domains'][domain] = domain_data
            
            time.sleep(0.5)
        
        # Analyze URLs
        for url in iocs.get('urls', [])[:5]:
            url_data = {}
            
            vt_result = self.check_url_virustotal(url)
            if vt_result:
                url_data['virustotal'] = vt_result
                if vt_result['malicious'] > 0:
                    results['summary']['total_malicious_urls'] += 1
            
            urlhaus_result = self.check_url_urlhaus(url)
            if urlhaus_result:
                url_data['urlhaus'] = urlhaus_result
            
            if url_data:
                results['urls'][url] = url_data
            
            time.sleep(0.5)
        
        # Analyze File Hashes
        all_hashes = (iocs.get('hashes', {}).get('md5', []) + 
                     iocs.get('hashes', {}).get('sha1', []) + 
                     iocs.get('hashes', {}).get('sha256', []))
        
        for file_hash in all_hashes[:10]:
            hash_data = {}
            
            vt_result = self.check_hash_virustotal(file_hash)
            if vt_result:
                hash_data['virustotal'] = vt_result
                if vt_result['malicious'] > 0:
                    results['summary']['total_malicious_hashes'] += 1
            
            if hash_data:
                results['hashes'][file_hash] = hash_data
            
            time.sleep(0.5)
        
        return results
