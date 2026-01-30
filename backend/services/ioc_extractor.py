import re
from typing import Dict, List, Set

class IOCExtractor:
    """Extract Indicators of Compromise from alert text"""
    
    def __init__(self):
        # Regex patterns for different IOC types
        self.patterns = {
            'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'cve': r'CVE-\d{4}-\d{4,7}',
        }
        
        # Private IP ranges to filter out
        self.private_ip_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^169\.254\.',
        ]
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        for pattern in self.private_ip_patterns:
            if re.match(pattern, ip):
                return True
        return False
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """
        Extract all IOCs from text
        
        Args:
            text: Alert text to analyze
            
        Returns:
            Dictionary with IOC types as keys and lists of found IOCs as values
        """
        iocs = {
            'ipv4': [],
            'domains': [],
            'urls': [],
            'hashes': {
                'md5': [],
                'sha1': [],
                'sha256': []
            },
            'emails': [],
            'cves': []
        }
        
        # Extract IPv4 addresses (excluding private IPs)
        ipv4_matches = re.findall(self.patterns['ipv4'], text)
        iocs['ipv4'] = list(set([ip for ip in ipv4_matches if not self.is_private_ip(ip)]))
        
        # Extract domains (excluding IPs and common false positives)
        domain_matches = re.findall(self.patterns['domain'], text)
        # Filter out IPs, common file extensions, and localhost
        filtered_domains = []
        for domain in domain_matches:
            if (not re.match(self.patterns['ipv4'], domain) and 
                not domain.endswith(('.exe', '.dll', '.log', '.txt', '.jpg', '.png')) and
                domain not in ['localhost', 'example.com']):
                filtered_domains.append(domain.lower())
        iocs['domains'] = list(set(filtered_domains))
        
        # Extract URLs
        url_matches = re.findall(self.patterns['url'], text)
        # Defang URLs (replace hxxp with http for processing)
        defanged_urls = [url.replace('hxxp', 'http').replace('[.]', '.') for url in url_matches]
        iocs['urls'] = list(set(defanged_urls))
        
        # Extract file hashes
        iocs['hashes']['md5'] = list(set(re.findall(self.patterns['md5'], text)))
        iocs['hashes']['sha1'] = list(set(re.findall(self.patterns['sha1'], text)))
        iocs['hashes']['sha256'] = list(set(re.findall(self.patterns['sha256'], text)))
        
        # Extract emails
        email_matches = re.findall(self.patterns['email'], text)
        iocs['emails'] = list(set(email_matches))
        
        # Extract CVEs
        cve_matches = re.findall(self.patterns['cve'], text, re.IGNORECASE)
        iocs['cves'] = list(set([cve.upper() for cve in cve_matches]))
        
        return iocs
    
    def get_ioc_summary(self, iocs: Dict) -> Dict[str, int]:
        """Get count summary of extracted IOCs"""
        return {
            'total_ips': len(iocs['ipv4']),
            'total_domains': len(iocs['domains']),
            'total_urls': len(iocs['urls']),
            'total_hashes': (len(iocs['hashes']['md5']) + 
                           len(iocs['hashes']['sha1']) + 
                           len(iocs['hashes']['sha256'])),
            'total_emails': len(iocs['emails']),
            'total_cves': len(iocs['cves'])
        }
