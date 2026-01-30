"""
Input Validators for ThreatLens

This module provides validation functions for:
- Alert text input
- IOCs (IPs, domains, URLs, hashes, emails)
- API responses
- User input sanitization
"""

import re
import ipaddress
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse


class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass


class InputValidator:
    """Validator for user inputs"""
    
    def __init__(self):
        # Maximum input lengths
        self.MAX_ALERT_LENGTH = 50000  # 50KB
        self.MAX_IOC_LENGTH = 500
        
        # Patterns for validation
        self.sql_injection_pattern = re.compile(
            r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|--|;|'|\")",
            re.IGNORECASE
        )
        
        self.xss_pattern = re.compile(
            r"(<script|<iframe|<object|<embed|javascript:|onerror=|onload=)",
            re.IGNORECASE
        )
    
    def validate_alert_text(self, alert_text: str) -> Tuple[bool, Optional[str]]:
        """
        Validate security alert text
        
        Args:
            alert_text: The alert text to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if empty
        if not alert_text or not alert_text.strip():
            return False, "Alert text cannot be empty"
        
        # Check length
        if len(alert_text) > self.MAX_ALERT_LENGTH:
            return False, f"Alert text too long (max {self.MAX_ALERT_LENGTH} characters)"
        
        # Check for extremely short input (likely not a real alert)
        if len(alert_text.strip()) < 10:
            return False, "Alert text too short (minimum 10 characters)"
        
        # Check for SQL injection attempts (basic)
        if self.sql_injection_pattern.search(alert_text):
            # This might be legitimate in security logs, so just warn
            pass
        
        # Check for XSS attempts
        if self.xss_pattern.search(alert_text):
            # This might be legitimate in security logs
            pass
        
        return True, None
    
    def sanitize_text(self, text: str) -> str:
        """
        Sanitize text input by removing potentially dangerous characters
        
        Args:
            text: Text to sanitize
            
        Returns:
            Sanitized text
        """
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Limit consecutive newlines
        text = re.sub(r'\n{4,}', '\n\n\n', text)
        
        # Remove control characters except common ones
        text = ''.join(char for char in text if char.isprintable() or char in '\n\r\t')
        
        return text


class IOCValidator:
    """Validator for Indicators of Compromise"""
    
    def __init__(self):
        # Regex patterns
        self.ipv4_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        
        self.domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        
        self.email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        
        self.md5_pattern = re.compile(r'^[a-fA-F0-9]{32}$')
        self.sha1_pattern = re.compile(r'^[a-fA-F0-9]{40}$')
        self.sha256_pattern = re.compile(r'^[a-fA-F0-9]{64}$')
        
        self.cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,7}$', re.IGNORECASE)
    
    def validate_ip(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Validate IPv4 address
        
        Args:
            ip: IP address string
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Use ipaddress module for robust validation
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if it's IPv4
            if not isinstance(ip_obj, ipaddress.IPv4Address):
                return False, "Only IPv4 addresses are supported"
            
            # Check if it's a valid unicast address
            if ip_obj.is_multicast or ip_obj.is_reserved:
                return False, "IP address is multicast or reserved"
            
            return True, None
        
        except ValueError as e:
            return False, f"Invalid IP address: {str(e)}"
    
    def validate_domain(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Validate domain name
        
        Args:
            domain: Domain name string
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Basic length check
        if len(domain) > 253:
            return False, "Domain name too long (max 253 characters)"
        
        # Check pattern
        if not self.domain_pattern.match(domain):
            return False, "Invalid domain format"
        
        # Check for suspicious patterns
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            # Just a warning, not invalid
            pass
        
        return True, None
    
    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Validate URL
        
        Args:
            url: URL string
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            result = urlparse(url)
            
            # Must have scheme and netloc
            if not result.scheme or not result.netloc:
                return False, "URL must have scheme (http/https) and domain"
            
            # Check scheme
            if result.scheme not in ['http', 'https', 'ftp']:
                return False, "URL scheme must be http, https, or ftp"
            
            # Check length
            if len(url) > 2048:
                return False, "URL too long (max 2048 characters)"
            
            return True, None
        
        except Exception as e:
            return False, f"Invalid URL: {str(e)}"
    
    def validate_hash(self, file_hash: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validate file hash and determine type
        
        Args:
            file_hash: File hash string
            
        Returns:
            Tuple of (is_valid, error_message, hash_type)
        """
        file_hash = file_hash.strip().lower()
        
        if self.md5_pattern.match(file_hash):
            return True, None, 'md5'
        elif self.sha1_pattern.match(file_hash):
            return True, None, 'sha1'
        elif self.sha256_pattern.match(file_hash):
            return True, None, 'sha256'
        else:
            return False, "Invalid hash format (must be MD5, SHA1, or SHA256)", None
    
    def validate_email(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Validate email address
        
        Args:
            email: Email address string
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.email_pattern.match(email):
            return False, "Invalid email format"
        
        if len(email) > 254:
            return False, "Email address too long"
        
        return True, None
    
    def validate_cve(self, cve: str) -> Tuple[bool, Optional[str]]:
        """
        Validate CVE identifier
        
        Args:
            cve: CVE identifier string
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.cve_pattern.match(cve):
            return False, "Invalid CVE format (must be CVE-YYYY-NNNN)"
        
        return True, None
    
    def validate_iocs(self, iocs: Dict) -> Dict[str, List]:
        """
        Validate all IOCs in a dictionary
        
        Args:
            iocs: Dictionary of IOCs by type
            
        Returns:
            Dictionary of validation results
        """
        results = {
            'valid': {
                'ips': [],
                'domains': [],
                'urls': [],
                'hashes': [],
                'emails': [],
                'cves': []
            },
            'invalid': {
                'ips': [],
                'domains': [],
                'urls': [],
                'hashes': [],
                'emails': [],
                'cves': []
            }
        }
        
        # Validate IPs
        for ip in iocs.get('ipv4', []):
            is_valid, error = self.validate_ip(ip)
            if is_valid:
                results['valid']['ips'].append(ip)
            else:
                results['invalid']['ips'].append({'value': ip, 'error': error})
        
        # Validate domains
        for domain in iocs.get('domains', []):
            is_valid, error = self.validate_domain(domain)
            if is_valid:
                results['valid']['domains'].append(domain)
            else:
                results['invalid']['domains'].append({'value': domain, 'error': error})
        
        # Validate URLs
        for url in iocs.get('urls', []):
            is_valid, error = self.validate_url(url)
            if is_valid:
                results['valid']['urls'].append(url)
            else:
                results['invalid']['urls'].append({'value': url, 'error': error})
        
        # Validate hashes
        all_hashes = (
            iocs.get('hashes', {}).get('md5', []) +
            iocs.get('hashes', {}).get('sha1', []) +
            iocs.get('hashes', {}).get('sha256', [])
        )
        for file_hash in all_hashes:
            is_valid, error, hash_type = self.validate_hash(file_hash)
            if is_valid:
                results['valid']['hashes'].append({'value': file_hash, 'type': hash_type})
            else:
                results['invalid']['hashes'].append({'value': file_hash, 'error': error})
        
        # Validate emails
        for email in iocs.get('emails', []):
            is_valid, error = self.validate_email(email)
            if is_valid:
                results['valid']['emails'].append(email)
            else:
                results['invalid']['emails'].append({'value': email, 'error': error})
        
        # Validate CVEs
        for cve in iocs.get('cves', []):
            is_valid, error = self.validate_cve(cve)
            if is_valid:
                results['valid']['cves'].append(cve)
            else:
                results['invalid']['cves'].append({'value': cve, 'error': error})
        
        return results


class APIResponseValidator:
    """Validator for API responses"""
    
    @staticmethod
    def validate_virustotal_response(response: Dict) -> bool:
        """Validate VirusTotal API response structure"""
        try:
            if 'data' not in response:
                return False
            
            if 'attributes' not in response['data']:
                return False
            
            return True
        except (KeyError, TypeError):
            return False
    
    @staticmethod
    def validate_abuseipdb_response(response: Dict) -> bool:
        """Validate AbuseIPDB API response structure"""
        try:
            if 'data' not in response:
                return False
            
            required_fields = ['abuseConfidenceScore', 'countryCode']
            return all(field in response['data'] for field in required_fields)
        except (KeyError, TypeError):
            return False
    
    @staticmethod
    def validate_gemini_response(response: Dict) -> bool:
        """Validate Gemini API response structure"""
        try:
            if 'content' not in response:
                return False
            
            return True
        except (KeyError, TypeError):
            return False


class SecurityValidator:
    """Additional security validations"""
    
    @staticmethod
    def is_safe_for_processing(text: str) -> Tuple[bool, Optional[str]]:
        """
        Check if text is safe to process
        
        Args:
            text: Text to check
            
        Returns:
            Tuple of (is_safe, warning_message)
        """
        # Check for extremely large inputs (DoS protection)
        if len(text) > 100000:  # 100KB
            return False, "Input too large, possible DoS attempt"
        
        # Check for excessive repetition (another DoS vector)
        if len(set(text)) < len(text) * 0.05:  # Less than 5% unique characters
            return False, "Input has excessive repetition"
        
        # Check for null bytes
        if '\x00' in text:
            return False, "Input contains null bytes"
        
        return True, None
    
    @staticmethod
    def check_rate_limit(user_id: str, max_requests: int = 10, 
                        time_window: int = 60) -> bool:
        """
        Check if user has exceeded rate limit
        
        Args:
            user_id: User identifier
            max_requests: Maximum requests allowed
            time_window: Time window in seconds
            
        Returns:
            True if within limit, False if exceeded
        """
        # This would be implemented with Redis or similar in production
        # For now, always return True
        return True


# Convenience functions
def validate_alert(alert_text: str) -> Tuple[bool, Optional[str]]:
    """Quick validation of alert text"""
    validator = InputValidator()
    return validator.validate_alert_text(alert_text)


def validate_ioc_list(iocs: Dict) -> Dict:
    """Quick validation of IOC list"""
    validator = IOCValidator()
    return validator.validate_iocs(iocs)


# Example usage
if __name__ == "__main__":
    # Test validators
    input_validator = InputValidator()
    ioc_validator = IOCValidator()
    
    # Test alert validation
    alert = "Test security alert from 192.168.1.1"
    is_valid, error = input_validator.validate_alert_text(alert)
    print(f"Alert valid: {is_valid}, Error: {error}")
    
    # Test IP validation
    ip = "192.168.1.1"
    is_valid, error = ioc_validator.validate_ip(ip)
    print(f"IP valid: {is_valid}, Error: {error}")
    
    # Test domain validation
    domain = "example.com"
    is_valid, error = ioc_validator.validate_domain(domain)
    print(f"Domain valid: {is_valid}, Error: {error}")
    
    # Test hash validation
    hash_val = "44d88612fea8a8f36de82e1278abb02f"
    is_valid, error, hash_type = ioc_validator.validate_hash(hash_val)
    print(f"Hash valid: {is_valid}, Type: {hash_type}, Error: {error}")
    
    # Test CVE validation
    cve = "CVE-2024-1234"
    is_valid, error = ioc_validator.validate_cve(cve)
    print(f"CVE valid: {is_valid}, Error: {error}")
