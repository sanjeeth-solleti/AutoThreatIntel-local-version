"""
Log Parsers for Different Security Alert Formats

This module provides parsers for common security log formats including:
- Syslog
- Windows Event Logs
- Firewall logs
- IDS/IPS alerts
- EDR alerts
"""

import re
from datetime import datetime
from typing import Dict, Optional, List


class LogParser:
    """Base class for log parsers"""
    
    def __init__(self):
        pass
    
    def parse(self, log_text: str) -> Dict:
        """Parse log text and return structured data"""
        raise NotImplementedError("Subclasses must implement parse()")


class SyslogParser(LogParser):
    """Parse standard Syslog format"""
    
    def __init__(self):
        super().__init__()
        # Syslog pattern: <priority>timestamp hostname process[pid]: message
        self.pattern = re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.+)'
        )
    
    def parse(self, log_text: str) -> Dict:
        """
        Parse syslog format
        
        Example:
        Jan 29 14:23:45 firewall sshd[1234]: Failed password for root from 192.168.1.1
        """
        match = self.pattern.search(log_text)
        
        if match:
            return {
                'format': 'syslog',
                'timestamp': match.group('timestamp'),
                'hostname': match.group('hostname'),
                'process': match.group('process'),
                'pid': match.group('pid'),
                'message': match.group('message'),
                'raw': log_text
            }
        
        return {
            'format': 'unknown',
            'raw': log_text
        }


class FirewallLogParser(LogParser):
    """Parse common firewall log formats"""
    
    def __init__(self):
        super().__init__()
        # Pattern for firewall logs
        self.patterns = [
            # Cisco ASA format
            re.compile(
                r'%ASA-(?P<severity>\d)-(?P<code>\d+):\s+(?P<action>\w+)\s+'
                r'(?P<protocol>\w+)\s+src\s+(?P<src_interface>\S+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+)\s+'
                r'dst\s+(?P<dst_interface>\S+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)'
            ),
            # Generic firewall format
            re.compile(
                r'(?P<action>ACCEPT|DENY|DROP|REJECT|BLOCK)\s+'
                r'(?P<protocol>TCP|UDP|ICMP)\s+'
                r'(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s*->\s*'
                r'(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)'
            ),
            # Another common format
            re.compile(
                r'(?P<action>blocked|allowed|denied)\s+connection\s+from\s+'
                r'(?P<src_ip>[\d.]+)\s+to\s+(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)',
                re.IGNORECASE
            )
        ]
    
    def parse(self, log_text: str) -> Dict:
        """Parse firewall logs"""
        for pattern in self.patterns:
            match = pattern.search(log_text)
            if match:
                result = {
                    'format': 'firewall',
                    'action': match.group('action'),
                    'src_ip': match.group('src_ip'),
                    'dst_ip': match.group('dst_ip'),
                    'raw': log_text
                }
                
                # Add optional fields
                if 'protocol' in match.groupdict():
                    result['protocol'] = match.group('protocol')
                if 'src_port' in match.groupdict():
                    result['src_port'] = match.group('src_port')
                if 'dst_port' in match.groupdict():
                    result['dst_port'] = match.group('dst_port')
                if 'severity' in match.groupdict():
                    result['severity'] = match.group('severity')
                
                return result
        
        return {'format': 'unknown', 'raw': log_text}


class WindowsEventLogParser(LogParser):
    """Parse Windows Event Log format"""
    
    def __init__(self):
        super().__init__()
        self.event_id_pattern = re.compile(r'Event\s+ID:\s*(?P<event_id>\d+)', re.IGNORECASE)
        self.source_pattern = re.compile(r'Source:\s*(?P<source>[^\n]+)', re.IGNORECASE)
        self.level_pattern = re.compile(r'Level:\s*(?P<level>Information|Warning|Error|Critical)', re.IGNORECASE)
    
    def parse(self, log_text: str) -> Dict:
        """Parse Windows Event Log format"""
        result = {
            'format': 'windows_event',
            'raw': log_text
        }
        
        # Extract Event ID
        event_id_match = self.event_id_pattern.search(log_text)
        if event_id_match:
            result['event_id'] = event_id_match.group('event_id')
        
        # Extract Source
        source_match = self.source_pattern.search(log_text)
        if source_match:
            result['source'] = source_match.group('source').strip()
        
        # Extract Level
        level_match = self.level_pattern.search(log_text)
        if level_match:
            result['level'] = level_match.group('level')
        
        return result


class IDSAlertParser(LogParser):
    """Parse IDS/IPS alert formats (Snort, Suricata)"""
    
    def __init__(self):
        super().__init__()
        # Snort alert format
        self.snort_pattern = re.compile(
            r'\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
            r'(?P<message>.+?)\s+'
            r'\[Classification:\s*(?P<classification>[^\]]+)\]\s+'
            r'\[Priority:\s*(?P<priority>\d+)\]'
        )
    
    def parse(self, log_text: str) -> Dict:
        """Parse IDS alert"""
        match = self.snort_pattern.search(log_text)
        
        if match:
            return {
                'format': 'ids_alert',
                'signature_id': match.group('sid'),
                'generator_id': match.group('gid'),
                'revision': match.group('rev'),
                'message': match.group('message'),
                'classification': match.group('classification'),
                'priority': match.group('priority'),
                'raw': log_text
            }
        
        return {'format': 'unknown', 'raw': log_text}


class EDRAlertParser(LogParser):
    """Parse EDR (Endpoint Detection and Response) alerts"""
    
    def __init__(self):
        super().__init__()
        self.process_pattern = re.compile(
            r'Process:\s*(?P<process>[^\n]+)',
            re.IGNORECASE
        )
        self.command_pattern = re.compile(
            r'Command(?:\s+Line)?:\s*(?P<command>[^\n]+)',
            re.IGNORECASE
        )
        self.user_pattern = re.compile(
            r'User:\s*(?P<user>[^\n]+)',
            re.IGNORECASE
        )
        self.parent_process_pattern = re.compile(
            r'Parent\s+Process:\s*(?P<parent>[^\n]+)',
            re.IGNORECASE
        )
    
    def parse(self, log_text: str) -> Dict:
        """Parse EDR alert"""
        result = {
            'format': 'edr_alert',
            'raw': log_text
        }
        
        # Extract process
        process_match = self.process_pattern.search(log_text)
        if process_match:
            result['process'] = process_match.group('process').strip()
        
        # Extract command line
        command_match = self.command_pattern.search(log_text)
        if command_match:
            result['command_line'] = command_match.group('command').strip()
        
        # Extract user
        user_match = self.user_pattern.search(log_text)
        if user_match:
            result['user'] = user_match.group('user').strip()
        
        # Extract parent process
        parent_match = self.parent_process_pattern.search(log_text)
        if parent_match:
            result['parent_process'] = parent_match.group('parent').strip()
        
        return result


class UniversalLogParser:
    """
    Universal parser that tries multiple formats
    """
    
    def __init__(self):
        self.parsers = [
            SyslogParser(),
            FirewallLogParser(),
            WindowsEventLogParser(),
            IDSAlertParser(),
            EDRAlertParser()
        ]
    
    def parse(self, log_text: str) -> Dict:
        """
        Try to parse log with all available parsers
        
        Args:
            log_text: Raw log text
            
        Returns:
            Parsed log data with format information
        """
        # Try each parser
        for parser in self.parsers:
            result = parser.parse(log_text)
            if result.get('format') != 'unknown':
                return result
        
        # If no parser matched, return generic result
        return {
            'format': 'generic',
            'raw': log_text
        }
    
    def parse_multiple(self, log_lines: List[str]) -> List[Dict]:
        """
        Parse multiple log lines
        
        Args:
            log_lines: List of log lines
            
        Returns:
            List of parsed log data
        """
        return [self.parse(line) for line in log_lines if line.strip()]


def extract_structured_data(log_text: str) -> Dict:
    """
    Extract structured data from any log format
    
    Args:
        log_text: Raw log text
        
    Returns:
        Structured data dictionary
    """
    parser = UniversalLogParser()
    return parser.parse(log_text)


def parse_log_file(file_path: str) -> List[Dict]:
    """
    Parse an entire log file
    
    Args:
        file_path: Path to log file
        
    Returns:
        List of parsed log entries
    """
    parser = UniversalLogParser()
    parsed_logs = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip():
                    parsed = parser.parse(line)
                    parsed_logs.append(parsed)
    except Exception as e:
        print(f"Error parsing log file: {e}")
    
    return parsed_logs


# Example usage
if __name__ == "__main__":
    # Test different log formats
    
    # Syslog
    syslog = "Jan 29 14:23:45 firewall sshd[1234]: Failed password for root from 192.168.1.1"
    print("Syslog:", SyslogParser().parse(syslog))
    
    # Firewall
    firewall = "blocked connection from 192.168.1.100 to 10.0.0.50:443"
    print("Firewall:", FirewallLogParser().parse(firewall))
    
    # Windows Event
    win_event = "Event ID: 4625\nSource: Microsoft-Windows-Security-Auditing\nLevel: Warning"
    print("Windows:", WindowsEventLogParser().parse(win_event))
    
    # Universal parser
    parser = UniversalLogParser()
    print("\nUniversal Parser:")
    print(parser.parse(syslog))
    print(parser.parse(firewall))
