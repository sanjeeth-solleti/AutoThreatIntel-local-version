"""
Utility modules for ThreatLens

This package contains utility functions for:
- parsers: Parse different log formats
- validators: Validate user inputs and IOCs
"""

from .parsers import (
    UniversalLogParser,
    SyslogParser,
    FirewallLogParser,
    WindowsEventLogParser,
    IDSAlertParser,
    EDRAlertParser,
    extract_structured_data,
    parse_log_file
)

from .validators import (
    InputValidator,
    IOCValidator,
    APIResponseValidator,
    SecurityValidator,
    ValidationError,
    validate_alert,
    validate_ioc_list
)

__all__ = [
    # Parsers
    'UniversalLogParser',
    'SyslogParser',
    'FirewallLogParser',
    'WindowsEventLogParser',
    'IDSAlertParser',
    'EDRAlertParser',
    'extract_structured_data',
    'parse_log_file',
    
    # Validators
    'InputValidator',
    'IOCValidator',
    'APIResponseValidator',
    'SecurityValidator',
    'ValidationError',
    'validate_alert',
    'validate_ioc_list',
]
