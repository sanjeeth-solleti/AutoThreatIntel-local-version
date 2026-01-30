import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Configuration class for API keys and settings"""
    
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'True') == 'True'
    
    # API Keys
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
    
    # API Endpoints
    VIRUSTOTAL_BASE_URL = 'https://www.virustotal.com/api/v3'
    ABUSEIPDB_BASE_URL = 'https://api.abuseipdb.com/api/v2'
    URLHAUS_BASE_URL = 'https://urlhaus-api.abuse.ch/v1'
    PHISHTANK_BASE_URL = 'https://checkurl.phishtank.com/checkurl/'
    NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    
    # Rate Limiting
    MAX_REQUESTS_PER_MINUTE = 60
    
    # Analysis Settings
    MAX_ALERT_LENGTH = 50000  # Maximum characters in alert
    TIMEOUT_SECONDS = 120  # API timeout
