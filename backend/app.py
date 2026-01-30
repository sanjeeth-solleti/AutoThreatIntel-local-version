from flask import Flask, request, jsonify
from flask_cors import CORS
from config import Config
from services.ioc_extractor import IOCExtractor
from services.gemini_service import GeminiService
from services.threat_intel import ThreatIntelligence
from services.report_generator import ReportGenerator
import traceback

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize services
ioc_extractor = IOCExtractor()
report_generator = ReportGenerator()

# Initialize services that require API keys
try:
    gemini_service = GeminiService(Config.GEMINI_API_KEY) if Config.GEMINI_API_KEY else None
    threat_intel = ThreatIntelligence(Config)
except Exception as e:
    print(f"Warning: Could not initialize services: {e}")
    gemini_service = None
    threat_intel = None

@app.route('/')
def index():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'service': 'ThreatLens Threat Intelligence Analyzer',
        'version': '1.0.0',
        'services': {
            'gemini': gemini_service is not None,
            'threat_intel': threat_intel is not None
        }
    })

@app.route('/api/analyze', methods=['POST'])
def analyze_alert():
    """
    Main endpoint to analyze security alerts
    
    Expected JSON body:
    {
        "alert_text": "Security alert text to analyze"
    }
    
    Returns:
    {
        "status": "success",
        "report": {...}  # Complete threat intelligence report
    }
    """
    try:
        # Get alert text from request
        data = request.get_json()
        if not data or 'alert_text' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Missing alert_text in request body'
            }), 400
        
        alert_text = data['alert_text']
        
        # Validate alert text
        if not alert_text or len(alert_text.strip()) == 0:
            return jsonify({
                'status': 'error',
                'message': 'Alert text cannot be empty'
            }), 400
        
        if len(alert_text) > Config.MAX_ALERT_LENGTH:
            return jsonify({
                'status': 'error',
                'message': f'Alert text too long (max {Config.MAX_ALERT_LENGTH} characters)'
            }), 400
        
        # Check if services are initialized
        if not gemini_service:
            return jsonify({
                'status': 'error',
                'message': 'Gemini AI service not configured. Please add GEMINI_API_KEY to .env file'
            }), 503
        
        print(f"\n{'='*60}")
        print(f"ANALYZING NEW ALERT")
        print(f"{'='*60}")
        
        # Step 1: Extract IOCs using regex
        print("\n[1/5] Extracting IOCs...")
        iocs = ioc_extractor.extract_iocs(alert_text)
        ioc_summary = ioc_extractor.get_ioc_summary(iocs)
        print(f"  Found: {ioc_summary['total_ips']} IPs, {ioc_summary['total_domains']} domains, "
              f"{ioc_summary['total_hashes']} hashes, {ioc_summary['total_cves']} CVEs")
        
        # Step 2: Parse alert with Gemini AI
        print("\n[2/5] Parsing alert context with Gemini AI...")
        alert_context = gemini_service.parse_alert(alert_text, iocs)
        print(f"  Alert Type: {alert_context.get('alert_type')}")
        print(f"  Severity: {alert_context.get('severity')}")
        
        # Step 3: Query threat intelligence APIs
        print("\n[3/5] Querying threat intelligence sources...")
        threat_data = threat_intel.analyze_iocs(iocs)
        print(f"  Malicious IPs: {threat_data.get('summary', {}).get('total_malicious_ips', 0)}")
        print(f"  Malicious Domains: {threat_data.get('summary', {}).get('total_malicious_domains', 0)}")
        print(f"  Malicious Hashes: {threat_data.get('summary', {}).get('total_malicious_hashes', 0)}")
        
        # Step 4: Comprehensive analysis with Gemini
        print("\n[4/5] Performing comprehensive analysis with Gemini AI...")
        gemini_analysis = gemini_service.analyze_threat_intelligence(iocs, threat_data)
        print(f"  Risk Score: {gemini_analysis.get('risk_score')}/100")
        print(f"  Threat Classification: {gemini_analysis.get('threat_classification')}")
        
        # Step 5: Generate final report
        print("\n[5/5] Generating threat intelligence report...")
        report = report_generator.generate_report(
            alert_text, iocs, alert_context, threat_data, gemini_analysis
        )
        
        # Generate firewall rules if there are malicious IPs/domains
        if report['blocking_rules']['malicious_ips'] or report['blocking_rules']['malicious_domains']:
            print("\n[BONUS] Generating firewall rules...")
            firewall_rules = gemini_service.generate_firewall_rules(
                report['blocking_rules']['malicious_ips'],
                report['blocking_rules']['malicious_domains']
            )
            report['firewall_rules'] = firewall_rules
        
        print(f"\n{'='*60}")
        print(f"ANALYSIS COMPLETE")
        print(f"Threat Level: {report['summary']['threat_level']}")
        print(f"Risk Score: {report['summary']['risk_score']}/100")
        print(f"{'='*60}\n")
        
        return jsonify({
            'status': 'success',
            'report': report
        })
    
    except Exception as e:
        print(f"\nERROR during analysis: {str(e)}")
        print(traceback.format_exc())
        return jsonify({
            'status': 'error',
            'message': f'Analysis failed: {str(e)}'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Detailed health check endpoint"""
    services_status = {
        'gemini_ai': {
            'configured': gemini_service is not None,
            'status': 'operational' if gemini_service else 'not configured'
        },
        'threat_intelligence': {
            'configured': threat_intel is not None,
            'virustotal': bool(Config.VIRUSTOTAL_API_KEY),
            'abuseipdb': bool(Config.ABUSEIPDB_API_KEY),
            'shodan': bool(Config.SHODAN_API_KEY)
        }
    }
    
    all_operational = (
        gemini_service is not None and
        (Config.VIRUSTOTAL_API_KEY or Config.ABUSEIPDB_API_KEY)
    )
    
    return jsonify({
        'status': 'healthy' if all_operational else 'degraded',
        'services': services_status,
        'message': 'All systems operational' if all_operational else 'Some services not configured'
    })

if __name__ == '__main__':
    print("\n" + "="*60)
    print("ThreatLens Threat Intelligence Analyzer")
    print("="*60)
    print(f"Gemini AI: {'✓ Configured' if gemini_service else '✗ Not configured'}")
    print(f"VirusTotal: {'✓ Configured' if Config.VIRUSTOTAL_API_KEY else '✗ Not configured'}")
    print(f"AbuseIPDB: {'✓ Configured' if Config.ABUSEIPDB_API_KEY else '✗ Not configured'}")
    print(f"Shodan: {'✓ Configured' if Config.SHODAN_API_KEY else '✗ Not configured'}")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)

