# API Keys Setup Guide

This guide will help you obtain the necessary API keys for ThreatLens.

## Required API Keys

### 1. Google Gemini API Key (REQUIRED)

**Purpose:** Powers the AI analysis and threat correlation

**How to get it:**
1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Click "Get API Key"
4. Click "Create API Key" 
5. Copy the generated API key
6. Paste it into your `.env` file as `GEMINI_API_KEY=your-key-here`

**Free Tier:** 60 requests per minute, which is sufficient for most use cases

---

## Recommended API Keys

### 2. VirusTotal API Key (RECOMMENDED)

**Purpose:** Check reputation of IPs, domains, URLs, and file hashes

**How to get it:**
1. Go to [VirusTotal](https://www.virustotal.com/)
2. Create a free account or sign in
3. Go to your [API Key page](https://www.virustotal.com/gui/my-apikey)
4. Copy your API key
5. Paste it into your `.env` file as `VIRUSTOTAL_API_KEY=your-key-here`

**Free Tier:** 4 requests per minute, 500 requests per day

---

### 3. AbuseIPDB API Key (RECOMMENDED)

**Purpose:** Check IP reputation and abuse reports

**How to get it:**
1. Go to [AbuseIPDB](https://www.abuseipdb.com/)
2. Create a free account
3. Go to [API page](https://www.abuseipdb.com/account/api)
4. Copy your API key
5. Paste it into your `.env` file as `ABUSEIPDB_API_KEY=your-key-here`

**Free Tier:** 1,000 requests per day

---

## Optional API Keys

### 4. Shodan API Key (OPTIONAL)

**Purpose:** Get information about exposed services and ports

**How to get it:**
1. Go to [Shodan](https://www.shodan.io/)
2. Create an account
3. Go to [Account page](https://account.shodan.io/)
4. Copy your API key under "API Key"
5. Paste it into your `.env` file as `SHODAN_API_KEY=your-key-here`

**Free Tier:** 100 results per month (paid plans available)

---

## Setting Up Your Environment

1. Navigate to the backend directory:
   ```bash
   cd threat-intelligence-tool/backend
   ```

2. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

3. Edit the `.env` file and add your API keys:
   ```bash
   nano .env
   # or use any text editor
   ```

4. Your `.env` file should look like this:
   ```env
   GEMINI_API_KEY=AIzaSyC...your-actual-key...
   VIRUSTOTAL_API_KEY=abc123...your-actual-key...
   ABUSEIPDB_API_KEY=xyz789...your-actual-key...
   SHODAN_API_KEY=optional-key-here
   ```

5. Save the file

## Testing Your Setup

Once you've added your API keys, test the backend:

```bash
cd backend
python3 app.py
```

You should see:
```
ThreatLens Threat Intelligence Analyzer
====================================================
Gemini AI: ✓ Configured
VirusTotal: ✓ Configured
AbuseIPDB: ✓ Configured
Shodan: ✗ Not configured
====================================================
```

## Rate Limits Summary

| Service | Free Tier Limit | Notes |
|---------|----------------|-------|
| Gemini | 60 req/min | Sufficient for analysis |
| VirusTotal | 4 req/min, 500/day | May need to pace requests |
| AbuseIPDB | 1,000 req/day | Good for most use cases |
| Shodan | 100 results/month | Optional, for advanced users |

## Tips

1. **Start with minimum keys:** Only Gemini is required to start. Add others as needed.
2. **Monitor usage:** Keep track of your API usage to avoid hitting limits
3. **Rate limiting:** The tool automatically paces requests to avoid hitting rate limits
4. **Upgrade if needed:** Consider paid tiers if you analyze many alerts daily

## Troubleshooting

**"Gemini API service not configured"**
- Make sure your `GEMINI_API_KEY` is set in the `.env` file
- Verify the key is valid by checking the Google AI Studio

**"VirusTotal rate limit exceeded"**
- Free tier has 4 requests per minute
- Wait a minute and try again
- Consider upgrading to a paid plan for higher limits

**"Connection errors"**
- Check your internet connection
- Verify the API keys are correct
- Make sure you haven't exceeded rate limits
