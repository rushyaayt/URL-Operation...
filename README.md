# URL-Operation...
This repo will breakthrough and tells you what this does

## 🚀 Install tools in linux
sudo apt update;
sudo apt install nodejs npm -y;
npm install node-fetch whois-json validator;

Deliverables
Minimal Script (suspicious-url-checker.js)
javascript
// suspicious-url-checker.js
// Run: node suspicious-url-checker.js https://example.com

const dns = require('dns');
const fetch = require('node-fetch');
const whois = require('whois-json');
const validator = require('validator');

async function checkURL(url) {
  if (!validator.isURL(url)) {
    console.log("❌ Invalid URL format.");
    return;
  }

  let suspicious = [];
  const hostname = new URL(url).hostname;

  // Heuristic checks
  if (url.match(/login|verify|update/i)) suspicious.push("Phishing keyword in URL");
  if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url)) suspicious.push("Uses IP instead of domain");
  if (hostname.match(/bit\.ly|tinyurl|goo\.gl/)) suspicious.push("Shortened URL service");

  // DNS check
  try {
    await dns.promises.lookup(hostname);
  } catch {
    suspicious.push("Domain does not resolve");
  }

  // WHOIS age check
  try {
    const info = await whois(hostname);
    if (info.creationDate) {
      const ageDays = (Date.now() - new Date(info.creationDate)) / (1000*60*60*24);
      if (ageDays < 30) suspicious.push("Domain is very new");
    }
  } catch {
    suspicious.push("WHOIS lookup failed");
  }

  // Optional fetch headers
  try {
    const res = await fetch(url, { method: 'HEAD', timeout: 5000 });
    if (!res.ok) suspicious.push(`Fetch returned status ${res.status}`);
  } catch {
    suspicious.push("Fetch failed or timed out");
  }

  // Output
  if (suspicious.length === 0) {
    console.log("✅ URL appears safe (no obvious red flags).");
  } else {
    console.log("⚠️ Suspicious indicators found:");
    suspicious.forEach(reason => console.log(" - " + reason));
  }
}

// CLI usage
const inputURL = process.argv[2];
if (!inputURL) {
  console.log("Usage: node suspicious-url-checker.js <URL>");
} else {
  checkURL(inputURL);
}
Instructions to Run on Kali
Save script as suspicious-url-checker.js.

Install Node.js + dependencies:

bash
sudo apt update
sudo apt install nodejs npm -y
npm install node-fetch whois-json validator
Run:

bash
node suspicious-url-checker.js https://suspicious-example.com
Optional Enhancements
Rate limiting for WHOIS queries.

Updateable blocklists (download daily from PhishTank).

UI version with Electron or browser extension.

Risk scoring system (0–100).
