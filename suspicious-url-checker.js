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

  // Optional fetch headers (refined)
  try {
    const res = await fetch(url, { method: 'HEAD', timeout: 10000 });
    if (!res.ok) suspicious.push(`Fetch returned status ${res.status}`);
  } catch {
    console.log("ℹ️ Could not verify via fetch (timeout or blocked). Not necessarily suspicious.");
  }

  // Output
  if (suspicious.length === 0) {
    console.log("🎉 Yeah, It’s Safe ✅");
  } else {
    console.log("⚠️ Suspicious indicators found:");
    suspicious.forEach((reason, index) => {
      console.log(` ${index + 1}. ${reason}`);
    });
  }
}

// CLI usage
const inputURL = process.argv[2];
if (!inputURL) {
  console.log("Usage: node suspicious-url-checker.js <URL>");
} else {
  checkURL(inputURL);
}
