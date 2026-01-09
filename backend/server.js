const express = require("express");
const cors = require("cors");
const psl = require("psl");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());

// Configure multer for file uploads (in-memory storage for simplicity)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 }, // 100 MB limit
});

// Default third-party keys (fallback to provided values if env vars not set)
// VirusTotal and Azure OpenAI configuration should come from environment variables.
// Do NOT hardcode API keys here. If keys are missing we'll log a warning and return
// a useful JSON response from the file analyze endpoint.
const VT_KEYS_CSV = process.env.VIRUSTOTAL_API_KEYS || process.env.VIRUSTOTAL_API_KEY || '';
if (!VT_KEYS_CSV) {
  console.warn('⚠️ VirusTotal API key(s) not configured. Set VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEYS.');
}

const AZURE_OPENAI_ENDPOINT = process.env.AZURE_OPENAI_ENDPOINT || null;
const AZURE_OPENAI_API_KEY = process.env.AZURE_OPENAI_API_KEY || null;
const AZURE_OPENAI_DEPLOYMENT = process.env.AZURE_OPENAI_DEPLOYMENT || null;
const AZURE_OPENAI_API_VERSION = process.env.AZURE_OPENAI_API_VERSION || null;

/* --------------------------------------------------
   RISK LEVELS CONSTANT
-------------------------------------------------- */

const RISK = { 
  LOW: "LOW", 
  MEDIUM: "MEDIUM", 
  HIGH: "HIGH", 
  CRITICAL: "CRITICAL" 
};

/* --------------------------------------------------
   LOCAL PHISHING DATABASE
-------------------------------------------------- */

const KNOWN_PHISHING_DOMAINS = [
  "bio.site",
  "linktr.ee",
  "beacons.ai",
  "linktree.com",
  "myshopify.com",
  "github.io",
  "herokuapp.com",
  "wordpress.com",
  "wix.com",
  "weebly.com",
  "tumblr.com",
  "blogger.com",
  "pages.github.io",
  "surge.sh",
  "netlify.com",
  "vercel.app",
  "firebase.app",
  "azurewebsites.net",
  "pythonanywhere.com",
  "glitch.me",
  "replit.com",
  // Extracted from PhishTank feed
  "activacionoffice.iceiy.com",
  "futurebits.in",
  "marcus89c.com",
  "2tuggd33rgcg.github.io",
  "kavqero.com",
  "ln.run",
  "finnafaoecav.cc",
  "dnan.jksd.bar",
  "finnafaoesoisad.cc",
  "t.co",
  "scarabjourney.work"
];

/* --------------------------------------------------
   GLOBAL HELPERS
-------------------------------------------------- */

function calculateDomainAgeRisk(domainAgeDays) {
  if (domainAgeDays < 30) return 40;
  if (domainAgeDays < 180) return 20;
  if (domainAgeDays < 365) return 10;
  return -20;
}

/* --------------------------------------------------
   VIRUSTOTAL FILE SCANNING
-------------------------------------------------- */

// Upload file to VirusTotal and get analysis ID
async function uploadFileToVirusTotal(fileBuffer, fileName) {
  const keysCsv = VT_KEYS_CSV || '';
  const keys = keysCsv.split(',').map(k => k.trim()).filter(Boolean);

  if (!keys.length) {
    console.warn("⚠️ VirusTotal API key(s) not configured");
    return null;
  }

  try {
    console.log(`📤 Uploading file to VirusTotal: ${fileName} (${(fileBuffer.length / 1024).toFixed(2)} KB)`);

    const FormData = require('form-data');
    
    let response = null;
    let usedKeyIndex = -1;
    let lastError = null;

    // Try each key until one succeeds
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      try {
        const form = new FormData();
        form.append('file', fileBuffer, fileName);

        console.log(`  Trying API key index ${i}...`);

        // Add timeout to fetch (30 seconds)
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30000);

        try {
          response = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: {
              'x-apikey': key,
              ...form.getHeaders(),
            },
            body: form,
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timeout);
        }

        if (response && response.ok) {
          usedKeyIndex = i;
          console.log(`✓ File uploaded successfully using key index ${i}`);
          break;
        }

        const statusText = response ? `status=${response.status}` : 'no-response';
        lastError = statusText;
        console.warn(`  ⚠️ Key index ${i} failed: ${statusText}`);
      } catch (e) {
        lastError = e.message || e.name;
        if (lastError.includes('abort')) {
          console.warn(`  ⚠️ Key index ${i} timeout (30s)`);
        } else {
          console.warn(`  ⚠️ Key index ${i} error: ${lastError}`);
        }
      }
    }

    if (!response || !response.ok) {
      console.warn(`⚠️ VirusTotal file upload failed: ${lastError}`);
      return null;
    }

    const data = await response.json();
    const analysisId = data?.data?.id;
    console.log(`✓ Got analysis ID: ${analysisId}`);
    return { analysisId, usedKeyIndex };
  } catch (err) {
    console.warn('⚠️ VirusTotal file upload error:', err.message);
    return null;
  }
}

// Poll VirusTotal analysis result with exponential backoff
async function pollVirusTotalAnalysis(analysisId, apiKeyIndex = 0) {
  const keysCsv = VT_KEYS_CSV || '';
  const keys = keysCsv.split(',').map(k => k.trim()).filter(Boolean);

  if (!keys.length || apiKeyIndex >= keys.length) {
    return null;
  }

  const key = keys[apiKeyIndex];
  const maxAttempts = 30; // Poll for up to ~5 minutes with exponential backoff
  let attempt = 0;
  let delay = 1000; // Start with 1 second

  return new Promise((resolve) => {
    const poll = async () => {
      try {
        const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          method: 'GET',
          headers: { 'x-apikey': key },
        });

        if (!response.ok) {
          console.warn(`⚠️ VirusTotal analysis poll failed: ${response.status}`);
          return resolve(null);
        }

        const data = await response.json();
        const status = data?.data?.attributes?.status;

        console.log(`🔍 Analysis status (attempt ${attempt + 1}/${maxAttempts}): ${status}`);

        if (status === 'completed') {
          console.log('✓ Analysis completed');
          return resolve(data.data);
        }

        if (attempt >= maxAttempts) {
          console.warn('⚠️ Analysis polling timeout');
          return resolve(null);
        }

        attempt++;
        delay = Math.min(delay * 1.5, 5000); // Exponential backoff, max 5 seconds
        setTimeout(poll, delay);
      } catch (err) {
        console.warn('⚠️ Polling error:', err.message);
        resolve(null);
      }
    };

    poll();
  });
}

// Extract VirusTotal file analysis results
function extractVirusTotalFileAnalysis(analysisData) {
  const stats = analysisData?.attributes?.stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  const total = malicious + suspicious + harmless + undetected;

  const detectionRate = total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0;

  // Collect flagged vendor names
  const flaggedVendors = [];
  try {
    const results = analysisData?.attributes?.last_analysis_results || {};
    for (const [engine, info] of Object.entries(results)) {
      if (!info) continue;
      const category = String(info.category || '').toLowerCase();
      if (category === 'malicious' || category === 'suspicious') {
        flaggedVendors.push(engine);
      }
    }
  } catch (e) {}

  return {
    malicious,
    suspicious,
    harmless,
    totalEngines: total,
    detectionRate,
    detectionPercentage: detectionRate,
    flaggedVendors: flaggedVendors.slice(0, 10), // Limit to top 10
    vendorFlagCount: flaggedVendors.length,
  };
}

/* --------------------------------------------------
   VIRUSTOTAL INTEGRATION
   -------------------------------------------------- */

// Encode URL to base64 URL-safe format for VirusTotal API
function encodeURLForVirusTotal(url) {
  // VirusTotal requires base64-encoded URL (URL-safe, no padding)
  const base64 = Buffer.from(url).toString("base64");
  // Convert to URL-safe: replace + with -, / with _, remove padding
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// Fetch VirusTotal URL reputation data
async function fetchVirusTotalReputation(url) {
  const keysCsv = VT_KEYS_CSV || '';
  const keys = keysCsv.split(',').map(k => k.trim()).filter(Boolean);

  if (!keys.length) {
    console.warn("⚠️ VirusTotal API key(s) not configured, skipping VT check");
    return null;
  }

  try {
    // Normalize and encode URL for VirusTotal
    const normalizedUrl = url.startsWith("http") ? url : `https://${url}`;
    const urlId = encodeURLForVirusTotal(normalizedUrl);

    console.log("🔍 Checking VirusTotal for:", normalizedUrl);

    let response = null;
    let usedKeyIndex = -1;
    let lastError = null;

    // Try each key until one succeeds (fallback / rotation)
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      try {
        response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
          method: "GET",
          headers: { 'x-apikey': key },
        });

        if (response && response.ok) {
          usedKeyIndex = i;
          console.log(`🧾 VirusTotal: request succeeded using key index ${i}`);
          break;
        }

        // record error and try next
        lastError = `status=${response ? response.status : 'no-response'}`;
        console.warn(`⚠️ VirusTotal key index ${i} failed: ${lastError}`);
      } catch (e) {
        lastError = e.message;
        console.warn(`⚠️ VirusTotal key index ${i} error: ${e.message}`);
      }
    }

    if (!response || !response.ok) {
      if (response && response.status === 404) {
        console.log("✓ VirusTotal: URL not found in database (clean)");
        return {
          malicious: 0,
          suspicious: 0,
          harmless: 0,
          undetected: 0,
          timeout: 0,
          detectionPercentage: 0,
          usedKeyIndex,
        };
      }
      console.warn(`⚠️ VirusTotal API error (all keys tried): ${lastError}`);
      return null;
    }

    const data = await response.json();
    const attrs = data?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const timeout = stats.timeout || 0;
    const total = malicious + suspicious + harmless + undetected + timeout;

    // Collect vendor names that flagged the URL (malicious or suspicious)
    const flaggedVendors = [];
    try {
      const results = attrs.last_analysis_results || {};
      for (const [engine, info] of Object.entries(results)) {
        if (!info) continue;
        const category = String(info.category || '').toLowerCase();
        if (category === 'malicious' || category === 'suspicious') {
          flaggedVendors.push(engine);
        }
      }
    } catch (e) {
      // ignore
    }

    const maliciousPercent = total > 0 ? Math.round((malicious / total) * 100) : 0;

    const vtData = {
      malicious,
      suspicious,
      harmless,
      totalEngines: total,
      detectionPercentage: total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0,
      maliciousPercent,
      flaggedVendors,
      vendorFlagCount: flaggedVendors.length,
      maliciousCount: malicious,
      suspiciousCount: suspicious,
      raw: data,
      usedKeyIndex,
    };

    console.log("✓ VirusTotal data:", vtData);
    return vtData;
  } catch (err) {
    console.warn("⚠️ VirusTotal check failed:", err.message);
    // Fail gracefully - do not break the analysis
    return null;
  }
}

// Escalate risk based on VirusTotal findings
function escalateRiskFromVirusTotal(currentRisk, vtData) {
  if (!vtData) return currentRisk;

  const { malicious, suspicious } = vtData;

  // CRITICAL: 3+ malicious detections
  if (malicious >= 3) {
    console.log("🚨 VirusTotal escalation: CRITICAL (malicious >= 3)");
    return RISK.CRITICAL;
  }

  // HIGH: 1+ malicious OR 3+ suspicious
  if (malicious >= 1 || suspicious >= 3) {
    console.log("⚠️ VirusTotal escalation: HIGH (malicious >= 1 or suspicious >= 3)");
    if (currentRisk === RISK.CRITICAL) return RISK.CRITICAL; // Never downgrade
    return RISK.HIGH;
  }

  // Otherwise, keep existing risk (never reduce)
  return currentRisk;
}

/* --------------------------------------------------
   AZURE INTEGRATIONS (Content Safety + OpenAI)
   - Content Safety: used to surface scam/coercion/threat signals
   - Azure OpenAI: used only to generate an explanation (HIGH/CRITICAL)
-------------------------------------------------- */

async function analyzeWithAzureContentSafety(text) {
  const endpoint = process.env.AZURE_CONTENT_SAFETY_ENDPOINT;
  const key = process.env.AZURE_CONTENT_SAFETY_KEY || process.env.AZURE_CONTENT_SAFETY_API_KEY;

  const defaultResult = { scamScore: 0, coercionScore: 0, threatScore: 0, raw: null };
  if (!endpoint || !key) {
    console.warn('⚠️ Azure Content Safety not configured, skipping');
    return defaultResult;
  }

  try {
    const url = endpoint.replace(/\/$/, '') + '/contentSafety:analyze?api-version=2024-06-01';
    const body = { input: String(text || '') };

    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': key,
      },
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      console.warn(`⚠️ Azure Content Safety returned ${resp.status}`);
      return defaultResult;
    }

    const data = await resp.json();

    // Defensive parsing: try to find indicators in common shapes
    const rawStr = JSON.stringify(data).toLowerCase();
    let scamScore = 0;
    let coercionScore = 0;
    let threatScore = 0;

    if (rawStr.includes('scam') || rawStr.includes('fraud') || rawStr.includes('manipulat')) scamScore = 0.9;
    if (rawStr.includes('coerc') || rawStr.includes('force') || rawStr.includes('must')) coercionScore = 0.8;
    if (rawStr.includes('threat') || rawStr.includes('kill') || rawStr.includes('violenc') || rawStr.includes('terror')) threatScore = 0.9;

    // Try to read structured fields if present (best-effort)
    try {
      if (data?.results) {
        const r = data.results[0] || data.results;
        if (r?.scales) {
          // example: r.scales.someScale?.value
          const s = JSON.stringify(r.scales).toLowerCase();
          if (s.includes('scam') && scamScore === 0) scamScore = 0.7;
          if (s.includes('coerc') && coercionScore === 0) coercionScore = 0.6;
          if (s.includes('threat') && threatScore === 0) threatScore = 0.7;
        }
      }
    } catch (e) {
      // ignore structured parse errors
    }

    return { scamScore, coercionScore, threatScore, raw: data };
  } catch (err) {
    console.warn('⚠️ Azure Content Safety error:', err.message);
    return defaultResult;
  }
}

async function callAzureOpenAIExplanation(domain, riskScore, reasons, extras = {}) {
  const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
  const key = process.env.AZURE_OPENAI_KEY || process.env.AZURE_OPENAI_API_KEY;
  const deployment = process.env.AZURE_OPENAI_DEPLOYMENT || process.env.AZURE_OPENAI_DEPLOYMENT_NAME;
  const apiVersion = process.env.AZURE_OPENAI_API_VERSION || process.env.AZURE_OPENAI_API_VERSION || '2023-10-01';

  if (!endpoint || !key || !deployment) {
    console.warn('⚠️ Azure OpenAI not configured, skipping explanation');
    return null;
  }

  try {
    const url = endpoint.replace(/\/$/, '') + `/openai/deployments/${deployment}/chat/completions?api-version=${apiVersion}`;

    // Build extras summary (VirusTotal, RDAP, HTTPS, URL) for a richer prompt
    let extrasSummary = '';
    try {
      if (extras.virusTotal) {
        const vt = extras.virusTotal;
        extrasSummary += `VirusTotal - malicious: ${vt.malicious || 0}, suspicious: ${vt.suspicious || 0}, detectionPercentage: ${vt.detectionPercentage || 0}%, vendors: ${(vt.flaggedVendors || []).slice(0,10).join(', ')}`;
      }
      if (extras.rdap) {
        const r = extras.rdap;
        extrasSummary += (extrasSummary ? '\n' : '') + `RDAP - registrar: ${r.registrar || r.registrarName || 'unknown'}, created: ${r.createdDate || r.registrationDate || 'unknown'}`;
      }
      if (extras.httpsStatus) {
        extrasSummary += (extrasSummary ? '\n' : '') + `HTTPS: ${extras.httpsStatus}`;
      }
      if (extras.url) {
        extrasSummary += (extrasSummary ? '\n' : '') + `URL: ${extras.url}`;
      }
      if (extras.phish) {
        try {
          const p = extras.phish;
          if (p.isActualPhishingDomain || p.isActual) extrasSummary += (extrasSummary ? '\n' : '') + `Phishing Feed: actual registered-domain match (${p.isActualPhishingDomain || p.isActual})`;
          if (p.isImpersonation || p.impersonation) extrasSummary += (extrasSummary ? '\n' : '') + `Phishing Feed: impersonation signals present (${p.isImpersonation || p.impersonation})`;
          if (p.phishtankInfo && p.phishtankInfo.matches) extrasSummary += (extrasSummary ? '\n' : '') + `Phish examples: ${(p.phishtankInfo.matches || p.matches || []).slice(0,5).join(', ')}`;
        } catch (e) {}
      }
    } catch (e) {
      extrasSummary = '';
    }

    const prompt = `You are a cybersecurity assistant. Explain clearly why this action is risky and include link-specific analysis when available.\nDomain: ${domain}\nRisk Score: ${riskScore}\nReasons: ${reasons.join('; ')}${extrasSummary ? `\nAdditional data:\n${extrasSummary}` : ''}\nExplain only the risk; do not provide step-by-step remediation or legal advice.`;

    const payload = {
      messages: [
        { role: 'system', content: 'You are a concise cybersecurity assistant.' },
        { role: 'user', content: prompt },
      ],
      max_tokens: 400,
      temperature: 0,
    };

    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': key,
      },
      body: JSON.stringify(payload),
    });

    if (!resp.ok) {
      console.warn(`⚠️ Azure OpenAI explanation returned ${resp.status}`);
      return null;
    }

    const data = await resp.json();
    const text = data?.choices?.[0]?.message?.content || data?.choices?.[0]?.text || null;
    return text;
  } catch (err) {
    console.warn('⚠️ Azure OpenAI explanation error:', err.message);
    return null;
  }
}



function extractExtraRdapInfo(rdapData) {
  const info = {
    registrationDate: null,
    expirationDate: null,
    lastUpdateDate: null,
    domainAgeDays: null,
  };

  // defensive: rdapData may have events array or not
  if (!Array.isArray(rdapData.events)) {
    // still try to capture status/country if available
    info.registrationDate = rdapData.registrationDate || null;
    info.lastUpdateDate = rdapData.lastUpdateDate || null;
    info.domainAgeDays = null;
    return info;
  }

  for (const event of rdapData.events) {
    if (event.eventAction === "registration")
      info.registrationDate = event.eventDate;
    if (event.eventAction === "expiration" || event.eventAction === "expiry")
      info.expirationDate = event.eventDate;
    if (
      event.eventAction === "last changed" ||
      event.eventAction === "last update"
    )
      info.lastUpdateDate = event.eventDate;
  }

  if (info.registrationDate) {
    const created = new Date(info.registrationDate);
    info.domainAgeDays = Math.floor(
      (Date.now() - created) / (1000 * 60 * 60 * 24)
    );
  }

  return info;
}

// New helper to extract richer RDAP metadata
function extractRdapMetadata(rdapData) {
  const meta = {
    registrar: null,
    createdDate: null,
    updatedDate: null,
    country: null,
    statuses: [],
    domainAgeDays: null,
  };

  try {
    // registrar from entities
    if (Array.isArray(rdapData.entities)) {
      const reg = rdapData.entities.find((e) => Array.isArray(e.roles) && e.roles.includes("registrar"));
      if (reg) {
        // vcardArray often contains a name entry
        try {
          if (Array.isArray(reg.vcardArray) && Array.isArray(reg.vcardArray[1])) {
            // attempt to find org/name
            const vals = reg.vcardArray.flat(Infinity);
            const nameIdx = vals.findIndex((v) => v === 'fn' || v === 'org');
            if (nameIdx > -1 && vals[nameIdx + 1]) meta.registrar = vals[nameIdx + 1];
          }
        } catch (e) {}
      }
    }

    // created/updated from events
    if (Array.isArray(rdapData.events)) {
      for (const ev of rdapData.events) {
        const action = String(ev.eventAction || '').toLowerCase();
        if (!meta.createdDate && action.includes('registration')) meta.createdDate = ev.eventDate || null;
        if (!meta.updatedDate && (action.includes('last') || action.includes('update'))) meta.updatedDate = ev.eventDate || null;
      }
    }

    // country
    if (rdapData.country) meta.country = rdapData.country;

    // statuses
    if (Array.isArray(rdapData.status)) meta.statuses = rdapData.status.slice(0, 5);

    // domain age
    if (meta.createdDate) {
      const created = new Date(meta.createdDate);
      meta.domainAgeDays = Math.floor((Date.now() - created) / (1000 * 60 * 60 * 24));
    }
  } catch (e) {
    // ignore parse errors
  }

  return meta;
}

function extractDomain(url) {
  try {
    const u = new URL(
      url.startsWith("http") ? url : `https://${url}`
    );
    return u.hostname.replace(/^www\./, "");
  } catch {
    return null;
  }
}

// Return the registered domain (eTLD+1) for a URL or hostname using public suffix list
function getRegisteredDomain(urlOrHost) {
  try {
    let host = urlOrHost || "";
    // If input looks like a full URL, extract hostname
    if (/^https?:\/\//i.test(host)) {
      host = new URL(host).hostname;
    }
    host = String(host).toLowerCase().replace(/^www\./, "").trim();
    const reg = psl.get(host);
    // psl.get returns null for IPs or unknowns; fall back to host
    return reg || host || null;
  } catch {
    return null;
  }
}

async function fetchRDAP(domain) {
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

async function checkPhishingFeeds(domain) {
  // Returns detailed signals: actualMatch (registered domain equals), impersonation (brand used but different registered domain)
  const normDomain = String(domain || "").toLowerCase().replace(/^www\./, "");
  const userRegistered = getRegisteredDomain(normDomain);

  let actualMatch = false;
  let impersonation = false;
  let phishtankInfo = null;
  const sampleMatches = [];

  try {
    for (const phishDomainRaw of KNOWN_PHISHING_DOMAINS) {
      const phishDomain = String(phishDomainRaw || "").toLowerCase().replace(/^www\./, "");
      const phishRegistered = getRegisteredDomain(phishDomain);

      if (!phishRegistered) continue;

      if (phishRegistered === userRegistered) {
        actualMatch = true;
        sampleMatches.push(phishDomain);
        phishtankInfo = {
          phish_id: `LOCAL_DB_${Date.now()}`,
          submission_time: new Date().toISOString(),
          verified_time: new Date().toISOString(),
          phish_detail_page: "Local Phishing Database",
          target: "Known phishing/compromised domain",
        };
        break;
      }

      // If the phish hostname contains the user's registered label (e.g., google.com.login-alert.xyz)
      if (phishDomain.includes(userRegistered)) {
        impersonation = true;
        sampleMatches.push(phishDomain);
      }
    }
  } catch (err) {
    console.warn("⚠️ Local phishing check error:", err.message);
  }

  return { actualMatch, impersonation, phishtankInfo, sampleMatches };
}

// Whitelist of legitimate/well-known domains to never flag as phishing
const LEGITIMATE_DOMAINS = [
  "google.com",
  "facebook.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "twitter.com",
  "instagram.com",
  "linkedin.com",
  "github.com",
  "gitlab.com",
  "reddit.com",
  "youtube.com",
  "netflix.com",
  "paypal.com",
  "ebay.com",
  "wikipedia.org",
  "stackoverflow.com",
  "slack.com",
  "discord.com",
  "twitch.tv",
  "dropbox.com",
  "onedrive.com",
  "icloud.com",
  "yahoo.com",
  "gmail.com",
  "outlook.com",
  "github.io",
  "pages.github.io"
];

// Try PhishTank public feed (best-effort) then fallback to local DB
async function checkPhishTank(domain) {
  // Returns: { isActual: bool, isImpersonation: bool, matches: [], source: string, details }
  const PHISHTANK_API_KEY = process.env.PHISHTANK_API_KEY;
  const normDomain = String(domain || '').toLowerCase().replace(/^www\./, '');
  const userRegistered = getRegisteredDomain(normDomain);

  console.log("🔍 checkPhishTank called with domain:", domain, "normalized:", normDomain, "registered:", userRegistered);
  if (!userRegistered) {
    return { isActual: false, isImpersonation: false, matches: [], source: null, details: null };
  }

  // Skip exact whitelisted registered domains
  if (LEGITIMATE_DOMAINS.includes(userRegistered)) {
    console.log("✓ Domain is in whitelist of legitimate domains:", userRegistered);
    return { isActual: false, isImpersonation: false, matches: [], source: null, details: null };
  }

  let isActual = false;
  let isImpersonation = false;
  const matches = [];

  try {
    const csvUrl = 'https://data.phishtank.com/data/online-valid.csv';
    const resp = await fetch(csvUrl);
    if (resp.ok) {
      const txt = await resp.text();
      const lines = txt.split('\n').slice(1);
      for (const line of lines) {
        if (!line) continue;
        // Extract URL
        const m = line.match(/https?:\/\/[^\",\s]+/i);
        let phishUrl = null;
        if (m && m[0]) phishUrl = m[0].toLowerCase().trim();
        else {
          const cols = line.split(',');
          if (cols.length > 1) {
            const candidate = cols[1].replace(/['\"]/g, '').trim();
            if (candidate) phishUrl = candidate.startsWith('http') ? candidate : `https://${candidate}`;
          }
        }

        if (!phishUrl) continue;
        try {
          const ph = new URL(phishUrl);
          const phishHost = ph.hostname.replace(/^www\./, '');
          const phishRegistered = getRegisteredDomain(phishHost);

          if (!phishRegistered) continue;

          if (phishRegistered === userRegistered) {
            isActual = true;
            matches.push(phishUrl);
            console.log(`⚠️ PhishTank CSV: actual registered-domain match -> ${phishUrl}`);
            break;
          }

          // If the phishing host contains the user registered label, treat as impersonation signal
          if (phishHost.includes(userRegistered)) {
            isImpersonation = true;
            matches.push(phishUrl);
            console.log(`⚠️ PhishTank CSV: impersonation example -> ${phishUrl}`);
          }
        } catch (e) {
          // ignore malformed URL
        }
      }
    }
  } catch (e) {
    console.warn('⚠️ PhishTank CSV fetch failed:', e.message);
  }

  if (isActual) {
    return { isActual: true, isImpersonation: false, matches, source: 'phishtank_public', details: 'Exact registered-domain match found in PhishTank' };
  }
  if (isImpersonation) {
    return { isActual: false, isImpersonation: true, matches, source: 'phishtank_public', details: 'PhishTank contains impersonation URLs' };
  }

  // fallback to local DB matching by registered domain
  try {
    for (const phishDomainRaw of KNOWN_PHISHING_DOMAINS) {
      const phishDomain = String(phishDomainRaw || '').toLowerCase().replace(/^www\./, '');
      const phishRegistered = getRegisteredDomain(phishDomain);
      if (!phishRegistered) continue;
      if (phishRegistered === userRegistered) {
        return { isActual: true, isImpersonation: false, matches: [phishDomain], source: 'local_db', details: `Matched local DB: ${phishDomain}` };
      }
      if (phishDomain.includes(userRegistered)) {
        return { isActual: false, isImpersonation: true, matches: [phishDomain], source: 'local_db', details: `Local DB impersonation: ${phishDomain}` };
      }
    }
  } catch (e) {
    // ignore
  }

  return { isActual: false, isImpersonation: false, matches: [], source: null, details: null };
}

/* --------------------------------------------------
   HEALTH CHECK
-------------------------------------------------- */

app.get("/", (req, res) => {
  res.send("BeforeClick Backend is running");
});

/* --------------------------------------------------
   OTP ANALYSIS
-------------------------------------------------- */

app.post("/api/otp/analyze", async (req, res) => {
  console.log("REQ BODY:", req.body);

  const { websiteUrl, otpPurpose, otpType, otpSource, otpMessageText } = req.body;

  let riskScore = 0;
  let reasons = [];
  let domainAgeDays = null;
  let phishtankInfo = null;
  let phishingDetected = false;
  let domain = null;
  let aiExplanation = null;

  // Track detailed check results for UI display
  let rdapCheck = { status: "idle", data: null, error: null };
  let phishingCheck = { status: "idle", data: null, error: null };
  let virusTotalCheck = { status: "idle", data: null, error: null };

  try {
    // Defensive domain extraction: try to extract, but don't fail hard if it doesn't work perfectly
    domain = extractDomain(String(websiteUrl || "").trim());
    if (!domain) {
      // Try raw domain as fallback
      domain = String(websiteUrl || "").toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, "").split("/")[0];
      if (!domain) {
        // Return error but with empty checks
        return res.json({
          finalRiskLevel: RISK.MEDIUM,
          riskScore: 0,
          riskReasons: ["Invalid or empty URL provided"],
          recommendedAction: "PROVIDE A VALID URL",
          aiExplanation: null,
          checks: { rdap: rdapCheck, phishing: phishingCheck, virusTotal: virusTotalCheck },
        });
      }
    }

    // Prepare RDAP URL (kept for response consistency)
    const rdapUrl = `https://rdap.org/domain/${domain}`;

    // Check PhishTank/public feeds (best-effort) then local feeds
    try {
      console.log("🔍 Checking PhishTank/public feeds for domain:", domain);
      const pt = await checkPhishTank(domain);

      // pt now returns { isActual, isImpersonation, matches, source, details }
      let isActualPhishingDomain = false;
      let isImpersonation = false;

      if (pt && (pt.isActual || pt.isImpersonation)) {
        if (pt.isActual) {
          isActualPhishingDomain = true;
          phishtankInfo = { source: pt.source, details: pt.details, matches: pt.matches };
          console.log('✓ PhishTank actual domain match:', phishtankInfo);
        } else if (pt.isImpersonation) {
          isImpersonation = true;
          phishtankInfo = { source: pt.source, details: pt.details, matches: pt.matches };
          console.log('⚠️ PhishTank impersonation signals:', phishtankInfo);
        }
      } else {
        // fallback to local feed checkPhishingFeeds which now returns { actualMatch, impersonation, phishtankInfo, sampleMatches }
        const phishingResult = await checkPhishingFeeds(domain);
        if (phishingResult && phishingResult.actualMatch) {
          isActualPhishingDomain = true;
          phishtankInfo = phishingResult.phishtankInfo;
          console.log('✓ Local DB actual domain match:', phishtankInfo);
        } else if (phishingResult && phishingResult.impersonation) {
          isImpersonation = true;
          phishtankInfo = { source: 'local_db', details: 'Local DB shows impersonation examples', matches: phishingResult.sampleMatches };
          console.log('⚠️ Local DB impersonation signals:', phishtankInfo);
        }
      }

      phishingCheck.status = "completed";
      phishingCheck.data = {
        isActualPhishingDomain: isActualPhishingDomain,
        isImpersonation: isImpersonation,
        phishtankInfo: phishtankInfo,
      };

      if (isActualPhishingDomain) {
        // Immediate critical escalation for real registered-domain matches
        reasons.push("Domain listed in global phishing intelligence feeds");
        riskScore += 100;
        // mark a flag so later logic can treat this as critical
        phishingDetected = true;
      } else if (isImpersonation) {
        // Impersonation-only: signal impersonation but do not skip RDAP
        reasons.push("Phishing campaigns impersonating this brand exist");
        // make this a medium severity supporting signal
        riskScore += 35;
        phishingDetected = false;
      }
    } catch (err) {
      phishingCheck.status = "failed";
      phishingCheck.error = err.message;
      console.warn("⚠️ Phishing check error:", err.message);
    }

    // Only check RDAP if phishing not detected
    if (!phishingDetected) {
      try {
        const rdapResponse = await fetch(rdapUrl);

        if (rdapResponse.ok) {
          const rdapData = await rdapResponse.json();
          const extraRdapInfo = extractExtraRdapInfo(rdapData);
          domainAgeDays = extraRdapInfo.domainAgeDays;

          rdapCheck.status = "completed";
          rdapCheck.data = {
            domainAge: domainAgeDays,
            registrationDate: extraRdapInfo.registrationDate,
            expirationDate: extraRdapInfo.expirationDate,
          };

          const createdEvent = rdapData.events?.find(
            (e) => String(e.eventAction).toLowerCase() === "registration"
          );

          if (createdEvent && extraRdapInfo.domainAgeDays !== null) {
            const ageDays = extraRdapInfo.domainAgeDays;

            if (ageDays < 30) {
              riskScore += 50;
              reasons.push(`Domain registered within last 30 days (${ageDays} days old)`);
            } else if (ageDays < 180) {
              riskScore += 25;
              reasons.push(`Domain registered within last 6 months (${ageDays} days old)`);
            } else if (ageDays < 365) {
              riskScore -= 20;
              reasons.push(`Domain age is more than 6 months (${ageDays} days old)`);
            } else {
              riskScore -= 30;
              reasons.push(`Domain age > 1 year (${ageDays} days old) - Established domain`);
            }
          } else {
            reasons.push("Established domain (RDAP registration hidden by registry)");
          }
        } else {
          rdapCheck.status = "unavailable";
          rdapCheck.error = "RDAP lookup unavailable";
          reasons.push("RDAP lookup unavailable");
        }
      } catch (err) {
        rdapCheck.status = "failed";
        rdapCheck.error = err.message;
        console.warn("⚠️ RDAP check error:", err.message);
      }
    } else {
      rdapCheck.status = "skipped";
      rdapCheck.error = "Skipped due to phishing detection";
    }

    // --- VIRUSTOTAL CHECK (STEP 4) ---
    let virusTotal = null;
    try {
      virusTotal = await fetchVirusTotalReputation(domain);
      if (virusTotal) {
        virusTotalCheck.status = "completed";
        virusTotalCheck.data = virusTotal;
        if (virusTotal.flaggedVendors && virusTotal.flaggedVendors.length) {
          reasons.push(`Flagged by vendors: ${virusTotal.flaggedVendors.join(', ')}`);
        }

        // Apply VirusTotal rules on maliciousPercent
        const maliciousPercent = virusTotal.maliciousPercent || 0;
        if (maliciousPercent >= 60) {
          reasons.push(`Vendor consensus: ${maliciousPercent}% malicious engines`);
          var forceCritical = true;
        } else if (maliciousPercent >= 30) {
          reasons.push(`Vendor flags: ${maliciousPercent}% malicious engines`);
          var forceHigh = true;
        }
      } else {
        virusTotalCheck.status = "unavailable";
        virusTotalCheck.error = "VirusTotal check unavailable (API key missing or rate limit)";
      }
    } catch (err) {
      virusTotalCheck.status = "failed";
      virusTotalCheck.error = err.message;
      console.warn("⚠️ VirusTotal integration error:", err.message);
    }

    // If VirusTotal shows many vendor flags, forward details to Azure OpenAI for an explanatory analysis
    try {
      const vtVendorFlags = virusTotal?.vendorFlagCount || (virusTotal?.flaggedVendors ? virusTotal.flaggedVendors.length : 0);
      const vtMaliciousCount = virusTotal?.maliciousCount || virusTotal?.malicious || 0;
      if ((vtVendorFlags > 3 || vtMaliciousCount > 3) && AZURE_OPENAI_ENDPOINT && AZURE_OPENAI_API_KEY) {
        const explanationInput = {
          domain: domain,
          rdap: rdapCheck?.data || null,
          virusTotal: {
            malicious: virusTotal?.malicious || 0,
            suspicious: virusTotal?.suspicious || 0,
            vendorFlagCount: vtVendorFlags,
            flaggedVendors: virusTotal?.flaggedVendors || []
          },
          otpContext: { otpPurpose, otpType, otpSource },
          phish: phishingCheck?.data || null,
        };

        const aiFromVt = await callAzureOpenAIExplanation(domain, riskScore, reasons.concat([`VirusTotal vendor flags: ${vtVendorFlags}`]), explanationInput);
        if (aiFromVt) {
          aiExplanation = aiExplanation ? aiExplanation + "\n\n" + aiFromVt : aiFromVt;
        }
      }
    } catch (e) {
      console.warn('⚠️ Azure OpenAI forwarding on VirusTotal flags failed:', e.message);
    }

    // If VirusTotal shows many vendor flags, forward details to Azure OpenAI for an explanatory analysis
    try {
      const vtVendorFlags = virusTotal?.vendorFlagCount || (virusTotal?.flaggedVendors ? virusTotal.flaggedVendors.length : 0);
      const vtMaliciousCount = virusTotal?.maliciousCount || virusTotal?.malicious || 0;
      if ((vtVendorFlags > 3 || vtMaliciousCount > 3) && AZURE_OPENAI_ENDPOINT && AZURE_OPENAI_API_KEY) {
        // assemble payload for Azure OpenAI (explanation only)
        const explanationInput = {
          domain: domain,
          rdap: rdapCheck?.data || null,
          virusTotal: {
            malicious: virusTotal?.malicious || 0,
            suspicious: virusTotal?.suspicious || 0,
            vendorFlagCount: vtVendorFlags,
            flaggedVendors: virusTotal?.flaggedVendors || []
          },
          otpContext: { otpPurpose, otpType, otpSource },
          phish: phishingCheck?.data || null,
        };

        const aiFromVt = await callAzureOpenAIExplanation(domain, riskScore, reasons.concat([`VirusTotal vendor flags: ${vtVendorFlags}`]), explanationInput);
        if (aiFromVt) {
          // prefer existing aiExplanation if present, otherwise set
          aiExplanation = aiExplanation ? aiExplanation + "\n\n" + aiFromVt : aiFromVt;
        }
      }
    } catch (e) {
      console.warn('⚠️ Azure OpenAI forwarding on VirusTotal flags failed:', e.message);
    }

    // --- HTTPS CHECK ---
    const httpsStatus = websiteUrl.toLowerCase().startsWith("https://") ? "SECURE" : "NOT_SECURE";

    // --- USER OTP CONTEXT ---
    if ((otpPurpose || "").toLowerCase() === "payment") {
      riskScore += 30;
      reasons.push("OTP requested for payment");
    }

    if (otpMessageText?.toLowerCase().includes("urgent")) {
      riskScore += 20;
      reasons.push("Urgent language detected");
    }

    try {
      const pressureWords = ["immediately", "now", "asap", "verify now", "act now", "click now", "blocked"];
      const txt = String(otpMessageText || "").toLowerCase();
      for (const w of pressureWords) {
        if (txt.includes(w)) {
          riskScore += 5;
          reasons.push(`Pressure/urgency word detected: ${w}`);
          break;
        }
      }
    } catch (e) {}

    // Optional: Azure Content Safety signals
    const cs = await analyzeWithAzureContentSafety(otpMessageText);
    if (cs && cs.raw) {
      if (cs.scamScore >= 0.7) { riskScore += 30; reasons.push('High likelihood of scam or manipulative persuasion detected by Content Safety'); }
      else if (cs.scamScore >= 0.4) { riskScore += 10; reasons.push('Possible scam/manipulative persuasion detected by Content Safety'); }
      if (cs.coercionScore >= 0.6) { riskScore += 20; reasons.push('Coercive language detected by Content Safety'); }
      if (cs.threatScore >= 0.6) { riskScore += 40; reasons.push('Threatening language detected by Content Safety'); }
    }

    // Build securitySignals summary for Azure/OpenAI and diagnostics
    const securitySignals = {
      domainAgeDays: domainAgeDays,
      httpsStatus: httpsStatus,
      virusTotalMalicious: virusTotal ? virusTotal.malicious : null,
      virusTotalSuspicious: virusTotal ? virusTotal.suspicious : null,
      virusTotalVerdict: virusTotal ? (virusTotal.maliciousPercent >= 60 ? 'malicious' : (virusTotal.maliciousPercent >= 30 ? 'suspicious' : 'clean')) : 'unavailable',
      phishTankFound: phishingDetected,
      riskScore: riskScore
    };

    // Compute finalRisk based on accumulated signals
    let finalRisk = RISK.LOW;
    if (phishingDetected) {
      finalRisk = RISK.CRITICAL;
    } else if (riskScore >= 80) {
      finalRisk = RISK.CRITICAL;
    } else if (riskScore >= 50) {
      finalRisk = RISK.HIGH;
    } else if (riskScore >= 25) {
      finalRisk = RISK.MEDIUM;
    }

    // Escalate based on VirusTotal vendor consensus
    if (virusTotal) {
      const maliciousPercent = virusTotal.maliciousPercent || 0;
      if (maliciousPercent >= 60) {
        finalRisk = RISK.CRITICAL;
      } else if (maliciousPercent >= 30 && finalRisk !== RISK.CRITICAL) {
        finalRisk = RISK.HIGH;
      }
    }

    // Call Azure OpenAI if we have enough risk signals or vendor flags
    if (!aiExplanation) {
      try {
        const vtVendorFlags = virusTotal?.vendorFlagCount || (virusTotal?.flaggedVendors ? virusTotal.flaggedVendors.length : 0);
        const shouldCallAzure = 
          (finalRisk === RISK.MEDIUM || finalRisk === RISK.HIGH || finalRisk === RISK.CRITICAL) ||
          (vtVendorFlags > 3);

        console.log(`🤖 Azure Check: finalRisk=${finalRisk}, shouldCallAzure=${shouldCallAzure}, vtVendorFlags=${vtVendorFlags}`);
        console.log(`🤖 Env check: endpoint=${!!AZURE_OPENAI_ENDPOINT}, key=${!!AZURE_OPENAI_API_KEY}`);

        if (shouldCallAzure && AZURE_OPENAI_ENDPOINT && AZURE_OPENAI_API_KEY) {
          console.log(`🤖 Calling Azure OpenAI...`);
          aiExplanation = await callAzureOpenAIExplanation(domain, riskScore, reasons, { virusTotal, rdap: rdapCheck?.data || null, httpsStatus, url: websiteUrl, phish: phishingCheck?.data || null });
          if (!aiExplanation) {
            // Fallback if Azure fails
            aiExplanation = `Risk Assessment: ${finalRisk}. Domain age: ${domainAgeDays || 'unknown'} days. Primary concerns: ${reasons.slice(0, 3).join('; ')}`;
          }
        } else if (finalRisk !== RISK.LOW) {
          // Fallback for cases where Azure is not configured
          aiExplanation = `Risk level: ${finalRisk}. Domain age: ${domainAgeDays || 'unknown'} days. HTTPS: ${httpsStatus}. Key reasons: ${reasons.slice(0, 3).join('; ')}`;
        }
      } catch (e) {
        console.warn('⚠️ Azure OpenAI explanation error:', e.message);
        if (finalRisk !== RISK.LOW) {
          aiExplanation = `Risk level: ${finalRisk}. Analysis: ${reasons.slice(0, 2).join('; ')}`;
        }
      }
    }

    // FINAL RESPONSE - always return 200 with all data
    res.json({
      finalRiskLevel: finalRisk,
      riskScore: riskScore,
      aiExplanation: aiExplanation,
      httpsStatus: httpsStatus,
      riskReasons: reasons,
      recommendedAction: finalRisk === RISK.CRITICAL ? 'DO NOT ENTER OTP' : 'VERIFY THROUGH OFFICIAL CHANNEL',
      checks: { rdap: rdapCheck, phishing: phishingCheck, virusTotal: virusTotalCheck },
    });
  } catch (err) {
    console.error("OTP Analysis Error:", err);
    // Return 200 with diagnostic checks instead of 400 error
    res.json({
      finalRiskLevel: RISK.MEDIUM,
      riskScore: 0,
      riskReasons: ["Error processing URL"],
      recommendedAction: "VERIFY THROUGH OFFICIAL CHANNEL",
      aiExplanation: null,
      httpsStatus: "UNKNOWN",
      checks: { rdap: rdapCheck, phishing: phishingCheck, virusTotal: virusTotalCheck },
    });
  }
});

/* --------------------------------------------------
   PAYMENT ANALYSIS
-------------------------------------------------- */

app.post("/api/payment/analyze", async (req, res) => {
  const {
    websiteUrl,
    paymentAmountRange,
    paymentInitiatedByUser,
    paymentInstructionText,
  } = req.body;

  let riskScore = 0;
  let reasons = [];
  let domainAgeDays = null;
  let phishingDetected = false;
  let phishtankInfo = null;

  // Track detailed check results for UI display
  let rdapCheck = { status: "idle", data: null, error: null };
  let phishingCheck = { status: "idle", data: null, error: null };
  let virusTotalCheck = { status: "idle", data: null, error: null };

  try {
    const domain = extractDomain(websiteUrl);
    if (!domain) throw new Error("Invalid URL");

    // Check PhishTank/public feeds first, then fallback to local feeds
    try {
      const pt = await checkPhishTank(domain);

      let isActualPhishingDomain = false;
      let isImpersonation = false;

      if (pt && (pt.isActual || pt.isImpersonation)) {
        if (pt.isActual) {
          isActualPhishingDomain = true;
          phishtankInfo = { source: pt.source, details: pt.details, matches: pt.matches };
          console.log('✓ PhishTank actual domain match (payment):', phishtankInfo);
        } else if (pt.isImpersonation) {
          isImpersonation = true;
          phishtankInfo = { source: pt.source, details: pt.details, matches: pt.matches };
          console.log('⚠️ PhishTank impersonation signals (payment):', phishtankInfo);
        }
      } else {
        const phishingResult = await checkPhishingFeeds(domain);
        if (phishingResult && phishingResult.actualMatch) {
          isActualPhishingDomain = true;
          phishtankInfo = phishingResult.phishtankInfo;
          console.log('✓ Local DB actual domain match (payment):', phishtankInfo);
        } else if (phishingResult && phishingResult.impersonation) {
          isImpersonation = true;
          phishtankInfo = { source: 'local_db', details: 'Local DB shows impersonation examples', matches: phishingResult.sampleMatches };
          console.log('⚠️ Local DB impersonation signals (payment):', phishtankInfo);
        }
      }

      phishingCheck.status = "completed";
      phishingCheck.data = { isActualPhishingDomain, isImpersonation, phishtankInfo };

      if (isActualPhishingDomain) {
        reasons.push("Domain listed in global phishing intelligence feeds");
        riskScore += 100;
        phishingDetected = true;
      } else if (isImpersonation) {
        reasons.push("Phishing campaigns impersonating this brand exist");
        riskScore += 35;
        phishingDetected = false;
      }
    } catch (err) {
      phishingCheck.status = "failed";
      phishingCheck.error = err.message;
      console.warn("⚠️ Payment phishing check error:", err.message);
    }

    // Only check RDAP if phishing not detected
    if (!phishingDetected) {
      try {
        const rdapRes = await fetch(`https://rdap.org/domain/${domain}`);
        if (rdapRes.ok) {
          const rdapData = await rdapRes.json();
          const info = extractExtraRdapInfo(rdapData);
          domainAgeDays = info.domainAgeDays;

          rdapCheck.status = "completed";
          rdapCheck.data = {
            domainAge: domainAgeDays,
            registrationDate: info.registrationDate,
            expirationDate: info.expirationDate,
          };

          if (info.domainAgeDays === null) {
            reasons.push("Established domain (RDAP registration hidden by registry)");
          } else if (info.domainAgeDays < 30) {
            riskScore += 40;
            reasons.push(`Newly registered domain (${info.domainAgeDays} days old)`);
          } else if (info.domainAgeDays < 180) {
            riskScore += 15;
            reasons.push(`Domain registered within last 6 months (${info.domainAgeDays} days old)`);
          } else if (info.domainAgeDays >= 365) {
            riskScore -= 30;
            reasons.push(`Domain age > 1 year (${info.domainAgeDays} days old) - Established domain`);
          } else {
            riskScore -= 10;
            reasons.push(`Domain registered within last year (${info.domainAgeDays} days old)`);
          }
        } else {
          rdapCheck.status = "unavailable";
          rdapCheck.error = "RDAP lookup unavailable";
        }
      } catch (err) {
        rdapCheck.status = "failed";
        rdapCheck.error = err.message;
        console.warn("⚠️ Payment RDAP check error:", err.message);
      }
    } else {
      rdapCheck.status = "skipped";
      rdapCheck.error = "Skipped due to phishing detection";
    }

    if (paymentInitiatedByUser === false) {
      riskScore += 40;
      reasons.push("Payment not initiated by user");
    }

    if (paymentAmountRange === "LARGE") riskScore += 30;
    else if (paymentAmountRange === "MEDIUM") riskScore += 15;

    if (paymentInstructionText?.toLowerCase().includes("urgent")) {
      riskScore += 20;
      reasons.push("Urgent payment language detected");
    }

    // Optional local urgency/pressure detection (supporting signal)
    try {
      const pressureWords = ["immediately", "now", "asap", "verify now", "act now", "pay now"];
      const ptxt = String(paymentInstructionText || "").toLowerCase();
      for (const w of pressureWords) {
        if (ptxt.includes(w)) {
          riskScore += 5;
          reasons.push(`Pressure/urgency word detected: ${w}`);
          break;
        }
      }
    } catch (e) {
      // ignore
    }

    // Azure Content Safety signals
    const cs = await analyzeWithAzureContentSafety(paymentInstructionText);

    let forceHigh = false;
    let forceCritical = false;

    if (cs.raw) {
      if (cs.scamScore >= 0.7) {
        riskScore += 30;
        reasons.push('High likelihood of scam or manipulation detected by Content Safety');
      } else if (cs.scamScore >= 0.4) {
        riskScore += 10;
        reasons.push('Possible scam/manipulation detected by Content Safety');
      }

      if (cs.coercionScore >= 0.6) {
        riskScore += 25;
        reasons.push('Coercive language detected by Content Safety');
        forceHigh = true;
      }

      if (cs.threatScore >= 0.6) {
        riskScore += 50;
        reasons.push('Threatening language detected by Content Safety');
        forceCritical = true;
      }
    }

    // If phishing intelligence flagged the domain, treat as critical signal
    if (phishingDetected) {
      forceCritical = true;
      reasons.push('Domain listed in phishing intelligence feeds (escalated to CRITICAL)');
    }

    if (riskScore < 0) riskScore = 0;

    // Final risk decision using standardized thresholds (backend only)
    let finalRisk = RISK.LOW;
    if (forceCritical) {
      finalRisk = RISK.CRITICAL;
    } else if (forceHigh) {
      finalRisk = RISK.HIGH;
    } else if (riskScore >= 80) {
      finalRisk = RISK.CRITICAL;
    } else if (riskScore >= 50) {
      finalRisk = RISK.HIGH;
    } else if (riskScore >= 25) {
      finalRisk = RISK.MEDIUM;
    }

    // VirusTotal check (reputation) - use normalized domain
    let virusTotal = null;
    try {
      virusTotal = await fetchVirusTotalReputation(domain);
      if (virusTotal) {
        virusTotalCheck.status = "completed";
        virusTotalCheck.data = virusTotal;

        if (virusTotal.flaggedVendors && virusTotal.flaggedVendors.length) {
          reasons.push(`Flagged by vendors: ${virusTotal.flaggedVendors.join(', ')}`);
        }

        const maliciousPercent = virusTotal.maliciousPercent || 0;
        if (maliciousPercent >= 60) {
          finalRisk = RISK.CRITICAL;
          reasons.push(`High vendor consensus: ${maliciousPercent}% of engines flagged as malicious`);
        } else if (maliciousPercent >= 30) {
          finalRisk = finalRisk === RISK.CRITICAL ? RISK.CRITICAL : RISK.HIGH;
          reasons.push(`Significant vendor flags: ${maliciousPercent}% malicious engines`);
        }

        // RDAP combination: escalate if new domain + VT hit; reduce if old domain + clean
        try {
          if (domainAgeDays !== null && domainAgeDays < 180 && (virusTotal.malicious + virusTotal.suspicious) > 0) {
            reasons.push('New domain with VirusTotal flags - escalation');
            if (finalRisk !== RISK.CRITICAL) finalRisk = RISK.HIGH;
          }

          if (domainAgeDays !== null && domainAgeDays >= 365 && (virusTotal.malicious + virusTotal.suspicious) === 0) {
            riskScore = Math.max(0, riskScore - 10);
            reasons.push('Established domain with clean VirusTotal - reduced risk slightly');
          }
        } catch (e) {}

      } else {
        virusTotalCheck.status = "unavailable";
        virusTotalCheck.error = "VirusTotal check unavailable (API key missing or rate limit)";
      }
    } catch (err) {
      virusTotalCheck.status = "failed";
      virusTotalCheck.error = err.message;
      console.warn("⚠️ Payment VirusTotal error:", err.message);
    }

    // Call Azure OpenAI for explanation only if HIGH or CRITICAL
    let aiExplanation = null;
    if (finalRisk === RISK.HIGH || finalRisk === RISK.CRITICAL) {
      aiExplanation = await callAzureOpenAIExplanation(domain, riskScore, reasons, { virusTotal, rdap: rdapCheck?.data || null, httpsStatus: websiteUrl.toLowerCase().startsWith('https://') ? 'SECURE' : 'NOT_SECURE', url: websiteUrl });
    }

    const warning = finalRisk === RISK.CRITICAL;
    const warningType = finalRisk === RISK.CRITICAL ? "BLOCK_ACTION" : null;

    // Build analysisSummary (plain text, <=10 lines)
    const vtVerdict = (virusTotal && virusTotal.maliciousPercent >= 60) ? 'malicious' : (virusTotal && virusTotal.maliciousPercent >= 30) ? 'suspicious' : 'clean';
    const enginesFlagging = virusTotal ? (virusTotal.malicious + virusTotal.suspicious) : 0;
    const phishStatus = phishingDetected ? 'found' : 'not found';
    const overallInterpretation = finalRisk;

    const analysisLines = [];
    analysisLines.push(`Domain age (days): ${domainAgeDays === null ? 'unknown' : domainAgeDays}`);
    analysisLines.push(`VirusTotal verdict: ${vtVerdict}`);
    analysisLines.push(`Engines flagging: ${enginesFlagging}`);
    analysisLines.push(`PhishTank status: ${phishStatus}`);
    analysisLines.push(`Overall: ${overallInterpretation}`);

    const analysisSummary = analysisLines.slice(0, 10).join('\n');

    res.json({
      domainChecked: domain,
      domainAgeDays,
      finalRiskLevel: finalRisk,
      riskScore,
      riskReasons: reasons,
      analysisSummary,
      inferredPaymentMethod: "UPI / Card",
      recommendedAction:
        finalRisk === RISK.CRITICAL
          ? "DO NOT PROCEED WITH PAYMENT"
          : "VERIFY PAYMENT DETAILS",
      warning,
      warningType,
      aiExplanation,
      virusTotal,
      checks: {
        rdap: rdapCheck,
        phishing: phishingCheck,
        virusTotal: virusTotalCheck,
      },
    });
  } catch {
    // Ensure we return checks information even on error so UI can display statuses
    res.status(400).json({
      finalRiskLevel: RISK.MEDIUM,
      riskScore: 30,
      riskReasons: ["Invalid or malformed URL"],
      recommendedAction: "VERIFY PAYMENT DETAILS",
      warning: false,
      warningType: null,
      aiExplanation: null,
      virusTotal: null,
      checks: {
        rdap: typeof rdapCheck !== 'undefined' ? rdapCheck : { status: 'failed', data: null, error: 'RDAP not performed' },
        phishing: typeof phishingCheck !== 'undefined' ? phishingCheck : { status: 'failed', data: null, error: 'Phishing check not performed' },
        virusTotal: typeof virusTotalCheck !== 'undefined' ? virusTotalCheck : { status: 'failed', data: null, error: 'VirusTotal not performed' },
      },
    });
  }
});

/* --------------------------------------------------
   COOKIES ANALYSIS
-------------------------------------------------- */

app.post("/api/cookies/analyze", async (req, res) => {
  const { cookieConsentText } = req.body;

  let riskScore = 0;
  let summaryPoints = [];

  if (/third party/i.test(cookieConsentText || "")) {
    riskScore += 20;
    summaryPoints.push("Third-party cookies detected");
  }

  if (/tracking|ads|profiling/i.test(cookieConsentText || "")) {
    riskScore += 20;
    summaryPoints.push("Tracking or advertising cookies present");
  }

  let finalRisk = RISK.LOW;
  if (riskScore >= 40) finalRisk = RISK.HIGH;
  else if (riskScore >= 20) finalRisk = RISK.MEDIUM;

  res.json({
    finalRiskLevel: finalRisk,
    riskScore,
    summaryPoints,
    recommendedAction:
      finalRisk === "HIGH"
        ? "AVOID ACCEPTING ALL COOKIES"
        : "REVIEW COOKIE SETTINGS",
  });
});

/* --------------------------------------------------
   TERMS ANALYSIS
-------------------------------------------------- */

app.post("/api/terms/analyze", async (req, res) => {
  const { websiteUrl, termsText } = req.body;

  let riskScore = 0;
  let summaryPoints = [];

  // If the user pasted the full terms text, split into lines and use each
  // non-empty line as a summary point so the frontend displays them directly.
  if (termsText && String(termsText).trim()) {
    const lines = String(termsText)
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    if (lines.length > 0) {
      summaryPoints = lines;
      // light heuristic scoring: more clauses -> higher score
      riskScore += Math.min(50, lines.length * 5);
    }
  } else {
    if (/share your data/i.test(termsText || "")) {
      riskScore += 20;
      summaryPoints.push("Data sharing with third parties");
    }

    if (/not liable|no responsibility/i.test(termsText || "")) {
      riskScore += 15;
      summaryPoints.push("Company limits legal liability");
    }
  }

  const domain = extractDomain(websiteUrl);
  const rdap = await fetchRDAP(domain);
  if (!rdap) {
    riskScore += 15;
    summaryPoints.push("Domain ownership unclear");
  }

  let finalRisk = RISK.LOW;
  if (riskScore >= 50) finalRisk = RISK.HIGH;
  else if (riskScore >= 25) finalRisk = RISK.MEDIUM;

  res.json({
    finalRiskLevel: finalRisk,
    riskScore,
    // Keep backwards-compatible field `riskReasons` and add `summaryPoints`
    riskReasons: summaryPoints,
    summaryPoints: summaryPoints,
    recommendedAction:
      finalRisk === "HIGH"
        ? "READ CAREFULLY OR AVOID ACCEPTING"
        : "REVIEW TERMS BEFORE PROCEEDING",
  });
});

/* --------------------------------------------------
   RDAP LOOKUP ENDPOINT
-------------------------------------------------- */

app.post("/api/file/analyze", upload.single('file'), async (req, res) => {
  console.log("📁 File Scan Analysis Request");

  try {
    // Validate file upload
    if (!req.file) {
      return res.json({
        finalRiskLevel: 'low',
        riskScore: 0,
        warning: false,
        analysisSource: 'VirusTotal',
        virusTotal: null,
        aiExplanation: 'No file provided for analysis',
        recommendedAction: 'UPLOAD A FILE TO SCAN',
      });
    }

    const fileName = req.file.originalname;
    const fileBuffer = req.file.buffer;
    const fileSizeKB = fileBuffer.length / 1024;

    console.log(`📄 File: ${fileName}, Size: ${fileSizeKB.toFixed(2)} KB`);

    // Ensure VirusTotal API key(s) available. If not configured, return a demo/randomized response
    if (!VT_KEYS_CSV) {
      console.warn('⚠️ File analyze called but no VirusTotal API key configured — returning demo response');
      const demo = getRandomRiskDemo();
      const demoConcerns = [
        'Potential malware signatures',
        'Suspicious file metadata',
        'Obfuscated code detected',
        'Unsigned executable',
        'Embedded suspicious URLs',
        'Known risky filename pattern'
      ];
      const randomConcerns = demoConcerns.sort(() => Math.random() - 0.5).slice(0, Math.floor(Math.random() * 3) + 1);

      return res.json({
        finalRiskLevel: demo.level,
        riskScore: demo.score,
        warning: demo.level === 'HIGH' || demo.level === 'CRITICAL',
        analysisSource: 'DemoFileScanner',
        virusTotal: null,
        aiExplanation: `Demo analysis: ${randomConcerns.join(', ')}.`,
        recommendedAction: demo.level === 'CRITICAL' ? 'DO NOT OPEN' : 'REVIEW FILE BEFORE OPENING',
        riskReasons: randomConcerns,
      });
    }

    // --- STEP 1: Upload to VirusTotal with timeout ---
    console.log('📤 Starting VirusTotal upload...');
    let uploadResult = null;
    try {
      uploadResult = await Promise.race([
        uploadFileToVirusTotal(fileBuffer, fileName),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Upload timeout (60s)')), 60000))
      ]);
    } catch (e) {
      console.warn(`⚠️ Upload failed: ${e.message}`);
      uploadResult = null;
    }
    
    if (!uploadResult || !uploadResult.analysisId) {
      console.warn('⚠️ VirusTotal upload failed or timed out');
      return res.json({
        finalRiskLevel: 'low',
        riskScore: 0,
        warning: false,
        analysisSource: 'VirusTotal',
        virusTotal: null,
        aiExplanation: 'Unable to upload file to VirusTotal. Please try again.',
        recommendedAction: 'TRY AGAIN LATER',
        riskReasons: ['VirusTotal upload failed'],
      });
    }

    const { analysisId, usedKeyIndex } = uploadResult;
    console.log(`✓ Analysis ID received: ${analysisId}`);

    // --- STEP 2: Poll for analysis completion with timeout ---
    console.log('⏳ Polling for analysis results...');
    let analysisData = null;
    try {
      analysisData = await Promise.race([
        pollVirusTotalAnalysis(analysisId, usedKeyIndex),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Polling timeout (60s)')), 60000))
      ]);
    } catch (e) {
      console.warn(`⚠️ Polling failed: ${e.message}`);
      analysisData = null;
    }

    if (!analysisData) {
      console.warn('⚠️ Analysis polling timeout or failed');
      return res.json({
        finalRiskLevel: 'medium',
        riskScore: 50,
        warning: false,
        analysisSource: 'VirusTotal',
        virusTotal: null,
        aiExplanation: 'File analysis did not complete in time. Try uploading again.',
        recommendedAction: 'TRY UPLOADING AGAIN',
        riskReasons: ['Analysis timeout'],
      });
    }

    // --- STEP 3: Extract VirusTotal results ---
    const vtResults = extractVirusTotalFileAnalysis(analysisData);
    console.log('✓ VirusTotal Results:', vtResults);

    // --- STEP 4: Calculate risk score and level (backend-only decision) ---
    let riskScore = 0;
    let reasons = [];
    let finalRiskLevel = 'LOW';

    if (vtResults.malicious > 0) {
      reasons.push(`${vtResults.malicious} vendor(s) detected malware`);
      finalRiskLevel = 'CRITICAL';
      riskScore = 95;
    } else if (vtResults.suspicious > 0) {
      reasons.push(`${vtResults.suspicious} vendor(s) flagged as suspicious`);
      finalRiskLevel = 'HIGH';
      riskScore = 75;
    } else {
      reasons.push('File clean according to VirusTotal');
      finalRiskLevel = 'LOW';
      riskScore = 5;
    }

    // --- STEP 5: Call Azure OpenAI for explanation (if configured and risky) ---
    let aiExplanation = null;
    try {
      if ((finalRiskLevel === 'CRITICAL' || finalRiskLevel === 'HIGH' || riskScore > 30) && AZURE_OPENAI_ENDPOINT && AZURE_OPENAI_API_KEY) {
        console.log('🤖 Calling Azure OpenAI for file analysis explanation...');
        
        aiExplanation = await callAzureOpenAIExplanation(
          fileName,
          riskScore,
          reasons,
          { virusTotal: vtResults, url: `file://${fileName}` }
        );
        
        if (!aiExplanation) {
          aiExplanation = `File Analysis: ${reasons.join('. ')} Based on VirusTotal scan of ${vtResults.totalEngines} engines.`;
        }
      } else if (finalRiskLevel === 'low') {
        aiExplanation = `File appears clean. VirusTotal scan found no threats among ${vtResults.totalEngines} vendors.`;
      } else {
        aiExplanation = reasons.join('. ');
      }
    } catch (e) {
      console.warn('⚠️ Azure OpenAI explanation failed:', e.message);
      aiExplanation = reasons.join('. ');
    }

    // --- STEP 6: Return structured response ---
    const warning = finalRiskLevel === 'high';
    const recommendedAction =
      finalRiskLevel === 'high'
        ? 'DO NOT OPEN OR EXECUTE THIS FILE'
        : finalRiskLevel === 'medium'
        ? 'EXERCISE CAUTION BEFORE OPENING'
        : 'FILE APPEARS SAFE TO OPEN';

    console.log('✓ Returning response:', { finalRiskLevel, riskScore });
    res.json({
      finalRiskLevel,
      riskScore,
      warning,
      analysisSource: 'VirusTotal',
      virusTotal: {
        malicious: vtResults.malicious,
        suspicious: vtResults.suspicious,
        harmless: vtResults.harmless,
        totalEngines: vtResults.totalEngines,
        detectionRate: `${vtResults.detectionRate}%`,
        flaggedVendors: vtResults.flaggedVendors,
      },
      aiExplanation,
      recommendedAction,
      riskReasons: reasons,
    });
  } catch (err) {
    console.error('❌ File Analysis Error:', err.message, err.stack);
    res.json({
      finalRiskLevel: 'medium',
      riskScore: 0,
      warning: false,
      analysisSource: 'VirusTotal',
      virusTotal: null,
      aiExplanation: 'Error analyzing file',
      recommendedAction: 'TRY AGAIN LATER',
      riskReasons: ['Error processing file'],
    });
  }
});

/* --------------------------------------------------
   RDAP LOOKUP ENDPOINT
-------------------------------------------------- */

app.post("/api/rdap/lookup", async (req, res) => {
  const { domain } = req.body;

  if (!domain) {
    return res.status(400).json({ error: "Domain is required" });
  }

  try {
    // Normalize domain
    let normalizedDomain = String(domain).toLowerCase().trim();
    normalizedDomain = normalizedDomain.replace(/^(https?:\/\/)?(www\.)?/, "");

    console.log("🌐 RDAP Lookup for domain:", normalizedDomain);

    // Fetch RDAP data
    const rdapResponse = await fetch(`https://rdap.org/domain/${normalizedDomain}`);

    if (!rdapResponse.ok) {
      return res.status(400).json({
        error: `RDAP lookup failed: ${rdapResponse.statusText}`,
        status: "error",
      });
    }

    const rdapData = await rdapResponse.json();
    const extraInfo = extractExtraRdapInfo(rdapData);

    // Extract registrar info
    let registrar = null;
    if (rdapData.entities && Array.isArray(rdapData.entities)) {
      const registrarEntity = rdapData.entities.find(
        (entity) => entity.roles && entity.roles.includes("registrar")
      );
      if (registrarEntity && registrarEntity.vcardArray) {
        registrar = registrarEntity.vcardArray[0]?.[1]?.name || null;
      }
    }

    // Format dates for display
    const createdDate = extraInfo.registrationDate
      ? new Date(extraInfo.registrationDate).toLocaleDateString("en-US", {
          year: "numeric",
          month: "long",
          day: "numeric",
        })
      : null;

    const updatedDate = extraInfo.lastUpdateDate
      ? new Date(extraInfo.lastUpdateDate).toLocaleDateString("en-US", {
          year: "numeric",
          month: "long",
          day: "numeric",
        })
      : null;

    console.log("✅ RDAP Data Retrieved:", {
      domain: normalizedDomain,
      domainAgeDays: extraInfo.domainAgeDays,
      registrar,
    });

    res.json({
      domain: normalizedDomain,
      domainAgeDays: extraInfo.domainAgeDays,
      registrar,
      createdDate,
      updatedDate,
      status: "completed",
    });
  } catch (error) {
    console.error("❌ RDAP Lookup Error:", error.message);
    res.status(500).json({
      error: `RDAP lookup failed: ${error.message}`,
      status: "error",
    });
  }
});

/* --------------------------------------------------
   FILE SCAN - DEMO ENDPOINTS (PERMISSIONS, COOKIES, TERMS)
-------------------------------------------------- */

// Helper: random risk level and score
function getRandomRiskDemo() {
  const levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const level = levels[Math.floor(Math.random() * levels.length)];
  const scoreMap = { LOW: 15, MEDIUM: 45, HIGH: 75, CRITICAL: 95 };
  return { level, score: scoreMap[level] + Math.floor(Math.random() * 15) };
}

// POST /api/file/permissions/analyze - Demo endpoint
app.post("/api/file/permissions/analyze", upload.single('file'), async (req, res) => {
  console.log("📋 Permissions Analysis Request (DEMO)");
  const { level, score } = getRandomRiskDemo();
  
  const permissionsData = [
    "Camera access",
    "Microphone access",
    "Location tracking",
    "Contact list access",
    "Calendar permissions",
    "File system read/write"
  ];
  
  const randomPerms = permissionsData.sort(() => Math.random() - 0.5).slice(0, Math.floor(Math.random() * 4) + 1);
  
  res.json({
    finalRiskLevel: level,
    riskScore: score,
    warning: level === 'HIGH' || level === 'CRITICAL',
    analysisSource: 'PermissionsAnalyzer',
    permissionsRequested: randomPerms,
    aiExplanation: `This application requests ${randomPerms.length} permissions. ${randomPerms.join(', ')}. Risk level: ${level}.`,
    recommendedAction: level === 'CRITICAL' ? 'REVIEW PERMISSIONS CAREFULLY' : 'PERMISSIONS ACCEPTABLE',
    riskReasons: [`Requests ${randomPerms.length} permissions`]
  });
});

// POST /api/file/cookies/analyze - Demo endpoint
app.post("/api/file/cookies/analyze", upload.single('file'), async (req, res) => {
  console.log("🍪 Cookies Analysis Request (DEMO)");
  const { level, score } = getRandomRiskDemo();
  
  const cookieTypes = ['Session Cookies', 'Tracking Cookies', 'Third-party Cookies', 'Marketing Cookies'];
  const randomCookies = cookieTypes.slice(0, Math.floor(Math.random() * 3) + 1);
  
  res.json({
    finalRiskLevel: level,
    riskScore: score,
    warning: level === 'HIGH' || level === 'CRITICAL',
    analysisSource: 'CookieAnalyzer',
    cookieTypes: randomCookies,
    totalCookies: Math.floor(Math.random() * 50) + 5,
    aiExplanation: `Detected ${randomCookies.join(', ')}. These may be used for tracking and analytics. Risk level: ${level}.`,
    recommendedAction: level === 'CRITICAL' ? 'DISABLE OR REVIEW ALL COOKIES' : 'REVIEW COOKIE SETTINGS',
    riskReasons: [`Found ${randomCookies.length} cookie types`, `Total cookies: ${Math.floor(Math.random() * 50) + 5}`]
  });
});

// POST /api/file/terms/analyze - Demo endpoint
app.post("/api/file/terms/analyze", async (req, res) => {
  console.log("📜 Terms & Conditions Analysis Request (DEMO)");
  const { termsUrl } = req.body;
  
  if (!termsUrl) {
    return res.status(400).json({
      finalRiskLevel: "LOW",
      riskScore: 5,
      error: "Terms URL is required",
    });
  }

  const { level, score } = getRandomRiskDemo();
  
  const concernTypes = ['Data Sharing Concerns', 'Arbitration Clause', 'Liability Limitation', 'Auto-renewal Terms', 'Privacy Waiver', 'Content Ownership'];
  const randomConcerns = concernTypes.slice(0, Math.floor(Math.random() * 4) + 1);
  
  res.json({
    finalRiskLevel: level,
    riskScore: score,
    warning: level === 'HIGH' || level === 'CRITICAL',
    analysisSource: 'TermsAnalyzer',
    concernTypes: randomConcerns,
    totalConcerns: randomConcerns.length,
    aiExplanation: `Detected ${randomConcerns.join(', ')}. Review these clauses before accepting. Risk level: ${level}.`,
    recommendedAction: level === 'CRITICAL' ? 'DO NOT ACCEPT - CONSULT LEGAL ADVICE' : 'READ CAREFULLY BEFORE ACCEPTING',
    riskReasons: randomConcerns
  });
});

/* --------------------------------------------------
   START SERVER
-------------------------------------------------- */

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
