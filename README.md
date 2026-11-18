# SPRIZAN — Cyber Threat Intelligence (100% Free Community Edition)

A dark, dragon-themed URL investigation dashboard and explainable threat analysis engine.

**SPRIZAN is built to operate 100% free of charge.** It requires no payment, billing accounts, credit cards, Google Cloud billing, or paid API subscriptions.

---

## Core Capabilities

### 1. Robust Local Analysis Engine
SPRIZAN features a powerful, zero-network local heuristic engine that evaluates structural threat indicators in memory:
- **1,000 Verified Top Legitimate Domains**: Built-in indexing of popular legitimate domains (including Amazon India `amazon.in`, Google India `google.co.in`, Microsoft, Apple, GitHub, YouTube, Wikipedia, etc.) to eliminate false positives on trusted properties.
- **Multi-Part ccTLD & Public Suffix Recognition**: Correctly extracts the true registered domain across international 2-level and 3-level ccTLDs (e.g. `.co.in`, `.org.in`, `.co.uk`, `.com.au`, `.co.jp`).
- **Brand Impersonation & Misleading Subdomains**: Distinguishes the true registered domain (e.g., `xyz.top`) from misleading brand labels in subdomains or host prefixes (e.g., `paypal.com.account-update.xyz`).
- **Typosquatting & Combosquatting Detection**: Uses Damerau-Levenshtein distance, brand-token extraction, and leetspeak/character substitution analysis to catch deceptive brand variants (e.g., `amazn.in`, `paypa1.com`, `amazon-security-update.com`).
- **Direct & Obfuscated IP Hosts**: Detects IPv4, IPv6, dword/hex obfuscation, and flags private/internal addresses (RFC 1918 / Loopback) to prevent internal network reconnaissance.
- **Homograph & Punycode (IDN) Attacks**: Identifies `xn--` Punycode and invisible/bidirectional unicode characters (e.g., zero-width spaces, right-to-left override).
- **Service Port Anomalies**: Differentiates standard web traffic (80/443) from non-standard web ports (8080/8443) and suspicious administration/exploit ports (21, 22, 23, 25, 445, 1337, 3389, 6667).
- **Subdomain Hierarchy**: Detects excessive label nesting ($\ge 5$ levels) used to push the true destination out of view.
- **High-Risk Disposable TLDs**: Contextually identifies disposable or high-abuse extensions paired with account, banking, or credential lures.
- **Deceptive Double File Extensions**: Uncovers executable malware disguised as documents or pictures (e.g., `.pdf.exe`, `.xlsx.scr`, `.jpg.vbs`).
- **Cryptocurrency & Wallet Drainer Lures**: Identifies links targeting seed phrases, private keys, or wallet recovery files.
- **Open Redirect Parameters**: Detects search parameters (`?url=`, `?redirect=`, etc.) pointing to external destinations.
- **Anti-Double-Counting**: Findings are categorized with score caps to prevent related indicators from compounding unrealistically.

### 2. Free Community Threat Intelligence (URLhaus by abuse.ch)
Integrates with the free community URLhaus malware database operated by abuse.ch.
- If configured with a free Auth-Key, queries are dispatched to `https://urlhaus-api.abuse.ch/v1/url/`.
- If unconfigured, the application runs in local standalone mode without fabricating results.
- VirusTotal and Google Web Risk are disabled/removed in this version to eliminate all payment or cloud billing requirements.

### 3. Distinct Threat Verdicts
- **`CONFIRMED MALWARE`**: Positively identified in the URLhaus community malware database.
- **`SUSPICIOUS`**: Meaningful structural warning indicators or deception techniques detected by local analysis.
- **`NO KNOWN THREATS DETECTED`**: Local structural analysis found no red flags, and external threat intelligence (URLhaus) completed and returned no matching malware records. *(Note: Not a guarantee of safety).*
- **`NOT FLAGGED BY LOCAL ANALYSIS`**: No structural warning indicators were detected by local analysis, but external community verification was unconfigured.
- **`PARTIALLY VERIFIED`**: Local structural analysis completed cleanly, but the external community threat feed check failed or timed out.
- **`UNABLE TO VERIFY`**: The URL was syntactically invalid or the analysis could not produce a reliable result.

---

## How to Get the Free URLhaus Auth-Key

The URLhaus community API is **100% free with zero payment or credit card required**:
1. Visit [abuse.ch Authentication Portal](https://auth.abuse.ch/) or [URLhaus API](https://urlhaus.abuse.ch/api/).
2. Create a free community account using your email.
3. Copy your personal `Auth-Key`.
4. Add it to your `.env` file as `URLHAUS_AUTH_KEY=your_key_here`.

*(If you choose not to configure a key, SPRIZAN will still perform complete local heuristic analysis and report the external feed as unconfigured).*

---

## Quickstart

### Prerequisites
- Node.js 18 or newer.
- No payment method, billing setup, or credit card.

### Run Locally
```bash
# 1. Install free open-source dependencies
npm install

# 2. (Optional) Set up your free .env file
cp .env.example .env

# 3. Start the application
npm start
```
Open **`http://localhost:3000`** in your browser.

### Run Verification Test Suite
```bash
npm test
```
Executes the comprehensive in-memory test suite verifying domain extraction, popular website accuracy, threat detection, and API endpoints without network calls.

---

## Security & Safety Principles

1. **Zero Execution**: SPRIZAN **never visits, executes, or fetches the target URL**. Only the URL string is parsed locally.
2. **SSRF Safe**: Outgoing network requests are strictly restricted to trusted external APIs (`urlhaus-api.abuse.ch`).
3. **Key Protection**: API credentials remain strictly server-side in `.env` and are never exposed to the frontend.
4. **Rate Limiting**: Built-in in-memory rate limiting prevents abuse (up to 60 requests per minute per IP).
5. **No False Safety Guarantees**: Clean results explicitly inform the user that unlisted URLs can still be newly registered or untracked.
