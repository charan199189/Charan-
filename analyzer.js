/**
 * ScamShield - 100% Client-side Rule-based Security Analyzer
 * No AI APIs, no external backend, no databases, safe client-side heuristics.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ScamAnalyzer = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {

  // Known brand imitation targets
  const FAMOUS_BRANDS = [
    { name: 'PayPal', regex: /paypa[l1i]|pay-pal/i },
    { name: 'Amazon', regex: /amaz[o0]n|amzn-verify/i },
    { name: 'Apple', regex: /app[l1]e-?id|icloud-verify/i },
    { name: 'Microsoft', regex: /micr[o0]s[o0]ft|msft-login|office365-verify/i },
    { name: 'Google', regex: /g[o0]{2}g[l1]e|gmail-security/i },
    { name: 'Netflix', regex: /netf[l1]ix|netflix-billing/i },
    { name: 'Chase', regex: /chase-?security|chase-online/i },
    { name: 'Wells Fargo', regex: /we[l1]{2}sfarg[o0]/i },
    { name: 'Bank of America', regex: /bofa-login|bankofamerica-verify/i },
    { name: 'USPS / Postal', regex: /usps-tracking|postal-redelivery|fedex-package|dhl-express/i }
  ];

  // High-risk and free TLDs frequently abused in phishing campaigns
  const SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.click', '.buzz', '.club', '.work', '.online', '.site',
    '.tk', '.ml', '.ga', '.cf', '.gq', '.su', '.fit', '.rest', '.bar',
    '.vip', '.icu', '.monster', '.live', '.surf', '.cam', '.skin', '.run'
  ];

  // Common URL shorteners
  const URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'cutt.ly', 'rebrand.ly', 'qr.net', 'rb.gy', 'v.gd'
  ];

  // Suspicious keywords frequently in malicious paths or subdomains
  const SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'secure', 'security',
    'update', 'confirm', 'confirmation', 'billing', 'wallet', 'banking',
    'account', 'authenticate', 'recovery', 'claim', 'refund', 'unlock',
    'unauthorized', 're-activate', 'validate'
  ];

  /**
   * Helper to normalize text
   */
  function normalizeText(text) {
    return (text || '').trim();
  }

  /**
   * Helper to extract URLs from free text
   */
  function extractUrls(text) {
    if (!text) return [];
    const urlRegex = /(https?:\/\/[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)/gi;
    const matches = text.match(urlRegex) || [];
    return matches.map(u => {
      let clean = u.replace(/[),.;!]+$/, '');
      if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
        clean = 'http://' + clean;
      }
      return clean;
    });
  }

  /**
   * Safe URL parser
   */
  function parseUrlSafely(urlStr) {
    try {
      let candidate = urlStr.trim();
      if (!candidate.startsWith('http://') && !candidate.startsWith('https://')) {
        candidate = 'https://' + candidate;
      }
      const parsed = new URL(candidate);
      return parsed;
    } catch (e) {
      return null;
    }
  }

  /**
   * 1. LINK / URL ANALYSIS ENGINE
   */
  function analyzeLink(inputUrl) {
    const raw = normalizeText(inputUrl);
    const parsed = parseUrlSafely(raw);

    const issues = [];
    let riskScore = 5; // Baseline low risk for any web link

    if (!parsed) {
      return {
        type: 'Link',
        rawInput: raw,
        score: 75,
        category: 'High Risk',
        categoryClass: 'high-risk',
        summary: 'Invalid or malformed URL structure.',
        hostname: 'Unknown',
        protocol: 'Invalid',
        issues: [{
          title: 'Malformed URL',
          description: 'The URL does not adhere to standard Internet formatting rules and may be an obfuscation trick.',
          severity: 'high',
          tag: 'Obfuscation'
        }],
        reasons: ['Malformed or invalid URL syntax is a common evasion technique used in cyber threats.'],
        recommendations: [
          'Do not attempt to visit this link in a standard browser.',
          'Verify the destination with the sender via an independent communication channel.'
        ]
      };
    }

    const protocol = parsed.protocol.replace(':', '');
    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();
    const search = parsed.search.toLowerCase();
    const fullHref = parsed.href;

    // 1. Protocol check
    if (protocol === 'http') {
      riskScore += 25;
      issues.push({
        title: 'Insecure Protocol (HTTP)',
        description: 'The URL uses unencrypted HTTP instead of modern encrypted HTTPS. Data sent over this link can be intercepted.',
        severity: 'medium',
        tag: 'Insecure Transmission'
      });
    }

    // 2. IP Address as Hostname
    const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const isIPv6 = /^\[?[a-f0-9:]+\]?$/i.test(hostname) && hostname.includes(':');
    if (isIPv4 || isIPv6) {
      riskScore += 45;
      issues.push({
        title: 'Numeric IP Address as Hostname',
        description: `Uses a raw IP address (${hostname}) instead of a registered domain name. Legitimate businesses almost never do this.`,
        severity: 'high',
        tag: 'IP Hostname'
      });
    }

    // 3. Userinfo (@ symbol trick)
    if (raw.includes('@')) {
      riskScore += 40;
      issues.push({
        title: 'Embedded Credential Symbol (@)',
        description: 'The URL contains an "@" symbol. Browsers may ignore everything before this symbol, disguising the true destination host.',
        severity: 'high',
        tag: 'Deceptive URL'
      });
    }

    // 4. URL Shortener detection
    const isShortener = URL_SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s));
    if (isShortener) {
      riskScore += 25;
      issues.push({
        title: 'URL Shortener Detected',
        description: `This link uses a shortening service (${hostname}) which obscures the actual destination server.`,
        severity: 'medium',
        tag: 'Hidden Destination'
      });
    }

    // 5. Suspicious TLD
    const hasSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
    if (hasSuspiciousTLD) {
      riskScore += 30;
      issues.push({
        title: 'High-Abuse Domain Extension',
        description: 'The top-level domain is commonly used for spam and phishing due to inexpensive or anonymous registration.',
        severity: 'medium',
        tag: 'Suspicious TLD'
      });
    }

    // 6. Excessive Subdomains
    const domainParts = hostname.split('.');
    if (domainParts.length > 4 && !isIPv4) {
      riskScore += 20;
      issues.push({
        title: 'Excessive Subdomain Stacking',
        description: `Found ${domainParts.length - 2} subdomain levels (${hostname}). Phishing kits frequently stack subdomains to mimic legitimate company structures.`,
        severity: 'medium',
        tag: 'Subdomain Stacking'
      });
    }

    // 7. Suspicious Keywords in Subdomains or Path
    const combinedPath = hostname + pathname + search;
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => {
      const regex = new RegExp(`\\b${kw}\\b|[-_.]${kw}[-_.]`, 'i');
      return regex.test(combinedPath);
    });

    if (foundKeywords.length > 0) {
      const addedRisk = Math.min(foundKeywords.length * 15, 35);
      riskScore += addedRisk;
      issues.push({
        title: 'Sensitive Action Keywords Detected',
        description: `Contains high-risk security keywords: "${foundKeywords.slice(0, 4).join(', ')}". Common in credential harvesting portals.`,
        severity: foundKeywords.length >= 2 ? 'high' : 'medium',
        tag: 'Phishing Keyword'
      });
    }

    // 8. Brand Spoofing / Typosquatting
    let detectedBrand = null;
    for (const brand of FAMOUS_BRANDS) {
      if (brand.regex.test(combinedPath)) {
        // If it mentions brand in path or subdomain but the main domain is not the brand
        const isOfficialDomain = hostname === brand.name.toLowerCase() + '.com' ||
          hostname.endsWith('.' + brand.name.toLowerCase() + '.com');
        if (!isOfficialDomain) {
          detectedBrand = brand.name;
          riskScore += 45;
          issues.push({
            title: `Imitation Pattern: ${brand.name}`,
            description: `The URL references "${brand.name}" but does not belong to the verified official ${brand.name} domain.`,
            severity: 'high',
            tag: 'Brand Spoofing'
          });
          break;
        }
      }
    }

    // 9. Unusual Length
    if (fullHref.length > 120) {
      riskScore += 15;
      issues.push({
        title: 'Unusually Long URL Length',
        description: `URL is ${fullHref.length} characters long. Excessive query parameters may be used to carry tracking or encoded payload scripts.`,
        severity: 'low',
        tag: 'Excessive Length'
      });
    }

    // 10. Unusual Characters / Port Numbers
    if (parsed.port && !['80', '443'].includes(parsed.port)) {
      riskScore += 25;
      issues.push({
        title: `Non-standard Port (:${parsed.port})`,
        description: `Traffic is directed to port ${parsed.port} rather than standard web ports 80 or 443.`,
        severity: 'medium',
        tag: 'Port Redirection'
      });
    }

    if (/[-_]{3,}/.test(hostname)) {
      riskScore += 20;
      issues.push({
        title: 'Repetitive Hyphens/Underscores',
        description: 'Domain exhibits repeated punctuation or unnatural word separators.',
        severity: 'medium',
        tag: 'Domain Anomaly'
      });
    }

    // Normalize final score 0-100
    riskScore = Math.min(Math.max(Math.round(riskScore), 0), 100);

    // Categories
    let category = 'Looks Safe';
    let categoryClass = 'safe';
    let summary = 'No obvious suspicious patterns detected in this link structure.';

    if (riskScore >= 61) {
      category = 'High Risk';
      categoryClass = 'high-risk';
      summary = 'High-risk patterns detected. Likely an imitation, insecure, or deceptive link.';
    } else if (riskScore >= 31) {
      category = 'Suspicious';
      categoryClass = 'suspicious';
      summary = 'Suspicious elements were detected in the URL structure. Exercise caution.';
    }

    // Reasons & Recommendations
    const reasons = issues.map(i => `${i.title}: ${i.description}`);
    if (reasons.length === 0) {
      reasons.push('Standard HTTPS protocol used.', 'Domain structure aligns with standard conventions.', 'No deceptive brand spoofing or known suspicious keywords found.');
    }

    const recommendations = [];
    if (riskScore >= 61) {
      recommendations.push(
        'Do not click or enter any passwords, credit card info, or personal details on this link.',
        'If this link claimed to be from a bank, carrier, or tech provider, visit their official app or website directly instead.',
        'Report this link to your IT security administrator or mark it as phishing in your message app.'
      );
    } else if (riskScore >= 31) {
      recommendations.push(
        'Inspect the destination page carefully before providing any login or payment data.',
        'Look at your browser’s address bar to verify the true domain once loaded.',
        'If asked for an OTP, immediate payment, or password reset, cancel immediately.'
      );
    } else {
      recommendations.push(
        'While this link structure appears standard, always verify the context of who sent it.',
        'Never enter sensitive two-factor authentication codes (OTP) on unverified pages.',
        'Ensure the website address bar displays a valid lock icon.'
      );
    }

    return {
      type: 'Link',
      rawInput: raw,
      parsedUrl: parsed.href,
      hostname: parsed.hostname,
      protocol: protocol.toUpperCase(),
      score: riskScore,
      category,
      categoryClass,
      summary,
      issues,
      reasons,
      recommendations,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * 2. MESSAGE ANALYSIS ENGINE
   */
  function analyzeMessage(messageText) {
    const raw = normalizeText(messageText);
    const issues = [];
    let riskScore = 10; // Baseline low risk for generic incoming message

    if (!raw || raw.length < 5) {
      return {
        type: 'Message',
        rawInput: raw || '(empty)',
        score: 0,
        category: 'Looks Safe',
        categoryClass: 'safe',
        summary: 'No meaningful content to analyze.',
        issues: [],
        reasons: ['Message is too short to evaluate patterns.'],
        recommendations: ['Provide a complete message to scan for security patterns.']
      };
    }

    const lower = raw.toLowerCase();

    // 1. OTP / Verification Code Requests
    const otpPattern = /\b(otp|one[- ]time (?:password|passcode|pin)|verification code|security code|auth code|6-digit code|do not share|never share this code)\b/i;
    if (otpPattern.test(raw)) {
      const match = raw.match(otpPattern)[0];
      riskScore += 35;
      issues.push({
        title: 'OTP / Verification Code Pattern',
        description: 'Mentions one-time passwords or security codes. Scammers routinely prompt victims to relay codes to bypass Multi-Factor Authentication.',
        severity: 'high',
        tag: 'OTP Phishing',
        matchExcerpt: match
      });
    }

    // 2. PIN, Password, Banking Credentials
    const credentialsPattern = /\b(pin|password|passcode|cvv|cvc|credit card|card details|bank details|ssn|social security|routing number|debit card|atm pin)\b/i;
    if (credentialsPattern.test(raw)) {
      const match = raw.match(credentialsPattern)[0];
      riskScore += 35;
      issues.push({
        title: 'Financial / Credential Request',
        description: 'Prompts for sensitive credentials like passwords, PINs, or banking details. Legitimate organizations never solicit PINs via SMS.',
        severity: 'high',
        tag: 'Credential Theft',
        matchExcerpt: match
      });
    }

    // 3. Urgency / Threatening Language
    const urgencyPattern = /\b(urgently|immediately|within 24 hours|within 12 hours|act now|final notice|legal action|warrant|arrest|lawsuit|account blocked|will be closed|action required|suspended today|time-sensitive)\b/i;
    if (urgencyPattern.test(raw)) {
      const match = raw.match(urgencyPattern)[0];
      riskScore += 25;
      issues.push({
        title: 'Urgent / Coercive Language',
        description: 'Uses artificial urgency or threats of closure to induce panic and provoke rapid, uncritical compliance.',
        severity: 'high',
        tag: 'Psychological Coercion',
        matchExcerpt: match
      });
    }

    // 4. Account Suspension / Restriction Claims
    const suspensionPattern = /\b(account (?:has been |is |will be )?(?:suspended|locked|frozen|restricted|disabled)|unusual activity|suspicious activity|unauthorized transaction|security alert|fraud alert)\b/i;
    if (suspensionPattern.test(raw)) {
      const match = raw.match(suspensionPattern)[0];
      riskScore += 30;
      issues.push({
        title: 'Account Suspension / Security Threat Claim',
        description: 'Claims an account has been compromised or restricted. A classic bank impersonation bait.',
        severity: 'high',
        tag: 'Account Fraud Bait',
        matchExcerpt: match
      });
    }

    // 5. Prize / Lottery / Crypto / Free Cash Scams
    const prizePattern = /\b(congratulations|you have won|selected winner|claim your prize|cash prize|lottery|guaranteed returns|crypto giveaway|free gift card|claim \$|reward pending)\b/i;
    if (prizePattern.test(raw)) {
      const match = raw.match(prizePattern)[0];
      riskScore += 30;
      issues.push({
        title: 'Unsolicited Prize / Reward Promise',
        description: 'Claims you have won money or prizes unexpectedly. Usually leads to advance-fee scams or identity theft.',
        severity: 'medium',
        tag: 'Reward Bait',
        matchExcerpt: match
      });
    }

    // 6. Fake Package / Delivery Scams
    const deliveryPattern = /\b(package pending|failed delivery|unclaimed parcel|redelivery fee|delivery attempted|customs fee|update address|postal service|reschedule your package)\b/i;
    if (deliveryPattern.test(raw)) {
      const match = raw.match(deliveryPattern)[0];
      riskScore += 30;
      issues.push({
        title: 'Delivery / Parcel Impersonation',
        description: 'Impersonates a courier or postal service claiming a delivery is held for fees or address confirmation.',
        severity: 'high',
        tag: 'Postal Scam',
        matchExcerpt: match
      });
    }

    // 7. Payment / Wire / Gift Card Requests
    const paymentPattern = /\b(wire transfer|western union|moneygram|gift card|itunes card|steam card|pay fee to release|bitcoin|usdt|crypto wallet)\b/i;
    if (paymentPattern.test(raw)) {
      const match = raw.match(paymentPattern)[0];
      riskScore += 35;
      issues.push({
        title: 'Irreversible Payment Method Requested',
        description: 'Requests payment via crypto, gift cards, or wire transfers, which are untraceable and cannot be refunded.',
        severity: 'high',
        tag: 'Untraceable Payment',
        matchExcerpt: match
      });
    }

    // 8. Fake Verification / Re-activation
    const verifyPattern = /\b(click (?:here|link) to (?:verify|validate|update|unlock|confirm|reactivate)|verify your identity|validate your details)\b/i;
    if (verifyPattern.test(raw)) {
      const match = raw.match(verifyPattern)[0];
      riskScore += 25;
      issues.push({
        title: 'Direct Link Verification Command',
        description: 'Instructs the reader to tap an unverified link to perform sensitive identity or account validation.',
        severity: 'medium',
        tag: 'Phishing Prompt',
        matchExcerpt: match
      });
    }

    // 9. Embedded Link Detection & Deep Check
    const extractedUrls = extractUrls(raw);
    if (extractedUrls.length > 0) {
      riskScore += 15;
      let highestLinkRisk = 0;
      let mostRiskyLinkResult = null;

      extractedUrls.forEach(link => {
        const linkAnalysis = analyzeLink(link);
        if (linkAnalysis.score > highestLinkRisk) {
          highestLinkRisk = linkAnalysis.score;
          mostRiskyLinkResult = linkAnalysis;
        }
      });

      if (mostRiskyLinkResult && mostRiskyLinkResult.score > 30) {
        riskScore += Math.round(mostRiskyLinkResult.score * 0.4);
        issues.push({
          title: `Suspicious Embedded Link (${mostRiskyLinkResult.category})`,
          description: `Embedded URL [${mostRiskyLinkResult.hostname}] scored ${mostRiskyLinkResult.score}/100. Issues: ${mostRiskyLinkResult.issues.map(i => i.title).join(', ')}.`,
          severity: mostRiskyLinkResult.score >= 60 ? 'high' : 'medium',
          tag: 'Risky URL Embedded'
        });
      } else {
        issues.push({
          title: 'Link Present in Message',
          description: `Found ${extractedUrls.length} external URL(s). Be mindful before tapping links from unknown numbers.`,
          severity: 'low',
          tag: 'External Link'
        });
      }
    }

    // Normalize final score 0-100
    riskScore = Math.min(Math.max(Math.round(riskScore), 0), 100);

    // If message is completely benign and short
    if (issues.length === 0 && riskScore < 30) {
      riskScore = 12; // Typical benign score
    }

    // Categories
    let category = 'Looks Safe';
    let categoryClass = 'safe';
    let summary = 'No obvious malicious patterns detected in this message.';

    if (riskScore >= 61) {
      category = 'High Risk';
      categoryClass = 'high-risk';
      summary = 'This message displays strong hallmarks of common phishing or scam tactics.';
    } else if (riskScore >= 31) {
      category = 'Suspicious';
      categoryClass = 'suspicious';
      summary = 'Suspicious elements detected. Proceed with heightened caution.';
    }

    // Safety recommendations
    const recommendations = [];
    if (riskScore >= 61) {
      recommendations.push(
        'Never reply to this message or tap any included links.',
        'Do not share any OTP, PIN, password, or security credentials under any circumstance.',
        'If it claims to be from a service you use (e.g. your bank), call the official phone number printed on your physical card or official statements.',
        'Block and report the sender number as spam.'
      );
    } else if (riskScore >= 31) {
      recommendations.push(
        'Verify the sender through a known, trusted contact channel before acting.',
        'Watch out for artificial urgency or pressure to send funds or click links.',
        'Remember that real institutions will not demand immediate payments via gift cards or crypto.'
      );
    } else {
      recommendations.push(
        'Basic pattern checks found no typical scam signatures.',
        'Stay mindful: even familiar contacts can have their devices compromised.',
        'Never share passwords or two-step verification codes with anyone.'
      );
    }

    return {
      type: 'Message',
      rawInput: raw,
      score: riskScore,
      category,
      categoryClass,
      summary,
      issues,
      extractedLinks: extractedUrls,
      reasons: issues.map(i => `${i.title}: ${i.description}`),
      recommendations,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * 3. WEBSITE SAFETY ENGINE (Domain & Structural Profile)
   */
  function analyzeWebsite(urlOrDomain) {
    const raw = normalizeText(urlOrDomain);
    const linkResult = analyzeLink(raw);

    const parsed = parseUrlSafely(raw);
    const hostname = parsed ? parsed.hostname : raw;
    const protocol = parsed ? parsed.protocol.replace(':', '').toUpperCase() : 'UNKNOWN';
    const domainLength = hostname.length;

    // Structural metrics
    const metrics = {
      protocol: protocol,
      hostname: hostname,
      domainLength: `${domainLength} chars`,
      isHttps: protocol === 'HTTPS',
      subdomainCount: parsed ? Math.max(0, hostname.split('.').length - 2) : 0,
      tld: hostname.includes('.') ? '.' + hostname.split('.').pop() : 'none',
      isIpAddress: /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)
    };

    return {
      type: 'Website',
      rawInput: raw,
      score: linkResult.score,
      category: linkResult.category,
      categoryClass: linkResult.categoryClass,
      summary: linkResult.score > 60
        ? 'Website address shows high-risk structural indicators.'
        : linkResult.score > 30
          ? 'Basic inspection identified potential risk factors.'
          : 'Domain structure aligns with standard conventions.',
      metrics: metrics,
      issues: linkResult.issues,
      reasons: linkResult.reasons,
      recommendations: linkResult.recommendations,
      disclaimer: 'This is a basic client-side analysis. A low-risk result does not guarantee that a website is completely safe.',
      timestamp: new Date().toISOString()
    };
  }

  /**
   * 4. QR CODE ANALYSIS ENGINE
   */
  function analyzeQRCode(content) {
    const raw = normalizeText(content);
    if (!raw) {
      return {
        type: 'QR',
        qrType: 'Empty',
        rawContent: '',
        score: 0,
        category: 'Looks Safe',
        categoryClass: 'safe',
        summary: 'No data decoded from QR code.',
        issues: [],
        reasons: [],
        recommendations: []
      };
    }

    // Detect QR payload type
    let qrType = 'Text';
    let childAnalysis = null;

    if (/^https?:\/\//i.test(raw) || /^www\./i.test(raw) || /^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\/?/i.test(raw)) {
      qrType = 'URL';
      childAnalysis = analyzeLink(raw);
    } else if (/^WIFI:/i.test(raw)) {
      qrType = 'WiFi Network';
      // Parse WiFi parameters: WIFI:T:WPA;S:MySSID;P:mypass;;
      const ssidMatch = raw.match(/S:([^;]+)/i);
      const typeMatch = raw.match(/T:([^;]+)/i);
      const ssid = ssidMatch ? ssidMatch[1] : 'Hidden Network';
      const encType = typeMatch ? typeMatch[1] : 'Unknown';

      const issues = [];
      let score = 15;

      if (encType.toUpperCase() === 'NOPASS' || encType.toUpperCase() === 'NONE') {
        score = 65;
        issues.push({
          title: 'Unsecured Open WiFi Network',
          description: `Network "${ssid}" has no password or encryption. Anyone nearby can monitor unencrypted network traffic.`,
          severity: 'high',
          tag: 'Open WiFi'
        });
      } else if (encType.toUpperCase() === 'WEP') {
        score = 55;
        issues.push({
          title: 'Obsolete WEP Encryption',
          description: 'WEP encryption is cryptographically broken and easily compromised in minutes.',
          severity: 'medium',
          tag: 'Weak Encryption'
        });
      }

      childAnalysis = {
        score,
        category: score >= 60 ? 'High Risk' : score >= 30 ? 'Suspicious' : 'Looks Safe',
        categoryClass: score >= 60 ? 'high-risk' : score >= 30 ? 'suspicious' : 'safe',
        summary: `WiFi configuration for network "${ssid}" (${encType}).`,
        issues,
        reasons: issues.map(i => i.title),
        recommendations: [
          'Verify that this QR code was placed by the legitimate venue owner.',
          'Never connect to untrusted public open Wi-Fi networks without an active VPN.',
          'Do not access sensitive banking portals on unknown shared Wi-Fi.'
        ]
      };
    } else if (/^BEGIN:VCARD/i.test(raw) || /^MECARD:/i.test(raw)) {
      qrType = 'Contact Card';
      childAnalysis = {
        score: 10,
        category: 'Looks Safe',
        categoryClass: 'safe',
        summary: 'Digital vCard contact card.',
        issues: [],
        reasons: ['Standard contact card structure.'],
        recommendations: ['Check phone numbers and email addresses before adding unknown contacts to your address book.']
      };
    } else if (/^SMSTO:/i.test(raw) || /^tel:/i.test(raw) || /^mailto:/i.test(raw)) {
      qrType = 'Communication Action';
      childAnalysis = {
        score: 25,
        category: 'Looks Safe',
        categoryClass: 'safe',
        summary: 'Prompts your device to compose an SMS, phone call, or email.',
        issues: [{
          title: 'Auto-composed Communication',
          description: 'QR codes that prompt SMS messages or calls can be used to trigger premium-rate numbers or verification traps.',
          severity: 'low',
          tag: 'Auto Dial'
        }],
        reasons: ['Triggers native dialer or messaging app.'],
        recommendations: ['Carefully check the destination phone number or email address before tapping Send.']
      };
    } else {
      // General text or message
      qrType = 'Text QR Code';
      childAnalysis = analyzeMessage(raw);
    }

    return {
      type: 'QR',
      qrType,
      rawContent: raw,
      score: childAnalysis.score,
      category: childAnalysis.category,
      categoryClass: childAnalysis.categoryClass,
      summary: childAnalysis.summary,
      issues: childAnalysis.issues || [],
      reasons: childAnalysis.reasons || [],
      recommendations: childAnalysis.recommendations || [],
      timestamp: new Date().toISOString()
    };
  }

  // Demo examples for instant one-click testing
  const DEMO_SAMPLES = {
    messages: [
      {
        id: 'bank-fraud',
        name: 'Bank Fraud Alert',
        text: 'SECURITY ALERT: Unusual activity of $940.00 detected on your Chase debit card. Your account is temporarily suspended. Verify your identity immediately or face account termination: http://chase-security-update.xyz/login'
      },
      {
        id: 'delivery-scam',
        name: 'Postal Delivery Scam',
        text: 'USPS Notice: Your parcel US-94829 has a pending delivery fee of $1.85 due to an incorrect postal address. Reschedule your package within 24 hours to prevent return: http://usps-tracking-redeliver.top/claim'
      },
      {
        id: 'lottery-prize',
        name: 'Lottery Prize Scam',
        text: 'CONGRATULATIONS! You have won a $5,000 cash prize in the International Rewards draw. Reply with your full name, bank details, and the 6-digit OTP code we just texted to claim your funds!'
      },
      {
        id: 'safe-friend',
        name: 'Safe Message (Friend)',
        text: 'Hey Heena! Are we still meeting for coffee tomorrow around 3:30pm? Let me know if that time works for you.'
      }
    ],
    links: [
      {
        id: 'fake-login',
        name: 'Fake Login Portal',
        url: 'http://secure-login.bank-update.xyz/verify-identity?account=locked'
      },
      {
        id: 'shortened-scam',
        name: 'Shortened Link',
        url: 'https://tinyurl.com/free-gift-card-claim99'
      },
      {
        id: 'ip-hostname',
        name: 'IP Address Hostname',
        url: 'http://192.168.1.105:8080/portal/update-billing'
      },
      {
        id: 'safe-amazon',
        name: 'Safe Official Link',
        url: 'https://www.amazon.com/gp/help/customer/display.html'
      }
    ],
    websites: [
      {
        id: 'fake-paypal',
        name: 'Imitation PayPal',
        url: 'http://paypa1-account-secure-verify.top'
      },
      {
        id: 'safe-wikipedia',
        name: 'Safe Wikipedia',
        url: 'https://www.wikipedia.org'
      },
      {
        id: 'safe-github',
        name: 'Safe GitHub',
        url: 'https://github.com'
      }
    ],
    quiz: [
      {
        id: 1,
        scenario: 'You receive an SMS from your bank stating: "Your card is blocked due to suspicious activity. Send the 6-digit code we just sent you to verify your identity."',
        options: [
          'Send the 6-digit code immediately to unblock your card.',
          'Never share the code. Legitimate banks never ask you to text your OTP.',
          'Forward the text to your friends to check if they got it too.'
        ],
        correctIndex: 1,
        explanation: 'One-Time Passwords (OTPs) are meant ONLY for you. If someone asks for your OTP, they are attempting to break into your account or authorize a fraudulent transaction.'
      },
      {
        id: 2,
        scenario: 'You find a QR code sticker pasted over a parking meter asking you to "Scan to Pay Parking Fee". What should you do?',
        options: [
          'Scan it and quickly input your credit card number.',
          'Inspect if the sticker is peeling or covering official instructions, and verify the URL before entering payment details.',
          'Always trust QR codes on physical public objects.'
        ],
        correctIndex: 1,
        explanation: 'Scammers frequently paste malicious QR code stickers ("quishing") over genuine parking meters or restaurant menus to redirect victims to payment harvesting websites.'
      },
      {
        id: 3,
        scenario: 'A link arrives in your inbox: "http://micros0ft-security-update.xyz/login". What gives away that this is risky?',
        options: [
          'It uses HTTP instead of HTTPS.',
          'It substitutes the letter "o" with the digit "0" (typosquatting).',
          'It uses an untrusted TLD (.xyz) instead of the genuine domain microsoft.com.',
          'All of the above.'
        ],
        correctIndex: 3,
        explanation: 'This link displays three classic scam indicators: unencrypted HTTP, typo-brand spoofing ("micros0ft"), and a high-risk spam TLD (.xyz).'
      },
      {
        id: 4,
        scenario: 'You receive a notification: "URGENT! You must transfer $50 via Steam Gift Card within 30 minutes to stop an arrest warrant."',
        options: [
          'Rush to the store to buy the gift card.',
          'Recognize this as a classic urgency scam. Government agencies never demand gift card payments.',
          'Negotiate for a discount on the fee.'
        ],
        correctIndex: 1,
        explanation: 'Scammers use fake urgency and fear to stop you from thinking clearly. No legitimate law enforcement or tax agency ever accepts gift cards as payment.'
      },
      {
        id: 5,
        scenario: 'A friend on social media suddenly messages you: "Hey, I am locked out of my account, can I send a verification code to your phone and have you send it back to me?"',
        options: [
          'Sure, they are your friend so help them out.',
          'Do NOT send the code. The friend\'s account was likely hacked, and the code is actually to reset YOUR account or SIM-swap you.',
          'Send them your bank PIN instead.'
        ],
        correctIndex: 1,
        explanation: 'This is a rampant social engineering takeover scam. The attacker already compromised your friend\'s profile and is now trying to trigger password resets or takeover your accounts.'
      }
    ]
  };

  return {
    analyzeLink,
    analyzeMessage,
    analyzeWebsite,
    analyzeQRCode,
    DEMO_SAMPLES
  };
}));
