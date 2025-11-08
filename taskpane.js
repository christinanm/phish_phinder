/* global Office */

/**
 * Configuration constants for phishing detection
 * These values can be adjusted based on false positive/negative rates
 */
const CONFIG = {
  // Scoring weights for different signals
  WEIGHTS: {
    DMARC_FAIL: 35,
    SPF_FAIL: 15,
    DKIM_FAIL: 15,
    DISPLAY_NAME_SPOOF: 10,
    MALFORMED_DOMAIN: 10,
    KEYWORD_MULTIPLE: 12,
    SHORTENED_LINK: 10,
    DATA_URI: 12,
    HTML_FORM: 10,
    DOMAIN_MISMATCH: 10
  },
  
  // Risk classification thresholds
  RISK_THRESHOLDS: {
    HIGH: 80,
    MEDIUM: 40
  },

  // Known URL shortener domains
  SHORTENER_DOMAINS: new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'buff.ly',
    'rb.gy', 'is.gd', 't.ly', 'cutt.ly', 'rebrand.ly'
  ]),

  // Suspicious keywords that may indicate phishing
  SUSPICIOUS_KEYWORDS: [
    'urgent', 'verify', 'password', 'invoice', 'gift card',
    'wire', 'overdue', '2fa', 'reset', 'confirm', 'pay now'
  ]
};

/**
 * Safely creates and appends DOM elements with text content
 * @param {string} tagName HTML element tag
 * @param {string} text Text content to set
 * @param {string[]} classNames CSS classes to add
 * @param {HTMLElement} parent Parent element to append to
 * @returns {HTMLElement} The created element
 */
function createSafeElement(tagName, text, classNames = [], parent = null) {
  const element = document.createElement(tagName);
  element.textContent = text;
  if (classNames.length) {
    element.className = classNames.join(' ');
  }
  if (parent) {
    parent.appendChild(element);
  }
  return element;
}

/**
 * Extracts domain from an email address with proper RFC5322 handling
 * @param {string} addr Email address to parse
 * @returns {string} Domain part of the email or empty string
 */
function extractDomain(addr) {
  if (!addr) return '';
  
  // Remove any display name parts and get just the email
  const emailPart = addr.toLowerCase().match(/<(.+@[^>]+)>|([^<\s]+@[^\s>]+)/);
  if (!emailPart) return '';

  const email = emailPart[1] || emailPart[2];
  const domainPart = email.split('@')[1];
  
  return domainPart || '';
}

/**
 * Returns unique array elements using Set
 * @template T
 * @param {T[]} arr Input array
 * @returns {T[]} Array with duplicate elements removed
 */
function uniq(arr) {
  return Array.from(new Set(arr));
}

/**
 * Finds URLs in text with improved pattern matching
 * @param {string} text Input text to search for URLs
 * @returns {string[]} Array of unique URLs found
 */
function findUrls(text) {
  if (!text) return [];
  
  // Enhanced URL regex that handles punctuation and parentheses
  const urlRe = /\bhttps?:\/\/[^\s<>"'`{}|\^\[\]\\]+/gi;
  const matches = text.match(urlRe) || [];
  
  // Clean up and normalize URLs
  return uniq(matches.map(url => {
    try {
      // Remove trailing punctuation and normalize
      url = url.replace(/[.,;!?)]+$/, '');
      return new URL(url).toString();
    } catch {
      return url;
    }
  }));
}

/**
 * Parses email headers with proper folding support
 * @param {string} raw Raw RFC822 header block
 * @returns {Object.<string, string>} Map of header names to values
 */
function parseHeaders(raw) {
  const headers = {};
  if (!raw) return headers;

  // Split on header boundaries (lines not starting with whitespace)
  const headerLines = raw.split(/\r?\n(?!\s)/);
  
  let currentHeader = '';
  let currentValue = '';

  headerLines.forEach(line => {
    if (line.match(/^\s/)) {
      // Continuation of previous header
      currentValue += ' ' + line.trim();
    } else {
      // Save previous header if any
      if (currentHeader) {
        headers[currentHeader] = currentValue.trim();
      }
      
      // Start new header
      const match = line.match(/^([^:]+):\s*(.*)$/);
      if (match) {
        currentHeader = match[1].toLowerCase();
        currentValue = match[2];
      }
    }
  });

  // Save last header
  if (currentHeader) {
    headers[currentHeader] = currentValue.trim();
  }

  return headers;
}

/**
 * Extracts authentication results from headers
 * @param {Object.<string, string>} headers Parsed email headers
 * @returns {{dmarc: string, spf: string, dkim: string}} Authentication status
 */
function parseAuthResults(headers) {
  const authRes = (headers['authentication-results'] || '').toLowerCase();
  const receivedSpf = (headers['received-spf'] || '').toLowerCase();

  const results = {
    dmarc: 'none',
    spf: 'none',
    dkim: 'none'
  };

  // Parse DMARC
  const dmarcMatch = authRes.match(/\bdmarc=([a-z]+)/);
  if (dmarcMatch) results.dmarc = dmarcMatch[1];

  // Parse SPF (check both headers)
  const spfMatch = receivedSpf.match(/\b(pass|fail|softfail|neutral|none)\b/) ||
                  authRes.match(/\bspf=([a-z]+)/);
  if (spfMatch) results.spf = spfMatch[1];

  // Parse DKIM
  const dkimMatch = authRes.match(/\bdkim=([a-z]+)/);
  if (dkimMatch) results.dkim = dkimMatch[1];

  return results;
}

/**
 * Gets the registrable domain from a hostname
 * Simple implementation - in production, use a proper public suffix list library
 * @param {string} hostname Full hostname
 * @returns {string} Registrable domain
 */
function getRegistrableDomain(hostname) {
  if (!hostname) return '';
  
  // Basic implementation - split and take last two parts
  // TODO: Replace with proper public suffix list handling
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join('.');
}

/**
 * Analyzes an email for phishing indicators
 * @param {Object} params Analysis parameters
 * @param {Object} params.from Sender information
 * @param {string} params.subject Email subject
 * @param {string} params.bodyText Email body text
 * @param {Object} params.headers Email headers
 * @returns {Object} Analysis results with risk score and reasons
 */
function analyze({ from, subject, bodyText, headers }) {
  const reasons = [];
  let score = 0;

  // Validate inputs
  if (!from || !from.emailAddress) {
    return {
      probability: 0,
      reasons: ['Unable to analyze: Missing sender information'],
      riskClass: 'risk-low',
      linkDomains: [],
      fromDomain: ''
    };
  }

  // 1) Parse authentication results
  const auth = parseAuthResults(headers);
  
  if (auth.dmarc === 'fail') {
    score += CONFIG.WEIGHTS.DMARC_FAIL;
    reasons.push('DMARC authentication failed!');
  }
  if (auth.spf === 'fail') {
    score += CONFIG.WEIGHTS.SPF_FAIL;
    reasons.push('SPF check failed!');
  }
  if (auth.dkim === 'fail') {
    score += CONFIG.WEIGHTS.DKIM_FAIL;
    reasons.push('DKIM signature verification failed!');
  }

  // 2) Analyze display name for spoofing
  const display = (from.displayName || '').trim();
  const address = (from.emailAddress || '').trim().toLowerCase();
  const fromDomain = extractDomain(address);
  
  if (display && display.toLowerCase().includes('@') && !display.includes(address)) {
    score += CONFIG.WEIGHTS.DISPLAY_NAME_SPOOF;
    reasons.push('Display name contains different email address (potential spoofing)');
  }
  
  if (!fromDomain || !fromDomain.includes('.')) {
    score += CONFIG.WEIGHTS.MALFORMED_DOMAIN;
    reasons.push('Sender domain appears malformed');
  }

  // 3) Content analysis
  const text = [subject || '', bodyText || ''].join('\n').toLowerCase();
  
  // Check for suspicious keywords
  const foundKeywords = CONFIG.SUSPICIOUS_KEYWORDS.filter(k => text.includes(k));
  if (foundKeywords.length >= 2) {
    score += CONFIG.WEIGHTS.KEYWORD_MULTIPLE;
    reasons.push(`Multiple suspicious keywords found: ${foundKeywords.join(', ')}`);
  }

  // URL analysis
  const urls = findUrls(bodyText || '');
  if (urls.length > 0) {
    reasons.push(`Found ${urls.length} URL(s) in message`);
  }

  // Check for URL shorteners
  const shortened = urls.filter(u => {
    try {
      const hostname = new URL(u).hostname.toLowerCase();
      return CONFIG.SHORTENER_DOMAINS.has(hostname);
    } catch {
      return false;
    }
  });
  
  if (shortened.length) {
    score += CONFIG.WEIGHTS.SHORTENED_LINK;
    reasons.push(`Found ${shortened.length} shortened URL(s)`);
  }

  // Check for data: URIs
  const dataUris = urls.filter(u => u.toLowerCase().startsWith('data:'));
  if (dataUris.length) {
    score += CONFIG.WEIGHTS.DATA_URI;
    reasons.push('Found embedded data: URI(s)');
  }

  // Check for HTML forms
  const formTag = /<\s*form\b/i.test(bodyText || '');
  if (formTag) {
    score += CONFIG.WEIGHTS.HTML_FORM;
    reasons.push('HTML form detected in message body');
  }

  // 4) Domain alignment check
  const linkDomains = uniq(urls.map(u => {
    try {
      const hostname = new URL(u).hostname.toLowerCase();
      return getRegistrableDomain(hostname);
    } catch {
      return '';
    }
  }).filter(Boolean));

  if (fromDomain && linkDomains.length) {
    const fromRegistrableDomain = getRegistrableDomain(fromDomain);
    const mismatchDomains = linkDomains.filter(d => 
      d !== fromRegistrableDomain && !d.endsWith('.' + fromRegistrableDomain)
    );
    
    if (mismatchDomains.length) {
      score += CONFIG.WEIGHTS.DOMAIN_MISMATCH;
      reasons.push(`Links point to different domains: ${mismatchDomains.join(', ')}`);
    }
  }

  // Clamp score and classify risk
  score = Math.min(score, 100);
  const probability = Math.round(score);
  
  const riskClass = probability >= CONFIG.RISK_THRESHOLDS.HIGH ? 'risk-high' :
                    probability >= CONFIG.RISK_THRESHOLDS.MEDIUM ? 'risk-med' : 
                    'risk-low';

  return { probability, reasons, riskClass, linkDomains, fromDomain };
}

/**
 * Updates the UI with analysis results using safe DOM manipulation
 * @param {Object} result Analysis results to display
 */
function setUI(result) {
  const summary = document.getElementById('summary');
  const reasonsEl = document.getElementById('reasons');

  // Clear existing content
  while (summary.firstChild) summary.removeChild(summary.firstChild);
  while (reasonsEl.firstChild) reasonsEl.removeChild(reasonsEl.firstChild);

  // Add score with proper class
  createSafeElement('div', `${result.probability}% risk`, ['score', result.riskClass], summary);
  
  // Add from domain
  createSafeElement('div', 'From domain: ', [], summary);
  createSafeElement('code', result.fromDomain || 'n/a', [], summary);

  // Add link domains
  createSafeElement('div', 'Link domains: ', [], summary);
  createSafeElement('code', 
    (result.linkDomains || []).join(', ') || 'none',
    [],
    summary
  );

  // Add reasons
  if (result.reasons && result.reasons.length) {
    result.reasons.forEach(reason => {
      createSafeElement('div', `• ${reason}`, ['reason'], reasonsEl);
    });
  } else {
    createSafeElement('em', 'No obvious red flags.', [], reasonsEl);
  }
}

/**
 * Initializes the add-in when Office.js is ready
 */
Office.onReady(async () => {
  try {
    const item = Office.context.mailbox.item;
    if (!item) {
      setUI({
        probability: 0,
        reasons: ['Unable to access email item'],
        riskClass: 'risk-low',
        linkDomains: [],
        fromDomain: ''
      });
      return;
    }

    const from = {
      displayName: item.from && item.from.displayName,
      emailAddress: item.from && item.from.emailAddress
    };

    // Get plain text body with error handling
    let bodyText = '';
    try {
      bodyText = await new Promise((resolve, reject) => {
        item.body.getAsync('text', result => {
          if (result.status === Office.AsyncResultStatus.Succeeded) {
            resolve(result.value);
          } else {
            reject(new Error(result.error.message));
          }
        });
      });
    } catch (error) {
      console.error('Failed to get email body:', error);
    }

    // Try to get internet headers if supported
    let headers = {};
    if (item.getAllInternetHeadersAsync) {
      try {
        const raw = await new Promise((resolve, reject) => {
          item.getAllInternetHeadersAsync(result => {
            if (result.status === Office.AsyncResultStatus.Succeeded) {
              resolve(result.value);
            } else {
              reject(new Error(result.error.message));
            }
          });
        });
        headers = parseHeaders(raw);
      } catch (error) {
        console.error('Failed to get email headers:', error);
      }
    }

    const subject = item.subject || '';
    const result = analyze({ from, subject, bodyText, headers });
    setUI(result);
    
  } catch (error) {
    console.error('Add-in initialization failed:', error);
    setUI({
      probability: 0,
      reasons: ['Analysis failed: ' + error.message],
      riskClass: 'risk-low',
      linkDomains: [],
      fromDomain: ''
    });
  }
});
