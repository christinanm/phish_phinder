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
    DOMAIN_MISMATCH: 10,
    EMBEDDED_MSG: 8
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

  // Known redirector hosts (SafeLinks, Proofpoint, others) used to try decoding real targets
  REDIRECTOR_HOSTS: new Set([
    'nam01.safelinks.protection.outlook.com',
    'safelinks.protection.outlook.com',
    'urldefense.proofpoint.com',
    'urldefense.sharepoint.com',
    'www.google.com'
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
 * Extracts href targets from an HTML body. This is more reliable than regex on text
 * because anchors contain the authoritative href (which may differ from displayed text).
 * It also attempts to decode common redirector patterns (SafeLinks, Proofpoint, etc.)
 * @param {string} html HTML string
 * @returns {string[]} Array of resolved target URLs (unique)
 */
function extractHrefTargetsFromHtml(html) {
  if (!html) return [];
  try {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const anchors = Array.from(doc.querySelectorAll('a[href]'));
    const results = [];

    // Known redirector hosts and parameter names where the real target is embedded
    const knownRedirectHosts = new Set([
      'nam01.safelinks.protection.outlook.com',
      'safelinks.protection.outlook.com',
      'urldefense.proofpoint.com',
      'urldefense.sharepoint.com',
      'www.google.com'
    ]);

    const redirectParams = ['url', 'u', 'target', 'q', 'r'];

    anchors.forEach(a => {
      try {
        const raw = a.getAttribute('href');
        if (!raw) return;

        // Resolve relative URLs against a base; using window.location might be wrong in some hosts
        const resolved = new URL(raw, 'https://localhost');

        // If this is a known redirector, try to extract the embedded target parameter
        if (knownRedirectHosts.has(resolved.hostname)) {
          for (const p of redirectParams) {
            const param = resolved.searchParams.get(p);
            if (param) {
              try {
                const decoded = decodeURIComponent(param);
                // normalize
                results.push(new URL(decoded).toString());
                return; // next anchor
              } catch (e) {
                // not a full URL after decode; continue
              }
            }
          }
          // Fallback: use the redirector URL itself
          results.push(resolved.toString());
        } else {
          results.push(resolved.toString());
        }
      } catch (e) {
        // ignore malformed hrefs
      }
    });

    return uniq(results);
  } catch (e) {
    return [];
  }
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
 * Attempt to decode known redirector URLs to their embedded target.
 * If the url is not a known redirector or no embedded target is found, returns the original URL string.
 * @param {string} urlStr
 * @returns {string} decoded url string or original
 */
function decodeRedirectTarget(urlStr) {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase();
    if (!CONFIG.REDIRECTOR_HOSTS.has(host)) return urlStr;

    // Common parameter names where real target is stored
    const params = ['url', 'u', 'target', 'q', 'r'];
    for (const p of params) {
      const v = u.searchParams.get(p);
      if (v) {
        try {
          const decoded = decodeURIComponent(v);
          return new URL(decoded).toString();
        } catch (e) {
          // ignore and continue
        }
      }
    }
    return urlStr;
  } catch (e) {
    return urlStr;
  }
}

/**
 * Analyzes an email for phishing indicators
 * @param {Object} params Analysis parameters
 * @param {Object} params.from Sender information
 * @param {string} params.subject Email subject
 * @param {string} params.bodyText Email body text
 * @param {Object} params.headers Email headers
 * @param {string} params.html Email body as HTML (if available)
 * @param {Array} params.attachments Attachment metadata from the item (if available)
 * @returns {Object} Analysis results with risk score and reasons
 */
function analyze({ from, subject, bodyText, headers, html, attachments }) {
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

  // URL analysis -- combine URLs found in the plain text body with anchor hrefs found in HTML if available
  const textUrls = findUrls(bodyText || '');
  const htmlUrls = extractHrefTargetsFromHtml(html || '');
  // Merge and dedupe
  const urls = uniq(textUrls.concat(htmlUrls));
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
  // First, try to decode any redirector URLs so we evaluate the real targets
  const decodedTargets = urls.map(u => {
    try {
      return decodeRedirectTarget(u);
    } catch {
      return u;
    }
  });

  const linkDomains = uniq(decodedTargets.map(u => {
    try {
      const hostname = new URL(u).hostname.toLowerCase();
      return getRegistrableDomain(hostname);
    } catch {
      return '';
    }
  }).filter(Boolean));

  // Detect if message looks like a forward/resend: check Resent-* headers or embedded item attachments
  const isForward = Boolean(headers['resent-from'] || headers['resent-sender']);
  let hasEmbeddedMsg = false;
  if (attachments && attachments.length) {
    for (const att of attachments) {
      const attType = att.attachmentType || att.type || '';
      if (attType === 'item') {
        hasEmbeddedMsg = true;
        break;
      }
    }
  }
  if (hasEmbeddedMsg) {
    score += CONFIG.WEIGHTS.EMBEDDED_MSG;
    reasons.push('Message contains embedded message attachment (likely forwarded)');
  }

  if (fromDomain && linkDomains.length) {
    const fromRegistrableDomain = getRegistrableDomain(fromDomain);
    const mismatchDomains = linkDomains.filter(d => 
      d !== fromRegistrableDomain && !d.endsWith('.' + fromRegistrableDomain)
    );

    if (mismatchDomains.length) {
      if (isForward || hasEmbeddedMsg) {
        // If this is a forwarded message, skip the generic domain-mismatch penalty but record it
        reasons.push(`Message appears forwarded; links point to different domains: ${mismatchDomains.join(', ')}`);
      } else {
        score += CONFIG.WEIGHTS.DOMAIN_MISMATCH;
        reasons.push(`Links point to different domains: ${mismatchDomains.join(', ')}`);
      }
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
 * Show a small matrix-style loader in the #status element
 */
function showLoader() {
  const st = document.getElementById('status');
  if (!st) return;
  // Clear previous
  while (st.firstChild) st.removeChild(st.firstChild);

  const loader = document.createElement('span');
  loader.className = 'loader';

  const matrix = document.createElement('span');
  matrix.className = 'matrix';
  // create a longer, denser stream of binary digits for the visual effect
  const len = 52; // number of bits in the stream
  let bits = '';
  for (let i = 0; i < len; i++) {
    bits += (Math.random() < 0.5 ? '1' : '0');
  }
  for (const ch of bits) {
    const s = document.createElement('span');
    s.textContent = ch;
    matrix.appendChild(s);
  }

  const text = document.createElement('span');
  text.className = 'loader-text';
  text.textContent = 'analyzing message...';

  // matrix stream first, then label under it
  loader.appendChild(matrix);
  loader.appendChild(text);
  st.appendChild(loader);
}

/**
 * Hide the loader and clear the status area
 */
function hideLoader() {
  const st = document.getElementById('status');
  if (!st) return;
  while (st.firstChild) st.removeChild(st.firstChild);
}

/**
 * Initializes the add-in when Office.js is ready
 */
Office.onReady(async () => {
  try {
    // show a loader while we fetch the message and run analysis
    showLoader();
    const item = Office.context.mailbox.item;
    if (!item) {
      hideLoader();
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

    // Also attempt to get the HTML body so we can extract anchor hrefs reliably
    let bodyHtml = '';
    try {
      bodyHtml = await new Promise((resolve, reject) => {
        item.body.getAsync('html', result => {
          if (result.status === Office.AsyncResultStatus.Succeeded) {
            resolve(result.value);
          } else {
            // Not all clients support getting HTML; fall back silently
            resolve('');
          }
        });
      });
    } catch (error) {
      console.error('Failed to get email HTML body:', error);
      bodyHtml = '';
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
  const attachments = item.attachments || [];
  const result = analyze({ from, subject, bodyText, headers, html: bodyHtml, attachments });
    setUI(result);
    hideLoader();
    
  } catch (error) {
    hideLoader();
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
