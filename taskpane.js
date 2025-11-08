/* global Office */
function extractDomain(addr) {
  const m = (addr || "").toLowerCase().match(/@([^>\s]+)>?$/);
  return m ? m[1] : "";
}

function uniq(arr){ return Array.from(new Set(arr)); }

function findUrls(text) {
  // Pragmatic URL regex (no lookbehinds for broad client support)
  const urlRe = /\bhttps?:\/\/[^\s<>"')]+/gi;
  return uniq((text || "").match(urlRe) || []);
}

function analyze({ from, subject, bodyText, headers }) {
  const reasons = [];
  let score = 0;

  // 1) Headers-based signals
  const authRes = (headers["authentication-results"] || "").toLowerCase();
  const receivedSpf = (headers["received-spf"] || "").toLowerCase();
  const dmarcFail = authRes.includes("dmarc=fail");
  const spfFail = receivedSpf.includes("fail") || authRes.includes("spf=fail");
  const dkimFail = authRes.includes("dkim=fail");

  if (dmarcFail) { score += 35; reasons.push("DMARC = fail in Authentication-Results"); }
  if (spfFail)   { score += 15; reasons.push("SPF = fail"); }
  if (dkimFail)  { score += 15; reasons.push("DKIM = fail"); }

  // 2) Display-name spoofing / address shape
  const display = (from.displayName || "").trim();
  const address = (from.emailAddress || "").trim().toLowerCase();
  const fromDomain = extractDomain(address);
  if (display && display.toLowerCase().includes("@") && !display.includes(address)) {
    score += 10; reasons.push("Display name contains an email (spoofing indicator)");
  }
  if (!fromDomain || !fromDomain.includes(".")) {
    score += 10; reasons.push("Sender domain looks malformed");
  }

  // 3) Content checks
  const text = [subject || "", bodyText || ""].join("\n").toLowerCase();

  const keywords = ["urgent","verify","password","invoice","gift card","wire","overdue","2fa","reset","confirm","pay now"];
  const kwHits = keywords.filter(k => text.includes(k)).length;
  if (kwHits >= 2) { score += 12; reasons.push(`Multiple urgent/financial keywords (${kwHits})`); }

  const urls = findUrls(bodyText || "");
  if (urls.length > 0) reasons.push(`Found ${urls.length} URL(s)`);

  const shorteners = ["bit.ly","tinyurl.com","t.co","ow.ly","buff.ly","rb.gy","is.gd","t.ly","cutt.ly","rebrand.ly"];
  const shortened = urls.filter(u => shorteners.some(s => u.toLowerCase().includes(s)));
  if (shortened.length) { score += 10; reasons.push(`Shortened link(s) detected (${shortened.length})`); }

  const dataUris = urls.filter(u => u.toLowerCase().startsWith("data:"));
  if (dataUris.length) { score += 12; reasons.push("Data URI link(s) embedded"); }

  const formTag = /<\s*form\b/i.test(bodyText || "");
  if (formTag) { score += 10; reasons.push("HTML form present in message"); }

  // 4) Link <> sender mismatch (basic)
  const linkDomains = uniq(urls.map(u => {
    try { return new URL(u).hostname.toLowerCase(); } catch { return ""; }
  }).filter(Boolean));
  if (fromDomain && linkDomains.length) {
    const mismatch = linkDomains.filter(d => d !== fromDomain && !d.endsWith("." + fromDomain));
    if (mismatch.length) { score += 10; reasons.push("Link domains differ from sender domain"); }
  }

  // Clamp and classify
  if (score > 100) score = 100;
  const probability = Math.round(score); // simple calibration
  const riskClass = probability >= 80 ? "risk-high" : probability >= 40 ? "risk-med" : "risk-low";

  return { probability, reasons, riskClass, linkDomains, fromDomain };
}

function setUI(result) {
  const summary = document.getElementById("summary");
  const reasonsEl = document.getElementById("reasons");
  summary.innerHTML = `<div class="score ${result.riskClass}">${result.probability}% risk</div>
    <div>From domain: <code>${result.fromDomain || "n/a"}</code></div>
    <div>Link domains: <code>${(result.linkDomains || []).join(", ") || "none"}</code></div>`;

  reasonsEl.innerHTML = (result.reasons || []).map(r => `<div class="reason">• ${r}</div>`).join("") || "<em>No obvious red flags.</em>";
}

function parseHeaders(raw) {
  // Convert raw RFC822 header block -> lowercase map
  const map = {};
  if (!raw) return map;
  raw.split(/\r?\n(?!\s)/).forEach(line => {
    const idx = line.indexOf(":");
    if (idx > 0) {
      const name = line.slice(0, idx).trim().toLowerCase();
      const value = line.slice(idx + 1).trim();
      map[name] = map[name] ? map[name] + " " + value : value;
    }
  });
  return map;
}

Office.onReady(async () => {
  const item = Office.context.mailbox.item;
  const from = {
    displayName: item.from && item.from.displayName,
    emailAddress: item.from && item.from.emailAddress
  };

  // Get a safe text body (avoid HTML tags confusing regex)
  const bodyText = await new Promise(resolve => {
    item.body.getAsync("text", r => resolve(r.status === Office.AsyncResultStatus.Succeeded ? r.value : ""));
  });

  // Try to get internet headers if the client supports it
  let headers = {};
  if (item.getAllInternetHeadersAsync) {
    try {
      const raw = await new Promise(resolve => item.getAllInternetHeadersAsync(res => resolve(res.status === Office.AsyncResultStatus.Succeeded ? res.value : "")));
      headers = parseHeaders(raw);
    } catch (_) { /* ignore */ }
  }

  const subject = item.subject || "";

  const result = analyze({ from, subject, bodyText, headers });
  setUI(result);
});
