// Holt News + Schwachstellen serverseitig und schreibt data.json (läuft in GitHub Actions, Node 20)
import { readFileSync, writeFileSync } from "node:fs";

const IT_FILTER = /dora|ikt\b|ikt-|\bit-|cyber|nis2|nis-2|informationssicherheit|resilien|cloud|outsourcing|drittdienstleister|k[uü]nstliche intelligenz|\bki\b|\bki-|ai act|\bai\b|datenschutz|dsgvo|krypto|mica|tiber|bait|vait|kritis|schwachstelle|verschl[uü]sselung|operational resilience|information security|ict/i;
const FEEDS = {
  heise: [
    { name: "heise online", url: "https://www.heise.de/rss/heise-atom.xml", heise: "full" },
    { name: "heise Security", url: "https://www.heise.de/security/feed.xml", heise: "exclude" },
    { name: "heise · Digitale Souveränität", url: "https://news.google.com/rss/search?q=" + encodeURIComponent('"digitale Souveränität" site:heise.de when:30d') + "&hl=de&gl=DE&ceid=DE:de" }],
  bsi: [
    { name: "BSI", url: "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_Presse.xml" },
    { name: "CERT-Bund", url: "https://wid.cert-bund.de/content/public/securityAdvisory/rss" }],
  reg: [
    { name: "BaFin", url: "https://www.bafin.de/SiteGlobals/Functions/RSSFeed/DE/RSSNewsfeed/RSSNewsfeed_Meldungen.xml", filter: true },
    { name: "EZB", url: "https://www.ecb.europa.eu/rss/press.html", filter: true },
    { name: "Google News (IT-Regulierung)", url: "https://news.google.com/rss/search?q=" + encodeURIComponent('DORA OR NIS2 OR "Cyber Resilience Act" OR "KI-Verordnung" OR "IKT-Risiko" OR BaFin Cybersicherheit when:14d') + "&hl=de&gl=DE&ceid=DE:de" }],
  ai: [
    { name: "Google News (KI)", url: "https://news.google.com/rss/search?q=" + encodeURIComponent('KI OR LLM OR "KI-Agenten" OR OpenAI OR Anthropic when:3d') + "&hl=de&gl=DE&ceid=DE:de" }],
};
// ---- heise: Themenfilter (Stichwörter hier anpassen) ----
const HEISE_SOVEREIGN = /souver[aä]n|sovereign|abh[aä]ngigkeit|gaia-x|eurostack|opendesk|cloud act|europ[aä]ische cloud|bundescloud/i;
const HEISE_INCLUDE = new RegExp([
  // Security & Schwachstellen
  "sicherheitsl[uü]cke|schwachstelle|ransomware|patch|exploit|cyber|hacker|malware|phishing|datenleck|zero-day|\\bcve|verschl[uü]ssel|\\bbsi\\b|sicherheit",
  // Cloud & Infrastruktur
  "cloud|microsoft|\\baws\\b|azure|rechenzentrum|kubernetes|vmware|infrastruktur",
  // KI
  "\\bki\\b|\\bki-|k[uü]nstliche intelligenz|chatgpt|\\bllm|openai|anthropic|claude|copilot|gemini",
  // Regulierung & Datenschutz
  "dsgvo|datenschutz|nis-?2|\\bdora\\b|cyber resilience|ai act|ki-verordnung|regulier|kritis|eu-kommission",
  // Betriebssysteme & Software
  "windows|linux|apple|macos|\\bios\\b|betriebssystem|open source",
].join("|"), "i");
const HEISE_EXCLUDE = /im test|\bdeals?\b|angebot|rabatt|schn[aä]ppchen|gaming|\bgames?\b|spiele|playstation|xbox|nintendo|steam deck|smartphone|handy|e-bike|fernseher|kopfh[oö]rer|kamera/i;
// mode "full" = Themenfilter + Ausschluss, "exclude" = nur Ausschluss
const heiseOk = (i, mode) => {
  if (HEISE_SOVEREIGN.test(i.title + " " + i.desc)) return true;
  if (HEISE_EXCLUDE.test(i.title)) return false;
  return mode === "exclude" || HEISE_INCLUDE.test(i.title + " " + i.desc);
};
const MIN_SCORE = 9.0, DAYS = 30;
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const get = async (url, tries = 3) => {
  for (let i = 1; ; i++) {
    try {
      const r = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 (compatible; IT-Cockpit/1.0)" }, signal: AbortSignal.timeout(25000) });
      if (!r.ok) throw new Error("HTTP " + r.status);
      return await r.text();
    } catch (e) { if (i >= tries) throw e; await new Promise(r => setTimeout(r, 6000)); }
  }
};
const decode = s => s.replace(/<!\[CDATA\[|\]\]>/g, "").replace(/<[^>]*>/g, " ")
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
  .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(n)).replace(/&amp;/g, "&").replace(/\s+/g, " ").trim();
const tag = (b, n) => (b.match(new RegExp(`<${n}(?:\\s[^>]*)?>([\\s\\S]*?)</${n}>`, "i")) || [])[1] || "";

function parse(xml, src) {
  return (xml.match(/<(item|entry)[\s>][\s\S]*?<\/\1>/gi) || []).map(b => {
    const href = (b.match(/<link[^>]*href=["']([^"']+)["']/i) || [])[1];
    const d = new Date(decode(tag(b, "pubDate") || tag(b, "published") || tag(b, "updated") || tag(b, "dc:date")));
    return {
      title: decode(tag(b, "title")), link: href || decode(tag(b, "link")),
      date: isNaN(d) ? null : d.toISOString(), src,
      desc: decode(tag(b, "description") || tag(b, "summary")).slice(0, 300),
    };
  }).filter(i => i.title && i.link);
}

let old = {};
try { old = JSON.parse(readFileSync("data.json", "utf8")); } catch {}
const out = { updated: new Date().toISOString(), feeds: {}, vulns: [] };

for (const [key, list] of Object.entries(FEEDS)) {
  let items = [];
  const status = [];
  for (const f of list) {
    try {
      let it = parse(await get(f.url, 2), f.name);
      if (f.filter) it = it.filter(i => IT_FILTER.test(i.title + " " + i.desc));
      if (f.heise) it = it.filter(i => heiseOk(i, f.heise));
      items = items.concat(it);
      status.push({ name: f.name, ok: true });
      console.log("OK  ", f.name, it.length);
    } catch (e) { status.push({ name: f.name, ok: false }); console.log("FAIL", f.name, e.message); }
  }
  items.sort((a, b) => (b.date || "").localeCompare(a.date || ""));
  out.feeds[key] = items.length ? { items: items.slice(0, 30), status } : { ...(old.feeds?.[key] || { items: [] }), status };
}

try {
  let kev = new Set();
  try { kev = new Set(JSON.parse(await get(KEV_URL)).vulnerabilities.map(v => v.cveID)); } catch (e) { console.log("KEV FAIL", e.message); }
  const end = new Date(), start = new Date(end - DAYS * 864e5), f = d => d.toISOString().slice(0, -1);
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&pubStartDate=${f(start)}&pubEndDate=${f(end)}&resultsPerPage=2000`;
  const data = JSON.parse(await get(url));
  out.vulns = (data.vulnerabilities || []).map(({ cve }) => {
    const m = cve.metrics || {};
    const score = (m.cvssMetricV31 || m.cvssMetricV30 || [])[0]?.cvssData?.baseScore || 0;
    const cpe = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria?.split(":");
    const prod = cpe ? [cpe[3], cpe[4]].filter(x => x && x !== "*").join(" ").replace(/_/g, " ") : "";
    const desc = (cve.descriptions.find(d => d.lang === "en") || cve.descriptions[0] || {}).value || "";
    return { id: cve.id, score, pub: cve.published, kev: kev.has(cve.id), prod, desc: desc.slice(0, 300) };
  }).filter(v => v.score >= MIN_SCORE).sort((a, b) => b.score - a.score || b.pub.localeCompare(a.pub));
  console.log("NVD OK", out.vulns.length);
} catch (e) { console.log("NVD FAIL", e.message); out.vulns = old.vulns || []; }

writeFileSync("data.json", JSON.stringify(out));
