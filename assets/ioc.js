/* IOC parsing + pivot links. Pure functions, no DOM, so it can be tested in Node. */
(function (root) {
  const refang = (s) => s
    .replace(/hxxp/gi, "http")
    .replace(/fxp/gi, "ftp")
    .replace(/\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}/gi, ".")
    .replace(/\[\s*:\s*\]/g, ":")
    .replace(/\[\s*(?:@|at)\s*\]|\(\s*(?:@|at)\s*\)/gi, "@")
    .replace(/\[\/\/\]/g, "//")
    .replace(/\[\s*\/\s*\]/g, "/");

  const defang = (s) => s
    .replace(/^http/i, (m) => (m === "http" ? "hxxp" : "hXXp"))
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");

  const RE = {
    url: /\b(?:https?|ftp):\/\/[^\s<>"'`)\]}]+/gi,
    email: /\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi,
    cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
    // JA4 (client): t13d1516h2_<12 hex>_<12 hex>. JA4S (server): t130200_<4 hex>_<12 hex>.
    ja4: /\b[tqd]\d{2}[di]\d{2}\d{2}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}\b/gi,
    ja4s: /\b[tqd]\d{2}\d{2}[a-z0-9]{2}_[a-f0-9]{4}_[a-f0-9]{12}\b/gi,
    sha256: /\b[a-f0-9]{64}\b/gi,
    sha1: /\b[a-f0-9]{40}\b/gi,
    md5: /\b[a-f0-9]{32}\b/gi,
    ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    ipv6: /\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b|\b(?:[a-f0-9]{1,4}:){1,7}:(?:[a-f0-9]{1,4})?\b/gi,
    domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,})\b/gi,
  };

  // Common file extensions that look like TLDs when embedded in text.
  const FAKE_TLD = new Set(["exe", "dll", "sys", "bat", "ps1", "vbs", "js", "png", "jpg", "gif", "txt", "log", "doc", "docx",
    "xls", "xlsx", "pdf", "zip", "rar", "html", "htm", "php", "asp", "aspx", "json", "xml", "csv", "tmp", "ini", "cfg", "py", "sh", "md", "lnk", "dat", "bin", "msi", "iso"]);

  function privateIPv4(ip) {
    const [a, b] = ip.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }

  // opts.hex32: how to label bare 32-character hex strings. A JA3 hash and an MD5 look identical,
  // so the user chooses: "md5" (default) or "ja3".
  function extract(text, opts) {
    opts = opts || {};
    const hex32Type = opts.hex32 === "ja3" ? "ja3" : "md5";
    const src = refang(text || "");
    const found = new Map(); // key = type|value
    const add = (type, value, extra) => {
      const key = type + "|" + (type === "domain" || type === "email" || /^(md5|sha1|sha256|ja3|ja4|ja4s)$/.test(type) ? value.toLowerCase() : value);
      if (!found.has(key)) found.set(key, { type, value: key.split("|").slice(1).join("|"), count: 0, ...extra });
      found.get(key).count++;
    };
    let rest = src;
    const take = (type, re, fn) => {
      rest = rest.replace(re, (m) => { (fn || ((x) => add(type, x)))(m); return " "; });
    };
    take("url", RE.url, (m) => add("url", m.replace(/[.,;:!?]+$/, "")));
    // Domains inside URLs are also useful pivots.
    for (const k of [...found.values()].filter((f) => f.type === "url")) {
      try { const h = new URL(k.value).hostname; if (!/^[\d.]+$/.test(h) && !h.includes(":")) add("domain", h); else if (/^[\d.]+$/.test(h)) add("ip", h, { private: privateIPv4(h) }); } catch (e) {}
    }
    take("email", RE.email, (m) => { add("email", m); add("domain", m.split("@")[1]); });
    take("cve", RE.cve, (m) => add("cve", m.toUpperCase()));
    take("ja4", RE.ja4, (m) => add("ja4", m));
    take("ja4s", RE.ja4s, (m) => add("ja4s", m));
    take("sha256", RE.sha256, (m) => add("sha256", m));
    take("sha1", RE.sha1, (m) => add("sha1", m));
    take(hex32Type, RE.md5, (m) => add(hex32Type, m));
    take("ip", RE.ipv4, (m) => add("ip", m, { private: privateIPv4(m) }));
    take("ip", RE.ipv6, (m) => add("ip", m.toLowerCase(), { private: /^(fe80|fc|fd|::1$)/i.test(m) }));
    take("domain", RE.domain, (m) => {
      const tld = m.split(".").pop().toLowerCase();
      if (FAKE_TLD.has(tld)) return;
      add("domain", m);
    });
    return [...found.values()];
  }

  const enc = encodeURIComponent;
  function pivots(ioc) {
    const v = ioc.value, e = enc(v);
    switch (ioc.type) {
      case "ip": return [
        ["VirusTotal", `https://www.virustotal.com/gui/ip-address/${e}`],
        ["AbuseIPDB", `https://www.abuseipdb.com/check/${e}`],
        ["GreyNoise", `https://viz.greynoise.io/ip/${e}`],
        ["Talos", `https://talosintelligence.com/reputation_center/lookup?search=${e}`],
        ["Shodan", `https://www.shodan.io/host/${e}`],
        ["OTX", `https://otx.alienvault.com/indicator/ip/${e}`],
        ["X-Force", `https://exchange.xforce.ibmcloud.com/ip/${e}`],
        ["Censys", `https://search.censys.io/hosts/${e}`],
      ];
      case "domain": return [
        ["VirusTotal", `https://www.virustotal.com/gui/domain/${e}`],
        ["Talos", `https://talosintelligence.com/reputation_center/lookup?search=${e}`],
        ["X-Force", `https://exchange.xforce.ibmcloud.com/url/${e}`],
        ["urlscan", `https://urlscan.io/search/#domain:${e}`],
        ["OTX", `https://otx.alienvault.com/indicator/domain/${e}`],
        ["Whois", `https://who.is/whois/${e}`],
        ["crt.sh", `https://crt.sh/?q=${e}`],
        ["URLhaus", `https://urlhaus.abuse.ch/browse.php?search=${e}`],
      ];
      case "url": return [
        ["VirusTotal", `https://www.virustotal.com/gui/search/${e}`],
        ["urlscan", `https://urlscan.io/search/#${enc('page.url:"' + v + '"')}`],
        ["URLhaus", `https://urlhaus.abuse.ch/browse.php?search=${e}`],
      ];
      case "md5": case "sha1": case "sha256": return [
        ["VirusTotal", `https://www.virustotal.com/gui/file/${e}`],
        ["MalwareBazaar", `https://bazaar.abuse.ch/browse.php?search=${e}`],
        ["Hybrid Analysis", `https://www.hybrid-analysis.com/search?query=${e}`],
        ["OTX", `https://otx.alienvault.com/indicator/file/${e}`],
        ["X-Force", `https://exchange.xforce.ibmcloud.com/malware/${e}`],
      ];
      // TLS fingerprints: public lookup support is limited and varies by platform, so these are search entry points.
      case "ja3": return [
        ["VirusTotal", `https://www.virustotal.com/gui/search/${e}`],
        ["SSLBL", `https://sslbl.abuse.ch/ja3-fingerprints/${e}/`],
        ["OTX", `https://otx.alienvault.com/browse/global/pulses?q=${e}`],
        ["Google", `https://www.google.com/search?q=${enc('"' + v + '"')}`],
        ["GitHub", `https://github.com/search?q=${e}&type=code`],
      ];
      case "ja4": case "ja4s": return [
        ["VirusTotal", `https://www.virustotal.com/gui/search/${e}`],
        ["JA4DB", `https://ja4db.com/`],
        ["OTX", `https://otx.alienvault.com/browse/global/pulses?q=${e}`],
        ["Google", `https://www.google.com/search?q=${enc('"' + v + '"')}`],
        ["GitHub", `https://github.com/search?q=${e}&type=code`],
      ];
      case "email": return [
        ["HIBP", `https://haveibeenpwned.com/account/${e}`],
        ["Domain in VT", `https://www.virustotal.com/gui/domain/${enc(v.split("@")[1])}`],
      ];
      case "cve": return [
        ["NVD", `https://nvd.nist.gov/vuln/detail/${e}`],
        ["CVE.org", `https://www.cve.org/CVERecord?id=${e}`],
        ["CISA KEV", `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${e}`],
        ["EPSS", `https://api.first.org/data/v1/epss?cve=${e}`],
      ];
    }
    return [];
  }

  const SAMPLE = { ip: "1.2.3.4", domain: "example.com", url: "http://example.com/", md5: "0".repeat(32), sha256: "0".repeat(64),
    ja3: "0".repeat(32), ja4: "t13d0000h2_000000000000_000000000000", email: "a@example.com", cve: "CVE-2000-0001" };
  // Every platform name that can appear, in a stable display order.
  const PREFERRED = ["VirusTotal", "AbuseIPDB", "GreyNoise", "Talos", "X-Force", "OTX", "Shodan", "Censys", "urlscan", "URLhaus", "MalwareBazaar", "Hybrid Analysis", "SSLBL", "JA4DB", "Google", "GitHub"];
  function platforms() {
    const all = new Set();
    Object.entries(SAMPLE).forEach(([type, value]) => pivots({ type, value }).forEach(([n]) => all.add(n)));
    return [...PREFERRED.filter((n) => all.has(n)), ...[...all].filter((n) => !PREFERRED.includes(n))];
  }

  const api = { refang, defang, extract, pivots, platforms, privateIPv4 };
  if (typeof module !== "undefined") module.exports = api; else root.IOC = api;
})(typeof window !== "undefined" ? window : globalThis);
