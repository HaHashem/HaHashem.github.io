/* Shared layout: injects nav + footer, theme toggle, tiny helpers. */
(function () {
  const pages = [
    ["index.html", "Home"],
    ["projects.html", "Projects"],
    ["articles.html", "Articles"],
    ["intel.html", "Threat Intel"],
    ["about.html", "About"],
  ];
  const here = location.pathname.split("/").pop() || "index.html";
  const activeFile = here === "article.html" ? "articles.html" : here;

  try {
    const t = localStorage.getItem("theme");
    if (t) document.documentElement.dataset.theme = t;
  } catch (e) {}

  const header = document.createElement("header");
  header.className = "site";
  header.innerHTML = `
    <div class="wrap">
      <a class="brand" href="index.html"><span class="dot"></span>Hashem H. Hashem</a>
      <nav class="main">
        ${pages.map(([f, n]) => `<a href="${f}" class="${f === activeFile ? "active" : ""}">${n}</a>`).join("")}
        <button class="theme-btn" id="themeBtn" title="Toggle theme" aria-label="Toggle theme">Theme</button>
      </nav>
    </div>`;
  document.body.prepend(header);

  const footer = document.createElement("footer");
  footer.className = "site";
  footer.innerHTML = `
    <div class="wrap">
      <span>© ${new Date().getFullYear()} Hashem H. Hashem · SOC / DFIR</span>
      <span>
        <a href="https://www.linkedin.com/in/hashem-hashem-47258456" target="_blank" rel="noopener">LinkedIn</a> ·
        <a href="https://github.com/HaHashem" target="_blank" rel="noopener">GitHub</a>
      </span>
    </div>`;
  document.body.append(footer);

  document.getElementById("themeBtn").addEventListener("click", () => {
    const cur = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = cur;
    try { localStorage.setItem("theme", cur); } catch (e) {}
  });
})();

window.H = {
  esc: (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])),
  fmtDate: (d) => new Date(d + "T00:00:00").toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" }),
  async json(path) { const r = await fetch(path); if (!r.ok) throw new Error(path + " " + r.status); return r.json(); },
};
