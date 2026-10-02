# hahashem.github.io

Static portfolio for GitHub Pages. No build step.

## Publish
Push these files to the root of the `hahashem.github.io` repo (main branch). Settings → Pages → Deploy from branch → `main` / root.

## Edit content
- **Projects:** `data/projects.json`
- **Articles:** add `articles/<slug>.md` and an entry in `data/articles.json`
- **CV download:** put your PDF at `resume/Hashem_Hashem_CV.pdf`
- **About page:** `about.html`
- **Threat Intel page:** `intel.html` + `assets/ioc.js` (extraction rules and pivot links)

## Preview locally
`python3 -m http.server 8000` then open http://localhost:8000
(Opening the files directly with file:// won't load the JSON data.)
