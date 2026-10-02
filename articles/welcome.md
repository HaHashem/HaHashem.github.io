## Adding an article

1. Create a Markdown file in `articles/`, for example `articles/phishing-triage.md`.
2. Add an entry at the top of `data/articles.json`:

```json
{
  "slug": "phishing-triage",
  "title": "Phishing triage in 10 minutes",
  "date": "2026-10-05",
  "summary": "One-line description shown on the list page.",
  "tags": ["SOC", "Email"],
  "minutes": 6
}
```

3. Commit and push. GitHub Pages publishes it in about a minute.

## What Markdown is supported

- Headings, lists, **bold**, *italic*, `inline code`
- Fenced code blocks (great for SPL, KQL, PowerShell)
- Tables and blockquotes

| Field | Example |
|---|---|
| Event ID | 4688 |
| Meaning | Process creation |

> Keep customer and employer data out of public write-ups. Use sanitized or public datasets.
