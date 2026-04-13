#!/usr/bin/env bash
set -euo pipefail

# Generate site/blog/index.html from blog/*.md frontmatter.
# Reads title, description, date from YAML frontmatter in each post.
# Sorts newest first (by date string — "April 2026" > "March 2026").

OUT="site/blog/index.html"

# Extract frontmatter fields from a markdown file
extract() {
  local file="$1" field="$2"
  sed -n '/^---$/,/^---$/p' "$file" | grep "^${field}:" | sed "s/^${field}: *//"
}

# Collect posts: "date|name|title|description" per line
posts=""
sources="blog/*.md"
if [ "${BLOG_INCLUDE_DRAFTS:-}" = "1" ] && ls drafts/*.md >/dev/null 2>&1; then
  sources="blog/*.md drafts/*.md"
fi
for f in $sources; do
  name=$(basename "$f" .md)
  title=$(extract "$f" title)
  desc=$(extract "$f" description)
  date=$(extract "$f" date)
  posts+="${date}|${name}|${title}|${desc}"$'\n'
done

# Sort by ISO date (YYYY-MM-DD), newest first
posts=$(echo "$posts" | grep -v '^$' | sort -t'|' -k1 -r)

# Format ISO date (YYYY-MM-DD) to "Month YYYY"
format_date() {
  local months=(January February March April May June July August September October November December)
  local y="${1%%-*}"
  local m="${1#*-}"; m="${m%%-*}"; m=$((10#$m))
  echo "${months[$((m-1))]} $y"
}

# Generate post list items
items=""
while IFS='|' read -r date name title desc; do
  display_date=$(format_date "$date")
  items+="    <li>
      <a href=\"/blog/posts/${name}.html\">
        <div class=\"post-title\">${title}</div>
        <div class=\"post-desc\">${desc}</div>
        <div class=\"post-date\">${display_date}</div>
      </a>
    </li>
"
done <<< "$posts"

# Write the full index.html — style matches the existing hand-maintained version
cat > "$OUT" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Blog — Numa</title>
<meta name="description" content="Technical writing about DNS, Rust, and building infrastructure from scratch.">
<link rel="stylesheet" href="/fonts/fonts.css">
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

:root {
  --bg-deep: #f5f0e8;
  --bg-surface: #ece5da;
  --bg-card: #faf7f2;
  --amber: #c0623a;
  --amber-dim: #9e4e2d;
  --teal: #6b7c4e;
  --text-primary: #2c2418;
  --text-secondary: #6b5e4f;
  --text-dim: #a39888;
  --border: rgba(0, 0, 0, 0.08);
  --font-display: 'Instrument Serif', Georgia, serif;
  --font-body: 'DM Sans', system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
}

body {
  background: var(--bg-deep);
  color: var(--text-primary);
  font-family: var(--font-body);
  font-weight: 400;
  line-height: 1.7;
  -webkit-font-smoothing: antialiased;
}

body::before {
  content: '';
  position: fixed;
  inset: 0;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.025'/%3E%3C/svg%3E");
  pointer-events: none;
  z-index: 9999;
}

.blog-nav {
  padding: 1.5rem 2rem;
  display: flex;
  align-items: center;
  gap: 1.5rem;
}

.blog-nav a {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-dim);
  text-decoration: none;
  transition: color 0.2s;
}
.blog-nav a:hover { color: var(--amber); }

.blog-nav .wordmark {
  font-family: var(--font-display);
  font-size: 1.4rem;
  font-weight: 400;
  color: var(--text-primary);
  text-decoration: none;
  text-transform: none;
  letter-spacing: -0.02em;
}
.blog-nav .wordmark:hover { color: var(--amber); }

.blog-nav .sep {
  color: var(--text-dim);
  font-family: var(--font-mono);
  font-size: 0.75rem;
}

.blog-index {
  max-width: 720px;
  margin: 0 auto;
  padding: 3rem 2rem 6rem;
}

.blog-index h1 {
  font-family: var(--font-display);
  font-weight: 400;
  font-size: 2.5rem;
  margin-bottom: 3rem;
}

.post-list {
  list-style: none;
}

.post-list li {
  padding: 1.5rem 0;
  border-bottom: 1px solid var(--border);
}

.post-list li:first-child {
  border-top: 1px solid var(--border);
}

.post-list a {
  text-decoration: none;
  display: block;
}

.post-list .post-title {
  font-family: var(--font-display);
  font-size: 1.4rem;
  font-weight: 600;
  color: var(--text-primary);
  line-height: 1.3;
  margin-bottom: 0.4rem;
  transition: color 0.2s;
}

.post-list a:hover .post-title {
  color: var(--amber);
}

.post-list .post-desc {
  font-size: 0.95rem;
  color: var(--text-secondary);
  line-height: 1.5;
  margin-bottom: 0.4rem;
}

.post-list .post-date {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--text-dim);
  letter-spacing: 0.04em;
}

.blog-footer {
  text-align: center;
  padding: 3rem 2rem;
  border-top: 1px solid var(--border);
  max-width: 720px;
  margin: 0 auto;
}

.blog-footer a {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-dim);
  text-decoration: none;
  margin: 0 1rem;
}
.blog-footer a:hover { color: var(--amber); }
</style>
</head>
<body>

<nav class="blog-nav">
  <a href="/" class="wordmark">Numa</a>
  <span class="sep">/</span>
  <a href="/blog/">Blog</a>
</nav>

<main class="blog-index">
  <h1>Blog</h1>
  <ul class="post-list">
${items}  </ul>
</main>

<footer class="blog-footer">
  <a href="https://github.com/razvandimescu/numa">GitHub</a>
  <a href="/">Home</a>
</footer>

</body>
</html>
HTMLEOF

echo "  blog/index.html generated ($(echo "$posts" | wc -l | tr -d ' ') posts)"
