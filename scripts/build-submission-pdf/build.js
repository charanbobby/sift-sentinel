import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { marked } from "marked";
import puppeteer from "puppeteer-core";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..");

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const [k, v] = a.replace(/^--/, "").split("=");
    return [k, v ?? true];
  })
);

const inputPath = resolve(repoRoot, args.input || "docs/submission/devpost-description.md");
const outputPath = resolve(repoRoot, args.output || "dist/Sift_Sentinel_Devpost_Submission.pdf");
const chromePath =
  args.chrome ||
  "C:/Users/chara/AppData/Local/ms-playwright/chromium-1208/chrome-win64/chrome.exe";

if (!existsSync(inputPath)) {
  console.error(`Input not found: ${inputPath}`);
  process.exit(1);
}
if (!existsSync(chromePath)) {
  console.error(`Chrome not found: ${chromePath}`);
  process.exit(1);
}

const md = readFileSync(inputPath, "utf8");

marked.setOptions({ gfm: true, breaks: false });
const bodyHtml = marked.parse(md);

const css = `
  @page {
    size: Letter;
    margin: 0.85in 0.85in 0.95in 0.85in;
  }

  :root {
    --ink: #1f2937;
    --ink-strong: #0f172a;
    --muted: #475569;
    --rule: #cbd5e1;
    --rule-soft: #e2e8f0;
    --accent: #0f3a5f;
    --link: #1e40af;
    --code-bg: #f1f5f9;
    --code-border: #e2e8f0;
  }

  * { box-sizing: border-box; }

  html, body {
    margin: 0;
    padding: 0;
    background: #ffffff;
    color: var(--ink);
    color-scheme: only light;
    font-family: "Charter", "Source Serif Pro", "Iowan Old Style", Georgia, "Times New Roman", serif;
    font-size: 10.75pt;
    line-height: 1.58;
    font-feature-settings: "kern" 1, "liga" 1, "onum" 1;
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
  }

  /* Cover block: the first H1 + the bold meta paragraph that follows */
  h1 {
    font-family: "Inter", "Helvetica Neue", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-weight: 600;
    color: var(--ink-strong);
    font-size: 22pt;
    line-height: 1.18;
    letter-spacing: -0.01em;
    margin: 0 0 0.35em 0;
    padding-bottom: 0.35em;
    border-bottom: 2px solid var(--accent);
    page-break-after: avoid;
  }

  /* Subsequent H1 = section divider with page break */
  h1 + * { margin-top: 0.6em; }
  body > h1:not(:first-of-type) {
    margin-top: 1.6em;
    font-size: 18pt;
    page-break-before: always;
  }

  h2 {
    font-family: "Inter", "Helvetica Neue", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-weight: 600;
    color: var(--ink-strong);
    font-size: 13.5pt;
    line-height: 1.3;
    letter-spacing: -0.005em;
    margin: 1.6em 0 0.4em 0;
    page-break-after: avoid;
  }

  h3 {
    font-family: "Inter", "Helvetica Neue", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-weight: 600;
    color: var(--ink-strong);
    font-size: 11pt;
    margin: 1.1em 0 0.3em 0;
    page-break-after: avoid;
  }

  p {
    margin: 0 0 0.7em 0;
    orphans: 3;
    widows: 3;
  }

  strong {
    color: var(--ink-strong);
    font-weight: 600;
  }

  em { font-style: italic; }

  a {
    color: var(--link);
    text-decoration: none;
    border-bottom: 0.5px solid rgba(30, 64, 175, 0.35);
    word-break: break-word;
  }

  ul, ol {
    margin: 0.4em 0 0.9em 0;
    padding-left: 1.35em;
  }

  li {
    margin: 0.25em 0;
    padding-left: 0.15em;
  }

  li > p { margin: 0 0 0.3em 0; }

  /* Inline code */
  code {
    font-family: "JetBrains Mono", "Source Code Pro", Consolas, "Liberation Mono", monospace;
    font-size: 0.86em;
    background: var(--code-bg);
    border: 0.5px solid var(--code-border);
    border-radius: 3px;
    padding: 0.5px 4px;
    color: #0b1f3a;
  }

  pre {
    background: var(--code-bg);
    border: 0.5px solid var(--code-border);
    border-radius: 4px;
    padding: 10px 12px;
    overflow-x: auto;
    page-break-inside: avoid;
  }
  pre code { background: transparent; border: 0; padding: 0; font-size: 0.82em; line-height: 1.5; }

  /* Replace <hr> with breathing-room rule */
  hr {
    border: 0;
    border-top: 0.5px solid var(--rule-soft);
    margin: 1.4em auto;
    width: 60%;
  }

  blockquote {
    margin: 0.8em 0 0.8em 0;
    padding: 0.2em 0 0.2em 1em;
    border-left: 2px solid var(--rule);
    color: var(--muted);
    font-style: italic;
  }

  table {
    border-collapse: collapse;
    width: 100%;
    margin: 0.8em 0;
    font-size: 0.95em;
    page-break-inside: avoid;
  }
  th, td {
    text-align: left;
    padding: 6px 10px;
    border-bottom: 0.5px solid var(--rule-soft);
    vertical-align: top;
  }
  th {
    background: #f8fafc;
    font-family: "Inter", "Helvetica Neue", sans-serif;
    font-weight: 600;
    color: var(--ink-strong);
  }

  /* Avoid leaving a heading at the bottom of a page */
  h1, h2, h3 { page-break-after: avoid; break-after: avoid; }
  p, ul, ol, blockquote { page-break-inside: avoid; }
`;

const fullHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sift Sentinel: Devpost Submission</title>
<style>${css}</style>
</head>
<body>
${bodyHtml}
</body>
</html>`;

mkdirSync(dirname(outputPath), { recursive: true });

const today = new Date().toISOString().slice(0, 10);

const headerTemplate = `
<div style="font-family: 'Inter', 'Helvetica Neue', sans-serif; font-size: 8pt; color: #64748b; width: 100%; padding: 0 0.85in; display: flex; justify-content: space-between; align-items: center; -webkit-print-color-adjust: exact;">
  <span>Sift Sentinel &nbsp;·&nbsp; SANS DFIR Hackathon Devpost Submission</span>
  <span></span>
</div>`;

const footerTemplate = `
<div style="font-family: 'Inter', 'Helvetica Neue', sans-serif; font-size: 8pt; color: #64748b; width: 100%; padding: 0 0.85in; display: flex; justify-content: space-between; align-items: center; -webkit-print-color-adjust: exact;">
  <span>${today}</span>
  <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
</div>`;

console.log(`[build] input  = ${inputPath}`);
console.log(`[build] output = ${outputPath}`);
console.log(`[build] chrome = ${chromePath}`);

const browser = await puppeteer.launch({
  executablePath: chromePath,
  headless: "shell",
  args: ["--no-sandbox", "--disable-gpu"],
});

try {
  const page = await browser.newPage();
  await page.setContent(fullHtml, { waitUntil: "load" });
  await page.emulateMediaType("print");

  await page.pdf({
    path: outputPath,
    format: "Letter",
    printBackground: true,
    displayHeaderFooter: true,
    headerTemplate,
    footerTemplate,
    margin: {
      top: "0.95in",
      bottom: "0.95in",
      left: "0.85in",
      right: "0.85in",
    },
    preferCSSPageSize: false,
  });

  console.log(`[build] wrote ${outputPath}`);
} finally {
  await browser.close();
}
