import { ACTIONS, LIKELIHOOD, predictProfile } from "./engine.js?v=2026.09.severity";

export const SORT_KEYS = Object.freeze(["cve", "threat", "baseline", "predicted"]);
const cveOrder = new Intl.Collator("en", { numeric: true, sensitivity: "base" });
const finite = value => typeof value === "number" && Number.isFinite(value) ? value : null;
const rank = (labels, value) => labels.includes(value) ? labels.indexOf(value) : null;
const threatRank = item => item.record.threat?.kev || item.record.threat?.exploitation_detected
  ? rank(LIKELIHOOD, "Active") : rank(LIKELIHOOD, item.profile.baseline.likelihood);

export function nextAdvisorySort(current, key) {
  if (!SORT_KEYS.includes(key)) return current;
  return { key, direction: current?.key === key
    ? current.direction === "asc" ? "desc" : "asc"
    : key === "cve" ? "asc" : "desc" };
}

// Missing values are last in either direction; they are not numeric zeroes.
function numericOrder(left, right, direction) {
  if (left === null || right === null) return left === right ? 0 : left === null ? 1 : -1;
  return (left - right) * (direction === "asc" ? 1 : -1);
}

export function sortAdvisories(records, sort, selectedMitigations = new Set()) {
  if (!sort || !SORT_KEYS.includes(sort.key)) return records;
  const direction = sort.direction === "asc" ? "asc" : "desc";
  const decorated = records.map((record, index) => ({ record, index,
    profile: sort.key === "cve" ? null : predictProfile(record, selectedMitigations) }));
  const compareCve = (a, b) => cveOrder.compare(String(a.cve || ""), String(b.cve || ""));
  decorated.sort((a, b) => {
    let result = 0;
    if (sort.key === "cve") result = compareCve(a.record, b.record) * (direction === "asc" ? 1 : -1);
    else if (sort.key === "threat") {
      result = numericOrder(threatRank(a), threatRank(b), direction)
        || numericOrder(finite(a.record.threat?.epss), finite(b.record.threat?.epss), direction)
        || numericOrder(finite(a.record.cvss?.base_score), finite(b.record.cvss?.base_score), direction);
    } else {
      const branch = sort.key === "baseline" ? "baseline" : "residual";
      result = numericOrder(rank(ACTIONS, a.profile[branch].action), rank(ACTIONS, b.profile[branch].action), direction)
        || numericOrder(rank(LIKELIHOOD, a.profile[branch].likelihood), rank(LIKELIHOOD, b.profile[branch].likelihood), direction);
    }
    return result || compareCve(a.record, b.record) || a.index - b.index;
  });
  return decorated.map(item => item.record);
}

export function escapeSourceHtml(value) {
  return String(value ?? "").replace(/[&<>"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char]);
}

const ENTITIES = Object.freeze({ amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ",
  ndash: "–", mdash: "—", hellip: "…", lsquo: "‘", rsquo: "’", ldquo: "“", rdquo: "”" });

export function sourcePlainText(value) {
  return String(value ?? "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(script|style|template|iframe)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, "")
    .replace(/>\s*\\[rn]\s*</g, ">\n<")
    .replace(/(<\/(?:p|div|li|h[1-6])>)[ \t]*\\[rn]\s*$/gi, "$1")
    .replace(/<br\s*\/?>|<\/(?:p|div|li|h[1-6]|tr|section|blockquote)\s*>/gi, "\n\n")
    .replace(/<li\b[^>]*>/gi, "• ")
    .replace(/<[^>]*>/g, "")
    .replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (literal, entity) => {
      if (entity[0] !== "#") return ENTITIES[entity.toLowerCase()] ?? literal;
      const code = entity[1].toLowerCase() === "x" ? parseInt(entity.slice(2), 16) : Number(entity.slice(1));
      return code > 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff) ? String.fromCodePoint(code) : literal;
    })
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "")
    .replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
}

export function microsoftSourceContent(record) {
  const notes = Array.isArray(record.vendor_guidance?.notes) ? record.vendor_guidance.notes
    : Array.isArray(record.notes) ? record.notes : [];
  const summaries = [], faqs = [], seen = new Set();
  for (const note of notes) {
    const title = String(note.title ?? note.Title ?? "").trim();
    const kind = title.toLowerCase().replace(/[\s_-]+/g, "");
    if (!["executivesummary", "description", "faq"].includes(kind)) continue;
    const text = sourcePlainText(note.value ?? note.Value ?? note.text);
    const key = `${kind === "faq" ? "faq" : "summary"}:${text}`;
    if (!text || seen.has(key)) continue;
    seen.add(key);
    if (kind === "faq") faqs.push(text);
    else summaries.push({ label: kind === "executivesummary" ? "Microsoft executive summary" : "Microsoft description", text });
  }
  summaries.sort((a, b) => Number(b.label === "Microsoft executive summary") - Number(a.label === "Microsoft executive summary"));
  let sourceUrl = "";
  try {
    const url = new URL(record.source?.url);
    if (url.protocol === "https:" && ["msrc.microsoft.com", "api.msrc.microsoft.com"].includes(url.hostname)) sourceUrl = url.href;
  } catch { /* An absent or untrusted source URL must not create an executable link. */ }
  if (!sourceUrl && /^CVE-\d{4}-\d+$/i.test(record.cve || "")) sourceUrl = `https://msrc.microsoft.com/update-guide/vulnerability/${encodeURIComponent(record.cve)}`;
  return { summaries, faqs, sourceUrl };
}

export function microsoftSourceHtml(record) {
  const { summaries, faqs, sourceUrl } = microsoftSourceContent(record);
  const html = escapeSourceHtml;
  const faqBody = faqs.map(text => {
    const paragraphs = text.split(/\n\n+/);
    const first = paragraphs[0];
    const question = first.endsWith("?") && first.length <= 500 && paragraphs.length > 1;
    return `<article class="msrc-faq">${question ? `<h4>${html(first)}</h4>` : ""}<div class="source-text">${html(question ? paragraphs.slice(1).join("\n\n") : text)}</div></article>`;
  }).join("");
  const longFaq = faqs.reduce((total, text) => total + text.length, 0) > 2500;
  return `<section class="msrc-source" aria-label="Microsoft vulnerability information">
    ${summaries.length ? summaries.map(item => `<h3>${html(item.label)}</h3><div class="source-text">${html(item.text)}</div>`).join("")
      : `<h3>Microsoft summary</h3><p class="detail-meta">No Microsoft executive summary or description was supplied for this advisory.</p>`}
    <h3>Microsoft FAQ</h3>
    ${faqs.length ? longFaq ? `<details class="source-faq-details"><summary>Read the complete Microsoft FAQ (${faqs.length} ${faqs.length === 1 ? "note" : "notes"})</summary>${faqBody}</details>` : faqBody
      : `<p class="detail-meta">No Microsoft FAQ was supplied for this advisory.</p>`}
    ${sourceUrl ? `<p class="source-attribution"><a href="${html(sourceUrl)}" target="_blank" rel="noreferrer">Microsoft Security Response Center</a> · Vendor text, separate from the assessment below.</p>` : ""}
  </section>`;
}
