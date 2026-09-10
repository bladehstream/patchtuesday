import assert from "node:assert/strict";
import fs from "node:fs";

const app = fs.readFileSync(new URL("../app.js", import.meta.url), "utf8");
const page = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");

assert.ok(app.includes("recordByCve: new Map()"), "Detail lookup should use the CVE map");
assert.ok(!app.includes("state.selectedCve = row.dataset.cve; render();"), "Selecting a row must not rebuild the full table");
assert.ok(app.includes("body.onclick = event =>"), "The table should use one delegated click handler");
assert.ok(app.includes("option.dataset.version = item.published_at"), "Published datasets should be cache-versioned by the manifest timestamp");
assert.ok(page.indexOf("Verified mitigations") < page.indexOf("Severity"), "Verified mitigations should sit below products and before severity");
console.log("UI performance regression tests passed");
