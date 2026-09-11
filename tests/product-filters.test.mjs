// Logic test for the curated filter list and AND/OR matching.
import fs from "node:fs";
import assert from "node:assert/strict";

const cfg = JSON.parse(fs.readFileSync(new URL("../data/product-filters.json", import.meta.url), "utf8"));
const recs = fs.readFileSync(new URL("../data/2026-Sep.jsonl", import.meta.url), "utf8").split("\n").filter(Boolean).map(JSON.parse);

const optionOf = tag => {
  for (const g of cfg.groups) { const o = g.options.find(x => x.tag === tag); if (o) return { ...o, source: g.source }; }
  return null;
};
const tagsFor = (r, src) => (src === "tags" ? r.tags : r.product_tags) || [];
const matches = (r, selected, mode) => {
  if (!selected.length) return true;
  const hit = t => { const o = optionOf(t); return o ? tagsFor(r, o.source).includes(t) : false; };
  return mode === "and" ? selected.every(hit) : selected.some(hit);
};

assert.equal(cfg.groups.length, 2);
assert.equal(cfg.groups.flatMap(g => g.options).length, 19, "19 curated checkboxes");
assert.ok(optionOf("microsoft"), "vendor filter must remain for future non-Microsoft products");
assert.equal(optionOf("azure"), null, "azure is deliberately excluded");
assert.ok(cfg.excluded.azure, "the azure exclusion must carry its reason");

// Nothing selected: every record visible, including uncategorised ones.
assert.equal(recs.filter(r => matches(r, [], "or")).length, recs.length);

const or = recs.filter(r => matches(r, ["server-2019", "server-2022"], "or")).length;
const and = recs.filter(r => matches(r, ["server-2019", "server-2022"], "and")).length;
assert.ok(and < or, `AND must narrow: or=${or} and=${and}`);
console.log(`  Server 2019 OR 2022 = ${or};  AND = ${and}`);

const crossOr = recs.filter(r => matches(r, ["server-2019", "dns"], "or")).length;
const crossAnd = recs.filter(r => matches(r, ["server-2019", "dns"], "and")).length;
console.log(`  Server 2019 OR DNS  = ${crossOr};  AND (DNS on 2019) = ${crossAnd}`);
assert.ok(crossAnd <= crossOr);

for (const g of cfg.groups) for (const o of g.options) {
  const n = recs.filter(r => tagsFor(r, g.source).includes(o.tag)).length;
  console.log(`  ${g.label.padEnd(9)} ${o.label.padEnd(16)} ${String(n).padStart(5)}`);
}
console.log("filter logic tests passed");
