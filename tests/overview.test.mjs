import assert from "node:assert/strict";
import fs from "node:fs";
import {
  ACTIONS,
  monthTotals,
  overviewBoard,
  parseJsonl,
  predictProfile,
  recordFilterTags,
  reviewStatus,
  summariseTile,
  worstFirst,
} from "../engine.js";

// A fixture record carries only what the risk model reads. Anything the engine
// needs and the fixture omits would silently take a default, so the pieces that
// decide the action are all stated here.
function fixture(cve, { severity = "Important", assessment = "less-likely", kev = false, tags = [], productTags = [], baselineAction = null, baselineModel = "standard-remediation", baseScore = 7.5 } = {}) {
  return {
    schema_version: "1.0",
    month: "2026-Fix",
    cve,
    title: `${cve} fixture`,
    severity,
    customer_action_required: true,
    cvss: { base_score: baseScore, temporal_score: null, vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", version: "3.1" },
    products: [],
    tags,
    product_tags: productTags,
    attack: { vector: "local", privileges_required: "low", user_interaction: "none" },
    threat: { kev, exploitation_detected: false, exploitation_assessment: assessment, epss: 0.0001, epss_status: "scored" },
    mitigation_candidates: [],
    vendor_guidance: { remediations: [] },
    source: {},
    dataset_provenance: {},
    inference: baselineAction
      ? {
          model: "fixture",
          review_status: "reviewed",
          framework_assessment: {
            risk_model_version: "2026.09.1",
            baseline_model: baselineModel,
            baseline_likelihood: "Plausible",
            baseline_action: baselineAction,
            confidence: "high",
            factors: {},
            risk_communication: { summary: "fixture", why_this_action: "fixture" },
          },
        }
      : { model: "fixture", review_status: "reviewed" },
  };
}

// ---------------------------------------------------------------------------
// The rule the dashboard exists to express: worst wins, however rare.
// ---------------------------------------------------------------------------
{
  const records = [
    fixture("CVE-0000-0001", { baselineAction: "Immediate", baselineModel: "active-exploitation", kev: true }),
    ...Array.from({ length: 200 }, (_, i) => fixture(`CVE-0000-1${String(i).padStart(3, "0")}`, { baselineAction: "Scheduled" })),
  ];
  const tile = summariseTile(records);
  assert.equal(tile.total, 201, "every record counts toward the total");
  assert.equal(tile.worstAction, "Immediate", "one Immediate among 200 Scheduled must set the tile to Immediate");
  assert.equal(tile.state, "emergency");
  assert.equal(tile.worstCount, 1, "the tile must say how many records sit at the worst level");
  assert.equal(tile.counts.Scheduled, 200);

  // Guard the guard. Remove the single Immediate record and the tile must fall
  // to Scheduled; if it does not, the assertions above are not testing the rule.
  const withoutEmergency = records.slice(1);
  const fallen = summariseTile(withoutEmergency);
  assert.equal(fallen.worstAction, "Scheduled", "dropping the only Immediate record must change the tile");
  assert.equal(fallen.state, "scheduled");
  assert.notEqual(fallen.state, tile.state, "the worst-wins assertion must be sensitive to the Immediate record");
}

// ---------------------------------------------------------------------------
// Rule 1: a missing vendor severity must never render as a clean bill of health.
// ---------------------------------------------------------------------------
{
  const unknowns = Array.from({ length: 23 }, (_, i) =>
    fixture(`CVE-0000-2${String(i).padStart(3, "0")}`, { severity: "Unknown", baselineAction: "Scheduled", baselineModel: "unknown-severity", baseScore: null }));
  const tile = summariseTile(unknowns);
  assert.equal(tile.worstAction, "Scheduled", "the action itself is still the placeholder the model assigns");
  assert.equal(tile.unverified, true, "all-Unknown at the worst level marks the tile unverified");
  assert.equal(tile.state, "unverified");
  assert.notEqual(tile.state, "scheduled", "an unverified tile must not share the green state");
  assert.equal(tile.reviewCount, 23, "every unrated record is counted as needing review");

  // One rated record at the same worst level is enough to establish that the
  // level was actually assessed, so the tile stops being unverified.
  const mixed = summariseTile([...unknowns, fixture("CVE-0000-2999", { baselineAction: "Scheduled" })]);
  assert.equal(mixed.unverified, false, "a rated record at the worst level clears the unverified state");
  assert.equal(mixed.state, "scheduled");
}

// Unverified must not soften a tile. An unrated but KEV-listed record is an
// emergency with a data gap, not an absence of urgency.
{
  const tile = summariseTile([
    fixture("CVE-0000-3001", { severity: "Unknown", kev: true, baselineAction: "Immediate", baselineModel: "active-exploitation", baseScore: null }),
  ]);
  assert.equal(tile.worstAction, "Immediate");
  assert.equal(tile.unverified, false, "unverified applies only where the colour would understate");
  assert.equal(tile.state, "emergency", "an unrated KEV record must stay red, not go grey");
}

// An empty tile is a fact, not an absence. It must be representable.
{
  const tile = summariseTile([]);
  assert.equal(tile.total, 0);
  assert.equal(tile.worstAction, null);
  assert.equal(tile.state, "empty");
  assert.equal(tile.unverified, false);
}

// ---------------------------------------------------------------------------
// Board membership uses the same predicate as the checkboxes.
// ---------------------------------------------------------------------------
{
  const config = {
    groups: [
      { id: "products", label: "Products", source: "product_tags", options: [
        { tag: "sharepoint", label: "SharePoint" },
        { tag: "microsoft", label: "Microsoft", overview: false },
        { tag: "absent", label: "Absent" },
      ] },
      { id: "workloads", label: "Workloads", source: "product_tags+tags", options: [{ tag: "dns", label: "DNS" }] },
    ],
  };
  const records = [
    fixture("CVE-0000-4001", { productTags: ["sharepoint", "microsoft"], baselineAction: "Scheduled" }),
    fixture("CVE-0000-4002", { productTags: ["dns", "microsoft"], baselineAction: "Out-of-cycle" }),
    // dns in `tags` only. The shipped predicate reads product_tags for the
    // "product_tags+tags" source, so this record must NOT reach the DNS tile.
    // The board mirrors the checkbox exactly, including where that is arguably
    // wrong; the discrepancy is reported separately, not patched here.
    fixture("CVE-0000-4003", { tags: ["dns"], baselineAction: "Immediate" }),
  ];
  const board = overviewBoard(records, config);
  assert.equal(board.length, 2);

  const productTiles = board[0].tiles.map(tile => tile.tag);
  assert.deepEqual(productTiles, ["sharepoint", "absent"], "an option marked overview:false gets no tile");
  assert.ok(!productTiles.includes("microsoft"), "the catch-all must not appear on the board");

  const sharepoint = board[0].tiles.find(tile => tile.tag === "sharepoint");
  assert.equal(sharepoint.total, 1);
  assert.equal(sharepoint.state, "scheduled");

  const absent = board[0].tiles.find(tile => tile.tag === "absent");
  assert.equal(absent.total, 0, "an option matching nothing this month is present and empty");
  assert.equal(absent.state, "empty");

  const dns = board[1].tiles[0];
  assert.equal(dns.total, 1, "the tags-only record must not reach the tile, matching recordFilterTags");
  assert.equal(dns.worstAction, "Out-of-cycle", "the Immediate record is tags-only and out of scope for this tile");

  // State this as an executable fact so a future union change breaks here and is
  // read, rather than quietly moving every workload tile.
  assert.deepEqual(recordFilterTags(records[2], "product_tags+tags"), [], "the config's '+tags' source currently reads product_tags only");
  assert.deepEqual(recordFilterTags(records[2], "tags"), ["dns"]);
}

// ---------------------------------------------------------------------------
// Verified mitigations move the board; view filters are not its business.
// ---------------------------------------------------------------------------
{
  const record = fixture("CVE-0000-5001", { baselineAction: "Out-of-cycle", baselineModel: "critical-technical", severity: "Critical" });
  record.attack = { vector: "network", privileges_required: "none", user_interaction: "none" };
  record.mitigation_candidates = [{
    id: "segmentation_acl",
    relevance: "relevant",
    confidence: "high",
    effect: { likelihood_steps: 1, consequence_steps: 0, path_block: false },
    evidence: "fixture",
  }];
  const before = summariseTile([record]);
  const after = summariseTile([record], new Set(["segmentation_acl"]));
  assert.equal(before.worstAction, "Out-of-cycle");
  assert.equal(after.worstAction, "Scheduled", "a credited mitigation must be able to turn a tile down");
  assert.notEqual(before.state, after.state);
}

// ---------------------------------------------------------------------------
// Worst-first list
// ---------------------------------------------------------------------------
{
  const records = [
    fixture("CVE-0000-6001", { baselineAction: "Scheduled" }),
    fixture("CVE-0000-6002", { baselineAction: "Out-of-cycle", baselineModel: "critical-technical", severity: "Critical" }),
    fixture("CVE-0000-6003", { baselineAction: "Immediate", baselineModel: "active-exploitation", kev: true }),
  ];
  const worst = worstFirst(records);
  assert.deepEqual(worst.map(item => item.record.cve), ["CVE-0000-6003", "CVE-0000-6002"], "Scheduled records are excluded and Immediate sorts first");
  assert.equal(worstFirst(records, new Set(), 1).length, 1, "the limit is honoured");
}

// ---------------------------------------------------------------------------
// Against the published month, with counts derived from the manifest rather
// than frozen in the test.
// ---------------------------------------------------------------------------
{
  const manifest = JSON.parse(fs.readFileSync(new URL("../data/months.json", import.meta.url), "utf8"));
  const entry = manifest.find(item => !item.month.endsWith("-demo")) || manifest[0];
  const records = parseJsonl(fs.readFileSync(new URL(`../data/${entry.file}`, import.meta.url), "utf8"));
  const config = JSON.parse(fs.readFileSync(new URL("../data/product-filters.json", import.meta.url), "utf8"));

  const totals = monthTotals(records);
  assert.equal(totals.total, entry.record_count, "the board covers every published record");
  assert.equal(
    ACTIONS.reduce((sum, action) => sum + totals.counts[action], 0),
    entry.record_count,
    "every record lands in exactly one action bucket",
  );

  const board = overviewBoard(records, config);
  assert.ok(board.length >= 1);
  for (const group of board) {
    assert.ok(!group.tiles.some(tile => tile.tag === "microsoft"), "the catch-all tile stays off the board");
    for (const tile of group.tiles) {
      const expected = records.filter(record => recordFilterTags(record, group.source).includes(tile.tag));
      assert.equal(tile.total, expected.length, `${tile.label} membership must match the filter predicate`);
      assert.equal(
        ACTIONS.reduce((sum, action) => sum + tile.counts[action], 0),
        tile.total,
        `${tile.label} buckets must sum to its total`,
      );
      if (tile.worstAction !== null) {
        assert.ok(tile.worstCount >= 1, `${tile.label} reports at least one record at its worst level`);
        const recomputed = expected.filter(record => predictProfile(record).residual.action === tile.worstAction).length;
        assert.equal(tile.worstCount, recomputed, `${tile.label} worst-level count must be recomputable`);
      }
      assert.equal(
        tile.reviewCount,
        expected.filter(record => reviewStatus(record).required).length,
        `${tile.label} review count must match reviewStatus`,
      );
      assert.ok(tile.state !== "scheduled" || !tile.unverified, "no tile is both green and unverified");
    }
  }
}

console.log("overview board tests passed");
