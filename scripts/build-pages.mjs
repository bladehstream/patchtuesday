import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });
for (const name of ["index.html", "styles.css", "app.js", "engine.js", "risk-model.js", "_headers"]) {
  fs.copyFileSync(path.join(root, name), path.join(dist, name));
}
fs.cpSync(path.join(root, "data"), path.join(dist, "data"), { recursive: true });

const distData = path.join(dist, "data");
const manifestPath = path.join(distData, "months.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
for (const item of manifest) {
  const source = path.join(distData, item.file);
  const content = fs.readFileSync(source);
  const hash = createHash("sha256").update(content).digest("hex").slice(0, 12);
  const extension = path.extname(item.file);
  const basename = path.basename(item.file, extension);
  const versionedName = `${basename}.${hash}${extension}`;
  fs.copyFileSync(source, path.join(distData, versionedName));
  item.file = versionedName;
}
fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Built Cloudflare Pages output in ${dist}`);
