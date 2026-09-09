import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });
for (const name of ["index.html", "styles.css", "app.js", "engine.js", "_headers"]) {
  fs.copyFileSync(path.join(root, name), path.join(dist, name));
}
fs.cpSync(path.join(root, "data"), path.join(dist, "data"), { recursive: true });
console.log(`Built Cloudflare Pages output in ${dist}`);
