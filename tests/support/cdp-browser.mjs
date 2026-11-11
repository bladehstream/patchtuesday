import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const MIME_TYPES = Object.freeze({
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".jsonl": "application/x-ndjson; charset=utf-8",
});

function executable(candidate) {
  try { return fs.statSync(candidate).isFile() && fs.accessSync(candidate, fs.constants.X_OK) === undefined; }
  catch { return false; }
}

function pathCandidates() {
  const names = process.platform === "win32"
    ? ["chrome.exe", "msedge.exe", "chromium.exe"]
    : ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "microsoft-edge", "msedge"];
  return (process.env.PATH || "").split(path.delimiter).flatMap(directory => names.map(name => path.join(directory, name)));
}

function playwrightCandidates() {
  const cache = path.join(os.homedir(), ".cache", "ms-playwright");
  try {
    return fs.readdirSync(cache, { withFileTypes: true })
      .filter(entry => entry.isDirectory() && /^(chromium|chrome|msedge)-/.test(entry.name))
      .flatMap(entry => [
        path.join(cache, entry.name, "chrome-linux", "chrome"),
        path.join(cache, entry.name, "chrome-linux64", "chrome"),
        path.join(cache, entry.name, "chrome-win", "chrome.exe"),
        path.join(cache, entry.name, "chrome-mac", "Chromium.app", "Contents", "MacOS", "Chromium"),
      ]);
  } catch { return []; }
}

export function findBrowser() {
  const override = process.env.PATCH_TUESDAY_BROWSER;
  if (override) {
    if (executable(override)) return override;
    throw new Error(`PATCH_TUESDAY_BROWSER is not an executable browser: ${override}`);
  }
  const browser = [...pathCandidates(), ...playwrightCandidates()].find(executable);
  if (!browser) {
    throw new Error("No Chromium, Chrome, or Edge executable found. Set PATCH_TUESDAY_BROWSER to an installed browser; the real-render benchmark cannot be skipped.");
  }
  return browser;
}

export async function startStaticServer(root) {
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, "http://127.0.0.1").pathname;
    const relative = decodeURIComponent(pathname === "/" ? "/index.html" : pathname).replace(/^\/+/, "");
    const filename = path.resolve(root, relative);
    if (!filename.startsWith(`${root}${path.sep}`)) {
      response.writeHead(403).end("Forbidden");
      return;
    }
    fs.readFile(filename, (error, body) => {
      if (error) { response.writeHead(error.code === "ENOENT" ? 404 : 500).end("Not found"); return; }
      response.writeHead(200, { "content-type": MIME_TYPES[path.extname(filename)] || "application/octet-stream" });
      response.end(body);
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}/`,
    close: () => new Promise(resolve => server.close(resolve)),
  };
}

class CdpPipe {
  constructor(input, output) {
    this.input = input;
    this.output = output;
    this.nextId = 1;
    this.pending = new Map();
    this.buffer = Buffer.alloc(0);
    output.on("data", chunk => this.receive(chunk));
    output.on("error", error => this.fail(error));
  }

  receive(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    let boundary;
    while ((boundary = this.buffer.indexOf(0)) !== -1) {
      const message = JSON.parse(this.buffer.subarray(0, boundary));
      this.buffer = this.buffer.subarray(boundary + 1);
      if (!message.id) continue;
      const request = this.pending.get(message.id);
      if (!request) continue;
      this.pending.delete(message.id);
      clearTimeout(request.timeout);
      message.error ? request.reject(new Error(`${message.error.message} (${request.method})`)) : request.resolve(message.result);
    }
  }

  fail(error) {
    for (const request of this.pending.values()) { clearTimeout(request.timeout); request.reject(error); }
    this.pending.clear();
  }

  send(method, params = {}, sessionId = undefined, timeoutMs = 15000) {
    const id = this.nextId++;
    const message = { id, method, params };
    if (sessionId) message.sessionId = sessionId;
    const json = Buffer.from(`${JSON.stringify(message)}\0`);
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Timed out after ${timeoutMs}ms waiting for CDP ${method}`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, method, timeout });
      this.input.write(json, error => {
        if (!error) return;
        clearTimeout(timeout);
        this.pending.delete(id);
        reject(error);
      });
    });
  }
}

export async function launchPage(url) {
  const browser = findBrowser();
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "patchtuesday-cdp-"));
  const child = spawn(browser, ["--headless=new", "--no-first-run", "--no-default-browser-check", "--no-sandbox", `--user-data-dir=${profile}`, "--remote-debugging-pipe"], {
    stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"],
  });
  // `exit` can precede pipe closure and Windows profile-handle release. Register
  // immediately so cleanup also observes browsers that fail during startup.
  let closed = false;
  const browserClosed = new Promise(resolve => child.once("close", () => { closed = true; resolve(); }));
  const waitForClose = async timeoutMs => {
    if (closed) return true;
    let timer;
    try {
      return await Promise.race([browserClosed.then(() => true), new Promise(resolve => { timer = setTimeout(() => resolve(false), timeoutMs); })]);
    } finally { clearTimeout(timer); }
  };
  const stopBrowser = async () => {
    if (await waitForClose(3000)) return;
    child.kill();
    if (await waitForClose(3000)) return;
    child.kill("SIGKILL");
    if (!await waitForClose(3000)) throw new Error("Owned browser process did not close within the cleanup timeout");
  };
  const removeProfile = () => {
    const ownedProfile = path.resolve(profile);
    if (path.dirname(ownedProfile) !== path.resolve(os.tmpdir()) || !path.basename(ownedProfile).startsWith("patchtuesday-cdp-")) {
      throw new Error("Refusing to remove a profile outside the owned temporary directory");
    }
    // Edge utility processes can release their handles just after browser close.
    fs.rmSync(ownedProfile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  };
  let stderr = "";
  child.stderr.on("data", chunk => { stderr += chunk; });
  const cdp = new CdpPipe(child.stdio[3], child.stdio[4]);
  child.once("exit", (code, signal) => cdp.fail(new Error(`Browser exited before CDP was ready (code=${code}, signal=${signal}): ${stderr}`)));
  let sessionId;
  try {
    const target = await cdp.send("Target.createTarget", { url: "about:blank" });
    const attached = await cdp.send("Target.attachToTarget", { targetId: target.targetId, flatten: true });
    sessionId = attached.sessionId;
    await cdp.send("Page.enable", {}, sessionId);
    await cdp.send("Runtime.enable", {}, sessionId);
    await cdp.send("Page.navigate", { url }, sessionId);
  } catch (error) {
    if (!child.killed) child.kill();
    try { await stopBrowser(); removeProfile(); }
    catch (cleanupError) { throw new AggregateError([error, cleanupError], "Browser initialization and cleanup failed"); }
    throw error;
  }

  const evaluate = async expression => {
    const result = await cdp.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sessionId);
    if (result.exceptionDetails) throw new Error(`Page evaluation failed: ${result.exceptionDetails.exception?.description || result.exceptionDetails.text}`);
    return result.result.value;
  };
  const close = async () => {
    try { await cdp.send("Browser.close", {}, undefined, 3000); } catch { /* Browser may already be exiting. */ }
    // Give Browser.close time to finish gracefully before terminating this child.
    await stopBrowser();
    removeProfile();
    if (child.exitCode && child.exitCode !== 0 && stderr) throw new Error(`Browser exited ${child.exitCode}: ${stderr}`);
  };
  return { browser, evaluate, close };
}

export async function waitFor(check, { attempts = 100, intervalMs = 25 } = {}) {
  let last;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    last = await check();
    if (last) return last;
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  throw new Error("Timed out waiting for the static page to become ready");
}
