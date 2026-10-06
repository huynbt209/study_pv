/*
  Builds docs/index.html (GitHub Pages serves main /docs): index.html with every <script src> inlined,
  gzipped, then encrypted with AES-256-GCM (key = PBKDF2-SHA256 of the password). The output holds only
  ciphertext + salt + iv, so neither the password nor the study content can be read from the deployed file.
  The plaintext sources stay out of this public repo (see .gitignore); they live in the private repo.

  Usage:  node build.mjs                    (asks for the password, hidden)
          STUDY_PASSWORD=... node build.mjs (CI: pass it from a secret, never commit it)
*/
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const ITERATIONS = 600000;

function inlineScripts(html) {
  return html.replace(/<script src="([^"]+)"><\/script>/g, function (_, src) {
    var js = readFileSync(join(ROOT, src), "utf8");
    if (/<\/script|<!--/i.test(js)) throw new Error(src + " contains </script or <!-- and cannot be inlined");
    return "<script>\n" + js + "\n</script>";
  });
}

function askHidden(question) {
  return new Promise(function (resolve, reject) {
    var stdin = process.stdin;
    if (!stdin.isTTY) return reject(new Error("No terminal: set STUDY_PASSWORD instead."));
    process.stdout.write(question);
    stdin.setRawMode(true);
    stdin.setEncoding("utf8");
    stdin.resume();
    var value = "";
    function onData(chunk) {
      for (var c of chunk) {
        if (c === "\r" || c === "\n") return done();
        if (c === "\u0003") { stdin.setRawMode(false); process.exit(130); }
        if (c === "\u007f" || c === "\b") value = value.slice(0, -1);
        else value += c;
      }
    }
    function done() {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
      process.stdout.write("\n");
      resolve(value);
    }
    stdin.on("data", onData);
  });
}

async function getPassword() {
  if (process.env.STUDY_PASSWORD) return process.env.STUDY_PASSWORD;
  var first = await askHidden("Password: ");
  var again = await askHidden("Confirm:  ");
  if (first !== again) throw new Error("Passwords do not match.");
  return first;
}

async function encrypt(plain, password) {
  var subtle = globalThis.crypto.subtle;
  var salt = crypto.getRandomValues(new Uint8Array(16));
  var iv = crypto.getRandomValues(new Uint8Array(12));
  var base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  var key = await subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: ITERATIONS },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  var data = await subtle.encrypt({ name: "AES-GCM", iv: iv }, key, plain);
  var b64 = function (u8) { return Buffer.from(u8).toString("base64"); };
  return { v: 1, n: ITERATIONS, s: b64(salt), i: b64(iv), d: b64(new Uint8Array(data)) };
}

var password = await getPassword();
if (password.length < 12) throw new Error("Use a password of at least 12 characters.");

var page = inlineScripts(readFileSync(join(ROOT, "index.html"), "utf8"));
var payload = await encrypt(gzipSync(page, { level: 9 }), password);
var gate = readFileSync(join(ROOT, "gate.template.html"), "utf8")
  .replace("{{PAYLOAD}}", function () { return JSON.stringify(payload); });

mkdirSync(join(ROOT, "docs"), { recursive: true });
writeFileSync(join(ROOT, "docs", "index.html"), gate);
writeFileSync(join(ROOT, "docs", ".nojekyll"), "");
console.log("docs/index.html: " + (gate.length / 1024).toFixed(0) + " KB (page " + (page.length / 1024).toFixed(0) + " KB before gzip + encryption)");
