// Cross-language wire-interop check: a mandate issued by one reference port must
// verify and authorize correctly in the other. Run after `npm run build`:
//
//   node scripts/interop.mjs
//
// Requires python3 on PATH (the Python port is dependency-free).
import { spawnSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { createBehalf } from "../dist/index.js";
import { HttpRevocationStore } from "../dist/remote.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pythonDir = join(root, "python");

function py(args) {
  const r = spawnSync("python3", args, { cwd: pythonDir, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`python3 ${args.join(" ")} failed:\n${r.stderr}`);
  return r.stdout.trim();
}

let failures = 0;
function check(name, cond) {
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}`);
  if (!cond) failures++;
}

async function allowed(mandate, action) {
  try {
    await mandate.authorize(action);
    return true;
  } catch {
    return false;
  }
}

// ---- A) Python issues -> TypeScript verifies ----
{
  const out = JSON.parse(py(["interop_issue.py", "spend:usd<=50"]));
  const verifier = createBehalf({ trust: [out.pubkey] });
  const m = verifier.import(out.mandate);
  check("PY->TS  allows in-scope (spend:usd=20)", await allowed(m, "spend:usd=20"));
  check("PY->TS  denies out-of-scope (spend:usd=60)", !(await allowed(m, "spend:usd=60")));
}

// ---- A2) Python issues + attenuates -> TypeScript verifies the 2-block chain ----
{
  const out = JSON.parse(py(["interop_issue.py", "spend:usd<=50", "spend:usd<=20"]));
  const verifier = createBehalf({ trust: [out.pubkey] });
  const m = verifier.import(out.mandate);
  check("PY->TS  attenuated chain allows spend:usd=20", await allowed(m, "spend:usd=20"));
  check("PY->TS  attenuated chain denies spend:usd=21", !(await allowed(m, "spend:usd=21")));
}

// ---- B) TypeScript issues -> Python verifies ----
{
  const issuer = createBehalf();
  const m = issuer.grant({
    principal: "ts",
    agent: "issuer",
    can: ["spend:usd<=50"],
    expiresIn: "1h",
  });
  const allow = py(["interop_verify.py", issuer.publicKey, m.serialize(), "spend:usd=20"]);
  const deny = py(["interop_verify.py", issuer.publicKey, m.serialize(), "spend:usd=60"]);
  check("TS->PY  allows in-scope (spend:usd=20)", allow === "ALLOW");
  check("TS->PY  denies out-of-scope (spend:usd=60)", deny.startsWith("DENY"));
}

// ---- B2) TypeScript issues + attenuates -> Python verifies the 2-block chain ----
{
  const issuer = createBehalf();
  const root = issuer.grant({
    principal: "ts",
    agent: "issuer",
    can: ["spend:usd<=50"],
    expiresIn: "1h",
  });
  const child = root.attenuate({ can: ["spend:usd<=20"], agent: "ts-sub" });
  const allow = py(["interop_verify.py", issuer.publicKey, child.serialize(), "spend:usd=20"]);
  const deny = py(["interop_verify.py", issuer.publicKey, child.serialize(), "spend:usd=21"]);
  check("TS->PY  attenuated chain allows spend:usd=20", allow === "ALLOW");
  check("TS->PY  attenuated chain denies spend:usd=21", deny.startsWith("DENY"));
}

// ---- C) Cross-language revocation propagation through the control plane ----
//   The control plane runs as its own process (the bin); Python issues a mandate
//   and later revokes it via the plane; a TS verifier (checking revocation
//   against the same plane) goes from allow -> deny. Revocation crosses the
//   language boundary. The plane must be a separate process because the Python
//   calls here are synchronous and would otherwise block an in-process server.
{
  const home = mkdtempSync(join(tmpdir(), "behalf-interop-"));
  const cp = spawn("node", [join(root, "dist", "control-plane.js")], {
    env: { ...process.env, PORT: "0", BEHALF_HOME: home },
    stdio: ["ignore", "ignore", "pipe"],
  });
  try {
    const base = await new Promise((resolve, reject) => {
      let buf = "";
      cp.stderr.on("data", (d) => {
        buf += d;
        const m = /http:\/\/127\.0\.0\.1:(\d+)/.exec(buf);
        if (m) resolve(`http://127.0.0.1:${m[1]}`);
      });
      cp.on("exit", () => reject(new Error("control plane exited early")));
      setTimeout(() => reject(new Error("control plane start timeout")), 5000);
    });

    const out = JSON.parse(py(["interop_issue.py", "spend:usd<=50"]));
    const verifier = createBehalf({ trust: [out.pubkey], revocations: new HttpRevocationStore(base) });
    const m = verifier.import(out.mandate);
    check("control-plane: TS allows PY mandate before revoke", await allowed(m, "spend:usd=20"));
    py(["interop_revoke.py", base, m.id]); // Python revokes through the plane
    check("control-plane: TS denies after PY revokes", !(await allowed(m, "spend:usd=20")));
  } finally {
    cp.kill();
    rmSync(home, { recursive: true, force: true });
  }
}

console.log(`\n${failures === 0 ? "all interop checks passed" : `${failures} interop check(s) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
