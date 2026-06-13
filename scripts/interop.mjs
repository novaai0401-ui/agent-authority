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
import { createBehalf, newSealKeyPair } from "../dist/index.js";
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

async function allowed(verifier, token, action, proof) {
  try {
    await verifier.authorize(token, action, proof);
    return true;
  } catch {
    return false;
  }
}

// ---- A) Python issues (+ action-bound proofs) -> TypeScript verifies ----
{
  const out = JSON.parse(py(["interop_issue.py", "spend:usd<=50", "-", "spend:usd=20,spend:usd=60"]));
  const verifier = createBehalf({ trust: [out.pubkey] });
  const token = verifier.import(out.mandate).token;
  check("PY->TS  allows in-scope (spend:usd=20)", await allowed(verifier, token, "spend:usd=20", out.proofs["spend:usd=20"]));
  check("PY->TS  denies out-of-scope (spend:usd=60)", !(await allowed(verifier, token, "spend:usd=60", out.proofs["spend:usd=60"])));
}

// ---- A2) Python issues + attenuates -> TypeScript verifies the 2-block chain ----
{
  const out = JSON.parse(py(["interop_issue.py", "spend:usd<=50", "spend:usd<=20", "spend:usd=20,spend:usd=21"]));
  const verifier = createBehalf({ trust: [out.pubkey] });
  const token = verifier.import(out.mandate).token;
  check("PY->TS  attenuated chain allows spend:usd=20", await allowed(verifier, token, "spend:usd=20", out.proofs["spend:usd=20"]));
  check("PY->TS  attenuated chain denies spend:usd=21", !(await allowed(verifier, token, "spend:usd=21", out.proofs["spend:usd=21"])));
}

// ---- B) TypeScript issues (+ action-bound proof) -> Python verifies ----
{
  const issuer = createBehalf();
  const m = issuer.grant({ principal: "ts", agent: "issuer", can: ["spend:usd<=50"], expiresIn: "1h" });
  const allow = py(["interop_verify.py", issuer.publicKey, m.serialize(), "spend:usd=20", JSON.stringify(m.prove("spend:usd=20"))]);
  const deny = py(["interop_verify.py", issuer.publicKey, m.serialize(), "spend:usd=60", JSON.stringify(m.prove("spend:usd=60"))]);
  check("TS->PY  allows in-scope (spend:usd=20)", allow === "ALLOW");
  check("TS->PY  denies out-of-scope (spend:usd=60)", deny.startsWith("DENY"));
}

// ---- B2) TypeScript issues + attenuates -> Python verifies the 2-block chain ----
{
  const issuer = createBehalf();
  const root = issuer.grant({ principal: "ts", agent: "issuer", can: ["spend:usd<=50"], expiresIn: "1h" });
  const child = root.attenuate({ can: ["spend:usd<=20"], agent: "ts-sub" });
  const allow = py(["interop_verify.py", issuer.publicKey, child.serialize(), "spend:usd=20", JSON.stringify(child.prove("spend:usd=20"))]);
  const deny = py(["interop_verify.py", issuer.publicKey, child.serialize(), "spend:usd=21", JSON.stringify(child.prove("spend:usd=21"))]);
  check("TS->PY  attenuated chain allows spend:usd=20", allow === "ALLOW");
  check("TS->PY  attenuated chain denies spend:usd=21", deny.startsWith("DENY"));
}

// ---- D) Cross-language DELEGATION: PY issues a holder credential -> TS imports
//        + attenuates (signs a new block) -> PY verifies the resulting chain ----
{
  const out = JSON.parse(py(["interop_issue.py", "spend:usd<=50", "-", "ignored"]));
  const eng = createBehalf({ trust: [out.pubkey] });
  const imported = eng.import(out.cred);
  check("PY->TS  imported credential can delegate", imported.canDelegate === true);
  const child = imported.attenuate({ can: ["spend:usd<=20"], agent: "ts-sub" });
  const childSer = child.serialize();
  const verify = (action) =>
    py(["interop_verify.py", out.pubkey, childSer, action, JSON.stringify(child.prove(action))]);
  check("PY->TS->PY  delegated chain allows spend:usd=20", verify("spend:usd=20") === "ALLOW");
  check("PY->TS->PY  delegated chain denies spend:usd=21", verify("spend:usd=21").startsWith("DENY"));
}

// ---- E) Cross-language DELEGATION, reverse: TS issues a holder credential ->
//        PY imports + attenuates -> TS verifies the resulting chain ----
{
  const issuer = createBehalf();
  const m = issuer.grant({ principal: "ts", agent: "issuer", can: ["spend:usd<=50"], expiresIn: "1h" });
  const out = JSON.parse(
    py(["interop_delegate.py", issuer.publicKey, m.serializeWithKey(), "spend:usd<=20", "spend:usd=20,spend:usd=21"]),
  );
  const verifier = createBehalf({ trust: [issuer.publicKey] });
  const token = verifier.import(out.child).token;
  check("TS->PY->TS  delegated chain allows spend:usd=20", await allowed(verifier, token, "spend:usd=20", out.proofs["spend:usd=20"]));
  check("TS->PY->TS  delegated chain denies spend:usd=21", !(await allowed(verifier, token, "spend:usd=21", out.proofs["spend:usd=21"])));
}

// ---- F) Sealed credentials across the language boundary (#8). Only runs when
//        Python sealing is available (the optional `cryptography` package); the
//        stdlib-only interop job skips it, the native-backend job exercises it. ----
{
  if (py(["interop_seal.py", "avail"]).trim() === "yes") {
    // TS seals -> Python opens + authorizes.
    const recip = JSON.parse(py(["interop_seal.py", "keypair"]));
    const issuer = createBehalf();
    const m = issuer.grant({ principal: "ts", agent: "a", can: ["read:x"], expiresIn: "1h" });
    const sealed = m.sealForRecipient(recip.pub);
    const r = py(["interop_seal.py", "open", issuer.publicKey, recip.priv, recip.pub, sealed, "read:x"]);
    check("TS-seal -> PY-open authorizes the credential", r === "ALLOW");

    // Python seals -> TS opens + authorizes.
    const tsRecip = newSealKeyPair();
    const out = JSON.parse(py(["interop_seal.py", "issue_and_seal", tsRecip.publicKey]));
    const verifier = createBehalf({ trust: [out.pubkey] });
    const opened = verifier.importSealed(out.sealed, tsRecip);
    let ok = true;
    try {
      await opened.authorize("read:x");
    } catch {
      ok = false;
    }
    check("PY-seal -> TS-open authorizes the credential", ok && opened.canDelegate);
  } else {
    console.log("skip - sealed-credential interop (Python 'cryptography' not installed)");
  }
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

    const out = JSON.parse(py(["interop_issue.py", "spend:usd<=50", "-", "spend:usd=20"]));
    const verifier = createBehalf({ trust: [out.pubkey], revocations: new HttpRevocationStore(base) });
    const m = verifier.import(out.mandate);
    check("control-plane: TS allows PY mandate before revoke", await allowed(verifier, m.token, "spend:usd=20", out.proofs["spend:usd=20"]));
    py(["interop_revoke.py", base, m.id]); // Python revokes through the plane
    check("control-plane: TS denies after PY revokes", !(await allowed(verifier, m.token, "spend:usd=20", out.proofs["spend:usd=20"])));
  } finally {
    cp.kill();
    rmSync(home, { recursive: true, force: true });
  }
}

console.log(`\n${failures === 0 ? "all interop checks passed" : `${failures} interop check(s) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
