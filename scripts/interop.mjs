// Cross-language wire-interop check: a mandate issued by one reference port must
// verify and authorize correctly in the other. Run after `npm run build`:
//
//   node scripts/interop.mjs
//
// Requires python3 on PATH (the Python port is dependency-free).
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createBehalf } from "../dist/index.js";

const pythonDir = join(dirname(fileURLToPath(import.meta.url)), "..", "python");

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

console.log(`\n${failures === 0 ? "all interop checks passed" : `${failures} interop check(s) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
