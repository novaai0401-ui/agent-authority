// Run every reference integration and fail on any non-zero exit, so examples
// are CI-checked and can't silently break when the core API evolves (this
// caught nothing the day it was added — it exists because the control-plane
// example DID silently break once).
import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const dir = join("dist-test", "examples");
const files = readdirSync(dir).filter((f) => f.endsWith(".js"));
if (files.length === 0) {
  console.error(`no compiled examples in ${dir} (run tsc -p tsconfig.test.json first)`);
  process.exit(1);
}

let failed = 0;
for (const f of files) {
  const r = spawnSync(process.execPath, [join(dir, f)], { encoding: "utf8", timeout: 60_000 });
  const ok = r.status === 0;
  console.log(`${ok ? "ok  " : "FAIL"} - ${f}`);
  if (!ok) {
    failed++;
    console.error((r.stdout ?? "") + (r.stderr ?? ""));
  }
}
process.exit(failed > 0 ? 1 : 0);
