// Cross-version test runner. `node --test` only expands glob patterns on Node
// 21+, and shells differ on glob expansion, so we enumerate the compiled test
// files ourselves and pass them explicitly — works on Node 18/20/22+ and any OS.
import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const dir = join("dist-test", "test");
const files = readdirSync(dir)
  .filter((f) => f.endsWith(".test.js"))
  .map((f) => join(dir, f));

if (files.length === 0) {
  console.error(`no test files found in ${dir} (did you run tsc -p tsconfig.test.json?)`);
  process.exit(1);
}

const result = spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" });
process.exit(result.status ?? 1);
