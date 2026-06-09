#!/usr/bin/env node
import { homedir } from "node:os";
import { join } from "node:path";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { createBehalf, type Behalf } from "./behalf.js";
import {
  newKeyPair,
  exportPublicKey,
  exportPrivateKey,
  importPublicKey,
  importPrivateKey,
} from "./crypto.js";
import { FileRevocationStore, FileAuditStore } from "./persist.js";
import { AuthorizationError } from "./errors.js";
import { lint } from "./lint.js";
import {
  generateQuickstart,
  findSurface,
  listSurfaces,
  type Surface,
} from "./quickstart.js";

/**
 * `behalf` CLI — grant, inspect, authorize, revoke, and audit mandates from the
 * terminal. State (issuer keypair, revocation list, audit log) lives under
 * $BEHALF_HOME (default ~/.behalf), so mandates issued in one invocation can be
 * checked and revoked in the next.
 */

const HOME = process.env.BEHALF_HOME ?? join(homedir(), ".behalf");
const KEY_FILE = join(HOME, "key.json");
const REV_FILE = join(HOME, "revocations.json");
const AUDIT_FILE = join(HOME, "audit.jsonl");

function loadEngine(): Behalf {
  if (!existsSync(HOME)) mkdirSync(HOME, { recursive: true });
  let keyPair;
  if (existsSync(KEY_FILE)) {
    const { priv, pub } = JSON.parse(readFileSync(KEY_FILE, "utf8"));
    keyPair = { privateKey: importPrivateKey(priv, pub), publicKey: importPublicKey(pub) };
  } else {
    keyPair = newKeyPair();
    writeFileSync(
      KEY_FILE,
      JSON.stringify({
        priv: exportPrivateKey(keyPair.privateKey),
        pub: exportPublicKey(keyPair.publicKey),
      }),
      "utf8",
    );
  }
  return createBehalf({
    rootKeyPair: keyPair,
    revocations: new FileRevocationStore(REV_FILE),
    audit: new FileAuditStore(AUDIT_FILE),
  });
}

/** Tiny flag parser: collects --flag value, repeats into arrays, _ for positionals. */
function parseArgs(argv: string[]): { _: string[]; [k: string]: string | string[] } {
  const out: { _: string[]; [k: string]: string | string[] } = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const val = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : "true";
      const existing = out[key];
      if (existing === undefined) out[key] = val;
      else if (Array.isArray(existing)) existing.push(val);
      else out[key] = [existing, val];
    } else {
      out._.push(a);
    }
  }
  return out;
}

function asArray(v: string | string[] | undefined): string[] {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

const USAGE = `behalf — agent authority CLI

Usage:
  behalf pubkey
  behalf grant --principal <id> --agent <id> --can <cap> [--can <cap> ...] --expires <dur>
  behalf inspect <mandate>
  behalf authorize <mandate> <action>
  behalf revoke <mandate-id>
  behalf audit <mandate-id>
  behalf lint <cap> [<cap> ...]
  behalf quickstart <surface>   (e.g. claude-code, cursor, copilot, gpt, gemini)
  behalf quickstart --list      (list every surface; any AI is configurable)

State dir: ${HOME}  (override with $BEHALF_HOME)`;

/** Commands that need no key store or engine: lint, quickstart. */
function runStateless(cmd: string, args: { _: string[]; [k: string]: string | string[] }): number {
  if (cmd === "lint") {
    const caps = args._;
    if (caps.length === 0) {
      console.error("lint requires at least one capability");
      return 2;
    }
    const findings = lint(caps);
    for (const f of findings) {
      console.log(`${f.level.toUpperCase().padEnd(5)} ${f.capability}  ${f.message}`);
    }
    const hasProblem = findings.some((f) => f.level !== "info");
    console.log(`\n${findings.length} finding(s)`);
    return hasProblem ? 1 : 0;
  }

  // quickstart
  const extra = loadCustomSurfaces(args.surfaces as string | undefined);
  if (args.list !== undefined || args._[0] === "list") {
    for (const s of listSurfaces(extra)) console.log(`${s.id.padEnd(16)} ${s.name}`);
    return 0;
  }
  const id = args._[0];
  if (!id) {
    console.error("quickstart requires a surface id, or --list. e.g. behalf quickstart claude-code");
    return 2;
  }
  const surface = findSurface(id, extra);
  if (!surface) {
    console.error(`unknown surface "${id}". Run: behalf quickstart --list`);
    return 2;
  }
  const command = args.local !== undefined ? "node" : (args.command as string) ?? undefined;
  const cliArgs = args.local !== undefined ? ["dist/mcp-server.js"] : asArray(args.arg);
  const env: Record<string, string> = {};
  for (const e of asArray(args.env)) {
    const i = e.indexOf("=");
    if (i > 0) env[e.slice(0, i)] = e.slice(i + 1);
  }
  const qs = generateQuickstart(surface, {
    name: (args.name as string) ?? undefined,
    command,
    args: cliArgs.length ? cliArgs : undefined,
    env: Object.keys(env).length ? env : undefined,
  });
  console.log(args.format === "json" ? JSON.stringify(qs, null, 2) : qs.text);
  return 0;
}

function loadCustomSurfaces(file: string | undefined): Surface[] {
  if (!file) return [];
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8"));
    return Array.isArray(parsed) ? (parsed as Surface[]) : [parsed as Surface];
  } catch (e) {
    console.error(`could not read surfaces file "${file}": ${(e as Error).message}`);
    return [];
  }
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === "help" || cmd === "--help") {
    console.log(USAGE);
    return 0;
  }
  const args = parseArgs(rest);

  // Commands that don't touch mandate state shouldn't create the key store.
  if (cmd === "lint" || cmd === "quickstart") {
    return runStateless(cmd, args);
  }

  const engine = loadEngine();

  switch (cmd) {
    case "pubkey": {
      console.log(engine.publicKey);
      return 0;
    }
    case "grant": {
      const principal = args.principal as string;
      const agent = args.agent as string;
      const can = asArray(args.can);
      const expiresIn = (args.expires as string) ?? "1h";
      if (!principal || !agent || can.length === 0) {
        console.error("grant requires --principal, --agent, and at least one --can");
        return 2;
      }
      // Warn (on stderr, so stdout stays a clean mandate) about loose scopes.
      for (const f of lint(can)) {
        process.stderr.write(`[lint:${f.level}] ${f.capability}: ${f.message}\n`);
      }
      const m = engine.grant({ principal, agent, can, expiresIn });
      console.log(m.serialize());
      return 0;
    }
    case "inspect": {
      const m = engine.import(args._[0]);
      try {
        engine.verifySignature(m.token);
        const scope = m.token.blocks
          .flatMap((b) => b.caveats)
          .filter((c) => c.t === "cap")
          .map((c) => (c as { can: string[] }).can);
        console.log(
          JSON.stringify(
            {
              valid: true,
              id: m.id,
              principal: m.principal,
              agent: m.agent,
              expiresAt: m.expiresAt ? new Date(m.expiresAt).toISOString() : undefined,
              chain: m.chain,
              scope,
            },
            null,
            2,
          ),
        );
        return 0;
      } catch (e) {
        console.log(JSON.stringify({ valid: false, reason: (e as Error).message }, null, 2));
        return 1;
      }
    }
    case "authorize": {
      const [mandate, action] = args._;
      if (!mandate || !action) {
        console.error("authorize requires <mandate> <action>");
        return 2;
      }
      try {
        await engine.import(mandate).authorize(action);
        console.log(`ALLOW  ${action}`);
        return 0;
      } catch (e) {
        const reason = e instanceof AuthorizationError ? e.reason : String(e);
        console.log(`DENY   ${action}  (${reason})`);
        return 1;
      }
    }
    case "revoke": {
      const id = args._[0];
      if (!id) {
        console.error("revoke requires <mandate-id>");
        return 2;
      }
      await engine.revoke(id);
      console.log(`revoked ${id}`);
      return 0;
    }
    case "audit": {
      const id = args._[0];
      if (!id) {
        console.error("audit requires <mandate-id>");
        return 2;
      }
      const trail = await engine.audit(id);
      for (const e of trail) {
        const ts = new Date(e.ts).toISOString();
        console.log(`${ts}  ${e.decision.toUpperCase().padEnd(5)}  ${e.action}${e.reason ? `  (${e.reason})` : ""}`);
      }
      console.log(`\n${trail.length} record(s)`);
      return 0;
    }
    default:
      console.error(`unknown command "${cmd}"\n\n${USAGE}`);
      return 2;
  }
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(e);
    process.exit(1);
  },
);
