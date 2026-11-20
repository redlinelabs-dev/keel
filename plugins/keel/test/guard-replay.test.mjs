/**
 * Guard replay: the security guard against the command shapes that cost a
 * real user's attention.
 *
 * A four-week audit of one user's auto-mode sessions found most of the
 * guard's asks were noise (`env` inside a grep pattern, curl flags inside a
 * URL slug or a heredoc) while the asks that mattered carried the wrong
 * label. That log is work data and stays off this public repo, so
 * fixtures/guard-standin.jsonl is a stand-in: commands written fresh, set in
 * this org's open-source repos (keel, dyno, ynab-mcp, banners-site), one per
 * shape the audit found. No line is copied from the audit.
 *
 * Each record carries a label:
 *
 *   signal   worth the interruption; it must ask
 *   noise    not worth it; the count of these that still ask is ratcheted
 *   blocked  must keep blocking
 *   allowed  must keep allowing (catches a rule that widens)
 *
 * security.test.mjs pins hand-written edge cases one rule at a time. This
 * file pins the ratio: how many interruptions are noise.
 */

import "./hermetic.mjs";
import { test, describe, before } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir, availableParallelism } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK = join(HERE, "..", "hooks", "security-guard.mjs");
const RECORDS = readFileSync(join(HERE, "fixtures", "guard-standin.jsonl"), "utf-8")
  .split("\n").filter(Boolean).map((l) => JSON.parse(l));

// Noise records the current guard still asks on. Each guard PR that cuts
// noise lowers this to its new exact count; it is never raised. A change that
// needs it raised is adding interruptions, and has to argue for that instead.
const NOISE_ASK_CEILING = 11;

// Signal the current guard misses, each with what closes it. Known, tracked,
// and expected to flip: when one starts asking, node:test reports the todo as
// passing and its entry comes out here.
const KNOWN_MISSES = new Map([
  ["deletes a remote branch with --delete", "a remote-deletion rule"],
  ["live POST to an outside password-forgot endpoint", "a write-to-outside-host rule"],
]);

const SCRATCH = mkdtempSync(join(tmpdir(), "keel-replay-"));
process.on("exit", () => rmSync(SCRATCH, { recursive: true, force: true }));
// ~ in an Edit subject expands against HOME; keep it off the real one.
const HOME = mkdtempSync(join(SCRATCH, "home-"));

function run(rec) {
  const tool_input = rec.tool === "Bash" ? { command: rec.subject } : { file_path: rec.subject };
  const payload = {
    hook_event_name: "PreToolUse", tool_name: rec.tool, tool_input,
    session_id: "replay", permission_mode: "auto",
  };
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [HOOK], {
      env: { ...process.env, HOME, KEEL_ACTIVITY_DIR: mkdtempSync(join(SCRATCH, "act-")) },
    });
    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("error", reject);
    p.on("close", (code) => {
      let json = null;
      try { json = JSON.parse(out); } catch { /* blocked paths write stderr only */ }
      resolve({ code, json, stderr: err });
    });
    p.stdin.end(JSON.stringify(payload));
  });
}

const BLOCKED = 2;
const isAsk = (r) => r.code === 0 && r.json?.hookSpecificOutput?.permissionDecision === "ask";
const isAllow = (r) => r.code === 0 && r.json?.continue === true;

// One spawn per record, run in parallel: sequential spawning is most of the
// suite's wall time otherwise.
const results = new Array(RECORDS.length);
before(async () => {
  let next = 0;
  const worker = async () => {
    while (next < RECORDS.length) {
      const i = next++;
      results[i] = await run(RECORDS[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(8, availableParallelism()) }, worker));
});

const byLabel = (label) => RECORDS.map((rec, i) => ({ rec, i })).filter((x) => x.rec.label === label);
const name = ({ rec, i }) => `#${i + 1}: ${rec.note}`;

test("every known miss names a signal record", () => {
  const notes = new Set(byLabel("signal").map((x) => x.rec.note));
  for (const note of KNOWN_MISSES.keys()) assert.ok(notes.has(note), `stale KNOWN_MISSES entry: ${note}`);
});

describe("replay: signal still asks", () => {
  for (const x of byLabel("signal")) {
    const fix = KNOWN_MISSES.get(x.rec.note);
    const opts = fix ? { todo: `closed by ${fix}` } : {};
    test(name(x), opts, () => assert.ok(isAsk(results[x.i]), `should ask: ${x.rec.subject.slice(0, 120)}`));
  }
});

describe("replay: blocked stays blocked", () => {
  for (const x of byLabel("blocked")) {
    test(name(x), () => assert.equal(results[x.i].code, BLOCKED));
  }
});

describe("replay: allowed stays allowed", () => {
  for (const x of byLabel("allowed")) {
    test(name(x), () => assert.ok(isAllow(results[x.i]), `should allow: ${x.rec.subject.slice(0, 120)}`));
  }
});

/**
 * A noise record that moves from ask to block is not a cut in noise: the
 * ceiling above counts only asks, so a harmless command turned into a hard
 * stop would read as progress. A block is fine only where the reason's
 * rewrite applies: running env (name one variable instead), or env as a
 * branch of a quoted search alternation (write [e]nv). Every other noise
 * record must not block. CI review on #27 caught `ls -a env` blocking under
 * an env rule that matched the word as a trailing argument.
 */
const BLOCK_WITH_REWRITE = /(?:^|[;&]\s*)(?:sudo\s+)?env\s*\||["'][^"'\n]*[|(]\s*env\s*\|[^"'\n]*["']/;
describe("replay: noise never becomes a block, except a dump blocked with a rewrite", () => {
  for (const x of byLabel("noise")) {
    test(name(x), () => {
      if (results[x.i].code !== BLOCKED) return;
      assert.match(x.rec.subject, BLOCK_WITH_REWRITE, `harmless command now blocks: ${x.rec.subject.slice(0, 120)}`);
      assert.match(results[x.i].stderr, /Rewrite and retry/);
    });
  }
});

test("replay: noise asks do not exceed the ceiling", (t) => {
  const asks = RECORDS.map((rec, i) => ({ rec, r: results[i] })).filter((x) => isAsk(x.r));
  const noise = asks.filter((x) => x.rec.label === "noise").length;
  const signal = asks.filter((x) => x.rec.label === "signal").length;
  t.diagnostic(`signal asks / total asks: ${signal}/${asks.length}`);
  t.diagnostic(`noise asks: ${noise} (ceiling ${NOISE_ASK_CEILING})`);
  assert.ok(noise <= NOISE_ASK_CEILING,
    `${noise} noise records ask, ceiling is ${NOISE_ASK_CEILING}: this change adds interruptions`);
});
