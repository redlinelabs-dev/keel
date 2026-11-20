// hermetic.mjs — imported first by every test file, for its side effect: the
// keel this suite spawns sees only the config its tests give it.
//
// Claude Code layers settings.json's env block into every process a session
// starts, so a suite run from a session on a configured machine inherited that
// machine's KEEL_* keys, and every spawn of bin/keel or a hook passed them on:
// on 2026-10-10, with the off switches set, 161 of 355 tests failed. And
// bin/keel reads settings.json itself, with the block winning over the shell,
// so a spawn without its own CLAUDE_CONFIG_DIR read the developer's real one.
//
// The same leak through a different root: the guard reads its user policy from
// $XDG_CONFIG_HOME/keel/policy.json. On 2026-11-20 a machine whose policy turns
// three shipped asks into blocks failed 6 security tests that CI passed. bin/keel
// also reads and writes under XDG_DATA_HOME and XDG_STATE_HOME.
//
// So: no inherited KEEL_* keys, and every env-redirectable root (ROOTS, which
// env.test.mjs checks against the code) points at its own empty temp dir. A test
// that needs one sets it in the child's env, where the reader can see it.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

for (const key of Object.keys(process.env)) {
  if (key.startsWith("KEEL_")) delete process.env[key];
}

export const ROOTS = ["CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"];

for (const name of ROOTS) {
  const dir = mkdtempSync(join(tmpdir(), `keel-test-${name.toLowerCase()}-`));
  process.env[name] = dir;
  process.on("exit", () => rmSync(dir, { recursive: true, force: true }));
}
