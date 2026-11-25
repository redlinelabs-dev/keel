/**
 * herdr-session hook, `keel resume` and doctor's herdr check, against a fake
 * `hc` on PATH. hermetic.mjs shadows the real one for every other test.
 *
 * The properties that matter:
 *   1. only the Claude in the terminal's foreground labels it — a nested
 *      `claude -p` inherits $HC_TERMINAL_ID and must not overwrite the label
 *   2. a deliberate exit clears the label; any other end leaves it, because a
 *      lost core is exactly the end it exists for
 *   3. resume types only where the terminal's own shell is the foreground
 *      program. Cold review (2026-11-24) found pid equality alone reading a
 *      terminal made with `hc run claude` as a shell, which would have pasted
 *      a command into a working agent.
 *   4. only allowlisted label values are ever typed: the same review built a
 *      fish quote-escape and a DEL backspace that the first version's
 *      quoting let through
 *   5. resume never appends to a line it didn't write: `hc send` pastes onto
 *      a draft older than 60s (measured: `echo DRAFTecho LATE` ran), so it
 *      presses Ctrl+C first, and gives up on a send hc holds
 *   6. never into a shell that may still be running its rc file: round three
 *      cut a .zshrc short with that Ctrl+C
 *   7. never with the sender's terminal id: on the first live run
 *      (2026-11-24) `hc send` from inside a pane wrapped the command in an
 *      <hc from="t2"> note and zsh answered "parse error near `\n'"
 *   8. neither the hook nor doctor starts a core: every hc command starts one,
 *      and a socket file or an inherited $HC_TERMINAL_ID outlives the core
 *   9. one session, one Claude: round four resumed a crashed pane's stale
 *      label beside the same session live elsewhere, typed past a Ctrl+Z'd
 *      Claude, aged a connected machine's shell with this machine's pid 1,
 *      and let two concurrent runs type into one pane; round five raced
 *      that version's lock over a dead run's and two runs held it
 *
 * Fixtures differ from the bare-shell base in one field each: round two found
 * six mutants surviving fixtures that changed two at once. The mutants these
 * tests must kill — re-run them by hand after touching hc-core.mjs,
 * atBareShell, resumeStep, cmdResume or the hook:
 *   drop `fg.pid === t.pid`                 → "a shell in front of the root shell"
 *   drop the foreground-name-is-a-shell test → "a program exec'd over the shell"
 *   drop the root-argv-is-a-shell test      → "a non-shell root under a shell foreground"
 *   drop `!status.app`                      → "the core reports an agent"
 *   drop Number.isInteger(t.pid)            → "no pid yet (still coming back)"
 *   drop the settle age                     → "a shell younger than the settle time"
 *   accept a shell of unknown age           → "a shell whose age ps can't report"
 *   use t.cwd instead of the foreground cwd → "a shell that has moved"
 *   drop the live filter                    → "a finished terminal"
 *   drop isForeground() on SessionEnd       → "a nested Claude's exit leaves the label"
 *   drop the hook's coreRunning()           → "with no core listening, the hook calls nothing"
 *   drop doctor's foreground-not-a-shell    → "is quiet about shells …"
 *   drop `step.command !== r.command`       → "a label that changed after the plan"
 *   drop the re-check after Ctrl+C          → "a pane that changed after Ctrl+C"
 *   drop doctor's coreRunning()             → "without a listening core it asks hc nothing"
 *   ignore HC_SOCKET / HC_TERMINAL_SOCKET   → "finds the core at $HC_SOCKET, or …"
 *   no-socket-path fallback returns true    → "with no socket path known …"
 *   doctor counts any app as Claude         → "is quiet about shells …" (the vim pane)
 *   allow `machine/t7` addresses            → "a terminal on a connected machine"
 *   drop the one-session-one-pane rule      → "a session labelled on two panes"
 *   ignore stopped / foreground children    → "a stopped job" / "job control off"
 *   count `+` from another tty              → every resume test (init's gettys)
 *   drop, never take over, or leak the lock → "a second keel resume …"
 *   remove a lock it no longer holds        → "a run whose lock is taken mid-way"
 *   skip the ownership check before acting  → "a run whose lock is taken mid-way"
 *   re-check one pane, not the whole plan   → "a session reopened in another pane …"
 *   ignore or drop a pane hc can't describe → "a pane hc can't describe …"
 * (mut.ts in the session scratchpad ran these; 2026-11-24.)
 */

import "./hermetic.mjs";
import { test, describe, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK = join(HERE, "..", "hooks", "herdr-session.mjs");
const KEEL = join(HERE, "..", "bin", "keel");
const SESSION = "199e2f9e-4d51-460f-a1e1-46c38db5ca12";
const OTHER = "0e49880b-0141-4fba-92bb-c525588e8248";
// coreRunning reads /proc/net/unix; without it (macOS) it trusts
// $HC_TERMINAL_ID, and the tests that tell a dead core from a live one can't.
const PROC = existsSync("/proc/net/unix");
const SCRIPT = process.platform === "linux" && spawnSync("script", ["--version"]).status === 0;

/** `[ppid, stat, comm]` for each child of pid, from ps. */
function children(pid) {
  const r = spawnSync("ps", ["-A", "-o", "pid=,ppid=,stat=,comm="], { encoding: "utf-8" });
  return r.stdout.split("\n").map((l) => l.trim().split(/\s+/)).filter((f) => Number(f[1]) === pid).map((f) => f.slice(1));
}

/** The pid whose child is named `name`, among root's descendants; null if none yet. */
function findParentOf(root, name) {
  const rows = spawnSync("ps", ["-A", "-o", "pid=,ppid=,comm="], { encoding: "utf-8" }).stdout
    .split("\n").map((l) => l.trim().split(/\s+/)).filter((f) => f.length >= 3).map(([p, pp, c]) => [Number(p), Number(pp), c]);
  const tree = new Set([root]);
  for (let grew = true; grew;) {
    grew = false;
    for (const [p, pp] of rows) if (tree.has(pp) && !tree.has(p)) { tree.add(p); grew = true; }
  }
  return rows.find(([p, pp, c]) => tree.has(p) && c === name && pp !== root)?.[1] ?? null;
}

/**
 * A real process resume's checks pass for: a minute old or more, with no
 * child stopped or in its terminal's foreground. pid 1 usually is; in a
 * container whose pid 1 just started, another one is. Found, not assumed.
 */
const OLD = (() => {
  const rows = spawnSync("ps", ["-A", "-o", "pid=,ppid=,tty=,etime=,stat="], { encoding: "utf-8" }).stdout
    .split("\n").map((l) => l.trim().split(/\s+/)).filter((f) => f.length >= 5);
  const secs = (e) => e.split(/[-:]/).map(Number).reverse().reduce((t, v, i) => t + v * [1, 60, 3600, 86400][i], 0);
  const fine = ([pid, , tty, etime]) => secs(etime) >= 60 &&
    !rows.some(([, pp, ctty, , stat]) => pp === pid && (stat.includes("T") || (stat.includes("+") && ctty === tty)));
  const pick = rows.find((r) => r[0] === "1" && fine(r)) ?? rows.find(fine);
  if (!pick) throw new Error("no process old enough to stand in for a settled shell");
  return Number(pick[0]);
})();

async function until(check, ms = 5000) {
  for (const end = Date.now() + ms; Date.now() < end; await new Promise((r) => setTimeout(r, 50))) if (check()) return;
  throw new Error("timed out waiting for the fixture process");
}

// A stand-in for herdr-core's CLI. `ls` and `get` answer from a state file.
// A terminal with `after` answers its first `get` as itself and later ones as
// `after` (a pane that changed while resume waited); with `afterKeys`, gets
// after a `keys` call to it answer as that. `failKeys` / `failSend` make those
// fail, and `failGet` its get; `holdSend` makes send hang, as hc does while a
// draft holds it; `stealLock: {path, pid}` makes keys overwrite resume's lock,
// as a second run taking it over would. Every call is recorded with the
// caller's terminal id.
const FAKE_HC = `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2).filter((a) => a !== "--json");
const log = process.env.FAKE_HC_LOG;
const prior = fs.existsSync(log) ? fs.readFileSync(log, "utf-8").trim().split("\\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
fs.appendFileSync(log, JSON.stringify({ args, from: process.env.HC_TERMINAL_ID ?? null }) + "\\n");
const state = JSON.parse(fs.readFileSync(process.env.FAKE_HC_STATE, "utf-8"));
const find = (a) => state.find((t) => t.address === a);
const t = find(args[1]);
if (args[0] === "ls") {
  console.log(JSON.stringify({ terminals: state.map((t) => ({ address: t.address, state: t.state ?? "live" })) }));
} else if (args[0] === "get") {
  if (!t || t.failGet) process.exit(1);
  const seen = prior.filter((c) => c.args[0] === "get" && c.args[1] === args[1]).length;
  const keyed = prior.some((c) => c.args[0] === "keys" && c.args[1] === args[1]);
  console.log(JSON.stringify(t.afterKeys && keyed ? t.afterKeys : t.after && seen > 0 ? t.after : t));
} else if (args[0] === "keys" && t?.failKeys) {
  process.exit(1);
} else if (args[0] === "keys" && t?.stealLock) {
  fs.writeFileSync(t.stealLock.path, t.stealLock.pid);
  console.log(JSON.stringify({ ok: true }));
} else if (args[0] === "send" && t?.failSend) {
  process.exit(1);
} else if (args[0] === "send" && t?.slowSend) {
  setTimeout(() => console.log(JSON.stringify({ ok: true })), 1000);
} else if (args[0] === "send" && t?.holdSend) {
  setTimeout(() => console.log(JSON.stringify({ ok: true })), 60000);
} else {
  console.log(JSON.stringify({ ok: true }));
}
`;

const cleanup = [];
after(() => { for (const f of cleanup) f(); });

/** A unix socket something is listening on, as a running core's is. */
async function listen(path) {
  mkdirSync(dirname(path), { recursive: true });
  const server = createServer();
  await new Promise((resolve) => server.listen(path, resolve));
  server.unref();
  cleanup.push(() => server.close());
  return path;
}

/**
 * The fake hc on PATH, and a core listening at
 * $XDG_RUNTIME_DIR/herdr-core/default.sock unless `core: false`.
 */
async function fakeHc(terminals, { core = true } = {}) {
  // Under /tmp, not $TMPDIR: the fake core's socket path must fit the
  // 104-108 byte limit on unix socket paths, and macOS's $TMPDIR alone is ~50.
  const root = mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "keel-fake-hc-"));
  cleanup.push(() => rmSync(root, { recursive: true, force: true }));
  const dir = join(root, "bin");
  mkdirSync(dir);
  writeFileSync(join(dir, "hc"), FAKE_HC);
  chmodSync(join(dir, "hc"), 0o755);
  // doctor asks `claude plugin list`; answer it without a real claude.
  writeFileSync(join(dir, "claude"), "#!/bin/sh\nprintf '[]'\n");
  chmodSync(join(dir, "claude"), 0o755);
  // So the fake runs even when a test narrows PATH to this directory.
  symlinkSync(process.execPath, join(dir, "node"));
  const runtime = join(root, "run");
  mkdirSync(runtime);
  if (core) await listen(join(runtime, "herdr-core", "default.sock"));
  const log = join(root, "calls.jsonl");
  const stateFile = join(root, "state.json");
  writeFileSync(stateFile, JSON.stringify(terminals));
  return {
    dir,
    runtime,
    env: { PATH: `${dir}:${process.env.PATH}`, FAKE_HC_LOG: log, FAKE_HC_STATE: stateFile, XDG_RUNTIME_DIR: runtime },
    calls: () => (existsSync(log) ? readFileSync(log, "utf-8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []),
  };
}

/**
 * A terminal as `hc get --json` describes it. The base: a zsh root that is
 * its own foreground, with no agent reported. Its pid is OLD, a real process
 * past the settle time with nothing stopped or in front under it. `fg`
 * overrides foreground fields one at a time; `root` sets the root argv (and,
 * unless `fg` names one, the foreground name with it).
 */
function term(address, { pid = OLD, root = "/usr/bin/zsh", fg, app = null, labels = {}, cwd = "/home/u/proj", ...rest } = {}) {
  const foreground = fg === null ? null : { pid, name: root.split("/").pop(), cwd, argv: [root], ...fg };
  return { address, pid, argv: [root], cwd, state: "live", labels, foreground, status: app ? { app, state: "idle" } : null, ...rest };
}
const claudeIn = (address, opts = {}) => term(address, { fg: { pid: 5555, name: "claude", argv: ["claude"] }, app: "claude-code", ...opts });

/**
 * Run the hook the way Claude Code does: through a shell, as a child of the
 * program the hook should recognise. `; :` keeps sh from exec'ing node, so
 * the ancestry is hook <- sh <- this test process, and a foreground pid of
 * process.pid means "the Claude in the foreground ran me".
 */
function runHook(payload, env, via = "sh") {
  const node = JSON.stringify(process.execPath), hook = JSON.stringify(HOOK);
  const [cmd, args] = via === "sh"
    ? ["sh", ["-c", `${node} ${hook}; :`]]
    // A non-shell in between, as a nested `claude -p` is: its own process.
    : [process.execPath, ["-e", `const r = require("node:child_process").spawnSync(process.execPath, [${hook}], { stdio: "inherit" }); process.exit(r.status ?? 1);`]];
  return spawnSync(cmd, args, {
    input: JSON.stringify(payload),
    encoding: "utf-8",
    env: { ...process.env, HC_TERMINAL_ID: "t3", ...env },
  });
}

const start = { hook_event_name: "SessionStart", source: "startup", session_id: SESSION, cwd: "/home/u/proj" };
const exit = (reason) => ({ hook_event_name: "SessionEnd", reason, session_id: SESSION });
const labels = (calls) => calls.filter((c) => c.args[0] === "label");
const meInFront = (address = "t3") => term(address, { fg: { pid: process.pid, name: "claude" } });

describe("herdr-session hook", () => {
  test("labels the terminal when its foreground program ran the hook through a shell", async () => {
    const hc = await fakeHc([meInFront()]);
    const r = runHook(start, hc.env);
    assert.equal(r.status, 0);
    assert.deepEqual(labels(hc.calls()).map((c) => c.args), [
      ["label", "t3", `claude.session=${SESSION}`, "claude.cwd=/home/u/proj"],
    ]);
  });

  test("a nested Claude — a different process between the hook and the foreground — leaves the label alone", async () => {
    const hc = await fakeHc([meInFront()]);
    runHook(start, hc.env, "nested");
    assert.equal(labels(hc.calls()).length, 0);
  });

  test("a nested Claude's exit leaves the label alone", async () => {
    const hc = await fakeHc([meInFront()]);
    runHook(exit("prompt_input_exit"), hc.env, "nested");
    assert.equal(labels(hc.calls()).length, 0);
  });

  test("outside an hc terminal it calls nothing", async () => {
    const hc = await fakeHc([meInFront()]);
    runHook(start, { ...hc.env, HC_TERMINAL_ID: "" });
    assert.equal(hc.calls().length, 0);
  });

  test("with no core listening, the hook calls nothing — an hc call would start one", { skip: !PROC && "no /proc" }, async () => {
    // An $HC_TERMINAL_ID inherited into tmux after the core is gone, with
    // the dead core's socket file still on disk (SIGKILL leaves it).
    const hc = await fakeHc([meInFront()], { core: false });
    mkdirSync(join(hc.runtime, "herdr-core"));
    writeFileSync(join(hc.runtime, "herdr-core", "default.sock"), "");
    runHook(start, hc.env);
    assert.equal(hc.calls().length, 0);
  });

  test("checks the pane's own core: a dead $HC_TERMINAL_SOCKET means no hc call, whatever else listens", { skip: !PROC && "no /proc" }, async () => {
    const hc = await fakeHc([meInFront()]);
    const gone = join(hc.runtime, "gone.sock");
    writeFileSync(gone, "");
    runHook(start, { ...hc.env, HC_TERMINAL_SOCKET: gone });
    assert.equal(hc.calls().length, 0);
  });

  test("KEEL_HERDR_OFF=1 turns it off", async () => {
    const hc = await fakeHc([meInFront()]);
    runHook(start, { ...hc.env, KEEL_HERDR_OFF: "1" });
    assert.equal(hc.calls().length, 0);
  });

  test("stores only an id-shaped session and an allowlisted absolute folder", async () => {
    const refused = [
      { session_id: "x; rm -rf ~" },
      { cwd: "relative/path" },
      { cwd: "/home/u/it's here" },
      { cwd: "/home/u/a\u007fb" },
      { cwd: "/home/u/$(touch x)" },
      { cwd: "/home/u/a\\b" },
      { cwd: "/home/u/a\nb" },
      { cwd: "/home/u/a‮b" },
    ];
    for (const change of refused) {
      const hc = await fakeHc([meInFront()]);
      runHook({ ...start, ...change }, hc.env);
      assert.equal(labels(hc.calls()).length, 0, JSON.stringify(change));
    }
    const accepted = [
      "/home/u/my proj-2.0",
      "/mnt/c/Program Files (x86)/tool",
      "/home/u/café", // precomposed
      "/home/u/café", // decomposed, as macOS names files
      "/home/u/हिन्दी",
    ];
    for (const cwd of accepted) {
      const hc = await fakeHc([meInFront()]);
      runHook({ ...start, cwd }, hc.env);
      assert.equal(labels(hc.calls()).length, 1, cwd);
    }
  });

  test("a deliberate exit clears the label; any other end keeps it", async () => {
    for (const reason of ["prompt_input_exit", "logout"]) {
      const hc = await fakeHc([meInFront()]);
      runHook(exit(reason), hc.env);
      assert.deepEqual(labels(hc.calls()).map((c) => c.args), [["label", "t3", "claude.session=", "claude.cwd="]], reason);
    }
    for (const reason of ["other", "clear"]) {
      const hc = await fakeHc([meInFront()]);
      runHook(exit(reason), hc.env);
      assert.equal(labels(hc.calls()).length, 0, reason);
    }
  });

  test("with no hc on PATH it still lets the session continue", () => {
    const r = spawnSync(process.execPath, [HOOK], {
      input: JSON.stringify(start),
      encoding: "utf-8",
      env: { ...process.env, HC_TERMINAL_ID: "t3", PATH: "/nonexistent" },
    });
    assert.equal(r.status, 0);
    assert.deepEqual(JSON.parse(r.stdout), { continue: true });
  });
});

function resume(args, hc, env = {}) {
  return spawnSync(process.execPath, [KEEL, "resume", ...args], {
    encoding: "utf-8",
    input: "",
    env: { ...process.env, ...hc.env, ...env },
  });
}
const typed = (calls) => calls.filter((c) => c.args[0] === "send" || c.args[0] === "keys");
const sends = (calls) => calls.filter((c) => c.args[0] === "send");
const labelled = { "claude.session": SESSION, "claude.cwd": "/home/u/proj" };

describe("keel resume", () => {
  test("clears the line, then types the resume, both without the sender's terminal id", async () => {
    const hc = await fakeHc([term("t7", { labels: labelled })]);
    const r = resume(["--yes"], hc, { HC_TERMINAL_ID: "t2" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const out = typed(hc.calls());
    assert.deepEqual(out.map((c) => c.args), [["keys", "t7", "ctrl+c"], ["send", "t7", `claude --resume ${SESSION}`]]);
    assert.deepEqual(out.map((c) => c.from), [null, null], "hc saw HC_TERMINAL_ID and would wrap the text in an <hc from> note");
  });

  test("changes to the session's folder first when the shell is elsewhere", async () => {
    const hc = await fakeHc([term("t7", { labels: { ...labelled, "claude.cwd": "/home/u/my proj" }, cwd: "/home/u" })]);
    resume(["--yes"], hc);
    assert.deepEqual(sends(hc.calls()).map((c) => c.args[2]), [`cd '/home/u/my proj' && claude --resume ${SESSION}`]);
  });

  test("a shell that has moved gets the cd, whatever folder the terminal started in", async () => {
    // The terminal's cwd is where it started; the shell's own cwd is where it is now.
    const hc = await fakeHc([term("t7", { labels: labelled, fg: { cwd: "/home/u/elsewhere" } })]);
    resume(["--yes"], hc);
    assert.deepEqual(sends(hc.calls()).map((c) => c.args[2]), [`cd '/home/u/proj' && claude --resume ${SESSION}`]);
  });

  test("a label with no folder resumes where the shell is", async () => {
    const hc = await fakeHc([term("t7", { labels: { "claude.session": SESSION } })]);
    resume(["--yes"], hc);
    assert.deepEqual(sends(hc.calls()).map((c) => c.args[2]), [`claude --resume ${SESSION}`]);
  });

  test("leaves alone every terminal whose own shell isn't the foreground program", async () => {
    const cases = {
      // one field from the base each
      "a shell in front of the root shell (nested bash, sudo -s)": term("t1", { labels: labelled, fg: { pid: 9999 } }),
      "a program exec'd over the shell (exec vim)": term("t2", { labels: labelled, fg: { name: "vim" } }),
      "a non-shell root under a shell foreground": term("t3", { labels: labelled, root: "/usr/bin/vim", fg: { name: "zsh" } }),
      "the core reports an agent": term("t4", { labels: labelled, app: "claude-code" }),
      "no foreground reported": term("t5", { labels: labelled, fg: null }),
      // as a terminal reports itself for a moment after a core start: no pid
      // anywhere, so null === null must not read as "the shell is in front"
      "no pid yet (still coming back)": term("t6", { labels: labelled, pid: null }),
      // the shapes these stand for
      "Claude in front of the shell": claudeIn("t7", { labels: labelled }),
      "Claude as the root program (hc run claude)": term("t8", { root: "claude", app: "claude-code", labels: labelled }),
    };
    for (const [name, t] of Object.entries(cases)) {
      const hc = await fakeHc([t]);
      const r = resume(["--yes"], hc);
      assert.equal(r.status, 0, name);
      assert.equal(typed(hc.calls()).length, 0, name);
      // Left alone, not offered as a command to type there yourself.
      assert.match(r.stdout, /left alone|still coming back/, name);
      assert.doesNotMatch(r.stdout, /run it there yourself/, name);
    }
  });

  test("a shell younger than the settle time gets nothing — it may still be running its rc file", async () => {
    const young = spawn("sleep", ["60"], { stdio: "ignore" });
    cleanup.push(() => young.kill());
    const hc = await fakeHc([term("t7", { labels: labelled, pid: young.pid })]);
    const r = resume(["--yes"], hc);
    assert.equal(typed(hc.calls()).length, 0);
    assert.match(r.stdout, /started \d+s ago/);
  });

  test("a shell with a stopped job under it gets nothing — a Claude suspended with Ctrl+Z", async () => {
    const shell = spawn("sh", ["-c", "sleep 60 & kill -STOP $!; wait"], { stdio: "ignore" });
    cleanup.push(() => { spawnSync("pkill", ["-KILL", "-P", String(shell.pid)]); shell.kill("SIGKILL"); });
    await until(() => children(shell.pid).some(([, stat]) => stat.includes("T")));
    const hc = await fakeHc([term("t7", { labels: labelled, pid: shell.pid })]);
    const r = resume(["--yes"], hc);
    assert.equal(typed(hc.calls()).length, 0);
    // (sh or sleep: the STOP can land before the forked child execs sleep)
    assert.match(r.stdout, /a stopped job \((sh|sleep)\) is under its shell/);
  });

  test("a shell with a program in its terminal's foreground gets nothing — job control off", { skip: !SCRIPT && "needs util-linux script" }, async () => {
    // In a pty, a non-interactive sh runs sleep in its own process group, the
    // terminal's foreground one: hc would report sh as the foreground leader.
    const pty = spawn("script", ["-qfc", "sh -c 'sleep 60; :'", "/dev/null"], { stdio: "ignore", env: { ...process.env, SHELL: "/bin/sh" } });
    cleanup.push(() => { spawnSync("pkill", ["-KILL", "-s", String(pty.pid)]); pty.kill("SIGKILL"); });
    let shell = null;
    await until(() => (shell = findParentOf(pty.pid, "sleep")) !== null);
    const hc = await fakeHc([term("t7", { labels: labelled, pid: shell })]);
    const r = resume(["--yes"], hc);
    assert.equal(typed(hc.calls()).length, 0);
    assert.match(r.stdout, /sleep is running in front of its shell/);
  });

  test("a terminal on a connected machine gets nothing — its pid isn't this machine's", async () => {
    const hc = await fakeHc([term("box/t7", { labels: labelled })]);
    const r = resume(["--yes"], hc);
    assert.equal(typed(hc.calls()).length, 0);
    assert.match(r.stdout, /on another machine/);
  });

  test("a session labelled on two panes is resumed in neither", async () => {
    const cases = {
      // a label left by a Claude that crashed, and the session reopened elsewhere
      "stale beside live": [term("t1", { labels: labelled }), claudeIn("t2", { labels: labelled })],
      "two bare shells": [term("t1", { labels: labelled }), term("t2", { labels: labelled })],
    };
    for (const [name, terms] of Object.entries(cases)) {
      const hc = await fakeHc(terms);
      const r = resume(["--yes"], hc);
      assert.equal(typed(hc.calls()).length, 0, name);
      assert.match(r.stdout, /same session is labelled on t2/, name);
    }
  });

  test("a session reopened in another pane after the plan is not resumed", async () => {
    // t2 is a plain shell when listed; by the re-check, Claude runs the session there.
    const t2 = term("t2", { fg: { pid: 9999, name: "vim" } });
    t2.after = claudeIn("t2", { labels: labelled });
    const hc = await fakeHc([term("t1", { labels: labelled }), t2]);
    resume(["--yes"], hc);
    assert.equal(typed(hc.calls()).length, 0);
  });

  test("a pane hc can't describe holds everything back — it might hold the session", async () => {
    const hc = await fakeHc([term("t1", { labels: labelled }), term("t2", { failGet: true })]);
    const r = resume(["--yes"], hc);
    assert.equal(typed(hc.calls()).length, 0);
    assert.match(r.stdout, /couldn't describe t2/);
  });

  test("Ctrl+C while it types stops it before the next pane", async () => {
    // Each send takes a moment; SIGINT the run during the first one.
    const slow = (a) => term(a, { labels: { "claude.session": a === "t1" ? SESSION : OTHER } });
    const hc = await fakeHc([slow("t1"), slow("t2")]);
    const state = JSON.parse(readFileSync(hc.env.FAKE_HC_STATE, "utf-8"));
    for (const t of state) t.slowSend = true;
    writeFileSync(hc.env.FAKE_HC_STATE, JSON.stringify(state));
    const p = spawn(process.execPath, [KEEL, "resume", "--yes"], { env: { ...process.env, ...hc.env }, stdio: "ignore" });
    await until(() => sends(hc.calls()).length >= 1, 15000);
    p.kill("SIGINT");
    await new Promise((done) => p.on("exit", done));
    await new Promise((r) => setTimeout(r, 1500));
    assert.equal(sends(hc.calls()).length, 1, "kept typing after Ctrl+C");
  });

  test("a run whose lock is taken mid-way stops before sending, and leaves the other's lock", async () => {
    const hc = await fakeHc([]);
    const lock = join(hc.runtime, `keel-resume-${process.getuid()}.lock`);
    writeFileSync(hc.env.FAKE_HC_STATE, JSON.stringify([term("t7", { labels: labelled, stealLock: { path: lock, pid: String(process.pid) } })]));
    const r = resume(["--yes"], hc);
    assert.equal(r.status, 1);
    assert.equal(sends(hc.calls()).length, 0);
    assert.match(r.stdout, /another keel resume took the lock/);
    assert.equal(readFileSync(lock, "utf-8"), String(process.pid), "removed a lock it no longer held");
  });

  test("a lock that isn't a pid is taken over", async () => {
    const hc = await fakeHc([term("t7", { labels: labelled })]);
    writeFileSync(join(hc.runtime, `keel-resume-${process.getuid()}.lock`), "");
    assert.equal(resume(["--yes"], hc).status, 0);
    assert.equal(sends(hc.calls()).length, 1);
  });

  test("eight runs racing over a dead run's lock type into the pane at most once", async () => {
    const hc = await fakeHc([term("t7", { labels: labelled })]);
    writeFileSync(join(hc.runtime, `keel-resume-${process.getuid()}.lock`), "2147483646");
    const run = () => new Promise((done) => {
      const p = spawn(process.execPath, [KEEL, "resume", "--yes"], { env: { ...process.env, ...hc.env }, stdio: "ignore" });
      p.on("exit", done);
    });
    await Promise.all(Array.from({ length: 8 }, run));
    assert.ok(sends(hc.calls()).length <= 1, `${sends(hc.calls()).length} runs sent`);
    assert.ok(hc.calls().filter((c) => c.args[0] === "keys").length <= 1, "two runs pressed Ctrl+C");
  });

  test("a second keel resume while one runs sends nothing; a dead one's lock is taken over", async () => {
    const live = await fakeHc([term("t7", { labels: labelled })]);
    writeFileSync(join(live.runtime, `keel-resume-${process.getuid()}.lock`), String(process.pid));
    const r = resume(["--yes"], live);
    assert.equal(r.status, 1);
    assert.equal(typed(live.calls()).length, 0);
    assert.match(r.stdout, new RegExp(`another keel resume \\(pid ${process.pid}\\)`));

    const dead = await fakeHc([term("t7", { labels: labelled })]);
    const lock = join(dead.runtime, `keel-resume-${process.getuid()}.lock`);
    writeFileSync(lock, "2147483646");
    assert.equal(resume(["--yes"], dead).status, 0);
    assert.equal(sends(dead.calls()).length, 1);
    assert.equal(existsSync(lock), false, "the lock outlived the run");
  });

  test("a shell whose age ps can't report gets nothing", async () => {
    // A pid no process has, as when hc reports one that has just exited.
    const hc = await fakeHc([term("t7", { labels: labelled, pid: 2147483646 })]);
    const r = resume(["--yes"], hc);
    assert.equal(typed(hc.calls()).length, 0);
    assert.match(r.stdout, /can't tell what its shell is running/);
  });

  test("a finished terminal is not a candidate", async () => {
    const hc = await fakeHc([term("t7", { labels: labelled, state: "finished" })]);
    resume(["--yes"], hc);
    assert.equal(typed(hc.calls()).length, 0);
  });

  test("says why: still coming back, or an agent the core reports", async () => {
    const back = await fakeHc([term("t6", { labels: labelled, pid: null })]);
    assert.match(resume(["--dry-run"], back).stdout, /still coming back/);
    const agent = await fakeHc([term("t4", { labels: labelled, app: "claude-code" })]);
    assert.match(resume(["--dry-run"], agent).stdout, /herdr-core reports claude-code there/);
  });

  test("types only allowlisted label values", async () => {
    const refused = ["/x\\'; touch PWN; #", "/a'\u007f\u007f; touch PWN", "relative/path", "/home/u/$(id)", "/a\nb", "/a‮b"];
    for (const cwd of refused) {
      const hc = await fakeHc([term("t7", { labels: { ...labelled, "claude.cwd": cwd } })]);
      resume(["--yes"], hc);
      assert.equal(typed(hc.calls()).length, 0, JSON.stringify(cwd));
    }
    const hc = await fakeHc([term("t7", { labels: { "claude.session": "x; rm -rf ~" } })]);
    resume(["--yes"], hc);
    assert.equal(typed(hc.calls()).length, 0);
  });

  test("prints the commands as separate lines for a shell it doesn't type into", async () => {
    const hc = await fakeHc([term("t7", { root: "/usr/bin/nu", labels: labelled, cwd: "/home/u" })]);
    const r = resume(["--yes"], hc);
    assert.equal(typed(hc.calls()).length, 0);
    assert.match(r.stdout, /^\s+cd '\/home\/u\/proj'$/m);
    assert.match(r.stdout, new RegExp(`^\\s+claude --resume ${SESSION}$`, "m"));
    assert.doesNotMatch(r.stdout, /&&/, "nu and Windows PowerShell can't parse &&");
  });

  test("a pane that changed after the plan gets nothing", async () => {
    const vim = term("t7", { labels: labelled });
    vim.after = term("t7", { labels: labelled, fg: { pid: 7777, name: "vim" } });
    const relabelled = term("t7", { labels: labelled });
    relabelled.after = term("t7", { labels: { ...labelled, "claude.session": OTHER } });
    for (const [name, t] of Object.entries({ "a program started": vim, "a label that changed after the plan": relabelled })) {
      const hc = await fakeHc([t]);
      const r = resume(["--yes"], hc);
      assert.equal(typed(hc.calls()).length, 0, name);
      assert.match(r.stdout, /changed since/, name);
    }
  });

  test("a pane that changed after Ctrl+C gets no command", async () => {
    const t = term("t7", { labels: labelled });
    t.afterKeys = term("t7", { labels: labelled, fg: { pid: 7777, name: "vim" } });
    const hc = await fakeHc([t]);
    resume(["--yes"], hc);
    assert.equal(sends(hc.calls()).length, 0);
  });

  test("a send hc holds is given up within seconds, reported, and exits 1", async () => {
    const hc = await fakeHc([term("t7", { labels: labelled, holdSend: true })]);
    const began = Date.now();
    const r = resume(["--yes"], hc);
    assert.ok(Date.now() - began < 9000, "resume waited on the held send");
    assert.equal(r.status, 1);
    assert.match(r.stdout, new RegExp(`held the send.*claude --resume ${SESSION}`));
  });

  test("a failed clear or send exits 1 and shows the command to type", async () => {
    for (const fail of ["failKeys", "failSend"]) {
      const hc = await fakeHc([term("t7", { labels: labelled, [fail]: true })]);
      const r = resume(["--yes"], hc);
      assert.equal(r.status, 1, fail);
      assert.match(r.stdout, new RegExp(`yourself.*claude --resume ${SESSION}`), fail);
      if (fail === "failKeys") assert.equal(sends(hc.calls()).length, 0, "typed after the line couldn't be cleared");
    }
  });

  test("--dry-run and a non-terminal stdin without --yes type nothing", async () => {
    for (const args of [["--dry-run"], []]) {
      const hc = await fakeHc([term("t7", { labels: labelled })]);
      const r = resume(args, hc);
      assert.equal(r.status, 0);
      assert.match(r.stdout, /claude --resume/);
      assert.equal(typed(hc.calls()).length, 0, args.join(" ") || "(no flags)");
    }
  });

  test("label text is printed without escape sequences, format characters or line breaks", async () => {
    const where = "evil\u001b]0;pwned\u0007‮\n  ✔ fake line";
    const hc = await fakeHc([
      claudeIn("t7", { labels: { ...labelled, where } }),
      term("t8", { labels: { "claude.session": OTHER }, fg: { pid: 9999, name: where } }), // a program name
    ]);
    const r = resume(["--dry-run"], hc);
    assert.match(r.stdout, /t8 .*is running there/, "the fixture didn't reach the program-name message");
    assert.doesNotMatch(r.stdout, /\u001b\]0;pwned/);
    assert.doesNotMatch(r.stdout, /‮/);
    assert.doesNotMatch(r.stdout, /^\s+✔ fake line/m);
  });

  test("without hc it says so and exits 1", () => {
    const r = spawnSync(process.execPath, [KEEL, "resume"], { encoding: "utf-8", env: { ...process.env, PATH: "/nonexistent" } });
    assert.equal(r.status, 1);
    assert.match(r.stdout, /hc/);
  });
});

function doctor(hc, env = {}) {
  return spawnSync(process.execPath, [KEEL, "doctor"], { encoding: "utf-8", env: { ...process.env, ...hc.env, ...env } });
}

describe("doctor's herdr check", () => {
  test("warns about a Claude pane with no usable label, and names it", async () => {
    const hc = await fakeHc([claudeIn("t1", { labels: { where: "proj / 1" } }), claudeIn("t2", { labels: labelled })]);
    const out = doctor(hc).stdout;
    assert.match(out, /1 of 2 Claude pane\(s\) in herdr-core carry no usable session label/);
    assert.match(out, /t1 proj \/ 1/);
  });

  test("counts a pane whose root program is Claude, as herdr-app launches them", async () => {
    const hc = await fakeHc([term("t3", { root: "claude", app: "claude-code" })]);
    assert.match(doctor(hc).stdout, /1 of 1 Claude pane/);
  });

  test("a malformed label doesn't count as labelled", async () => {
    for (const bad of [{ "claude.session": "x; rm -rf ~" }, { "claude.session": SESSION, "claude.cwd": "/it's" }]) {
      const hc = await fakeHc([claudeIn("t1", { labels: bad })]);
      assert.match(doctor(hc).stdout, /1 of 1 Claude pane/, JSON.stringify(bad));
    }
  });

  test("is quiet about shells and labelled panes, even with a stale agent status", async () => {
    const hc = await fakeHc([
      claudeIn("t1", { labels: labelled }),
      term("t2", { app: "claude-code" }), // the root shell, stale app
      term("t3", { app: "claude-code", fg: { pid: 9999, name: "bash" } }), // a nested shell, stale app
      term("t4", { fg: { pid: 9999, name: "vim" } }), // another program, no agent reported
    ]);
    assert.match(doctor(hc).stdout, /herdr-core panes .*1 Claude session\(s\), each labelled/);
  });

  test("KEEL_HERDR_OFF=1 says it's off and asks hc nothing", async () => {
    const hc = await fakeHc([claudeIn("t1")]);
    const out = doctor(hc, { KEEL_HERDR_OFF: "1" }).stdout;
    assert.match(out, /herdr session labels off/);
    assert.equal(hc.calls().length, 0);
  });

  test("without a listening core it asks hc nothing — any hc command would start one", { skip: !PROC && "no /proc" }, async () => {
    const hc = await fakeHc([claudeIn("t1")], { core: false });
    doctor(hc);
    assert.equal(hc.calls().length, 0, "no socket at all");
    // A crashed core's socket file, and an $HC_TERMINAL_ID that outlived it.
    mkdirSync(join(hc.runtime, "herdr-core"));
    writeFileSync(join(hc.runtime, "herdr-core", "default.sock"), "");
    doctor(hc, { HC_TERMINAL_ID: "t9" });
    assert.equal(hc.calls().length, 0, "a stale socket file and an inherited terminal id");
  });

  test("names a terminal it couldn't describe instead of skipping it quietly", async () => {
    const hc = await fakeHc([claudeIn("t1", { labels: labelled }), term("t2", { failGet: true })]);
    assert.match(doctor(hc).stdout, /couldn't describe t2/);
  });

  test("finds the core at $HC_SOCKET, or at the pane's $HC_TERMINAL_SOCKET", { skip: !PROC && "no /proc" }, async () => {
    for (const key of ["HC_SOCKET", "HC_TERMINAL_SOCKET"]) {
      const hc = await fakeHc([claudeIn("t1")], { core: false });
      const sock = await listen(join(hc.runtime, "elsewhere.sock"));
      doctor(hc, { [key]: sock });
      assert.ok(hc.calls().length > 0, key);
    }
  });

  test("with no socket path known it trusts $HC_TERMINAL_ID", async () => {
    const hc = await fakeHc([claudeIn("t1")]);
    doctor(hc, { XDG_RUNTIME_DIR: "" });
    assert.equal(hc.calls().length, 0, "outside a pane");
    doctor(hc, { XDG_RUNTIME_DIR: "", HC_TERMINAL_ID: "t9" });
    assert.ok(hc.calls().length > 0, "inside a pane");
  });

  test("without ps it reports once that labels can't work, instead of warning about every pane", async () => {
    const hc = await fakeHc([claudeIn("t1")]);
    // Only the fake bin dir on PATH: hc and claude, no ps.
    const out = doctor(hc, { PATH: hc.dir }).stdout;
    assert.match(out, /herdr session labels can't work here/);
    assert.doesNotMatch(out, /carry no usable session label/);
  });
});
