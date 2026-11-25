#!/usr/bin/env node
/**
 * herdr-session.mjs — label a herdr-core terminal with the Claude session in it.
 *
 * THE PROBLEM THIS SOLVES
 * herdr-core (`hc`) keeps terminals alive while its machine is up. When the
 * core loses them — a reboot, a crash, and every Windows restart for a core
 * running in WSL2 — each kept terminal (herdr-app keeps the ones in its panes)
 * comes back as a shell, and its program is never run again (herdr-app's own
 * guide says so). The Claude conversation is still on disk, but nothing
 * records which one was in which pane, and `claude -r` offers every session
 * from that folder: with several panes started in ~, picking the right one
 * became guesswork.
 *
 * WHAT IT DOES
 * Only inside an hc terminal ($HC_TERMINAL_ID set). On SessionStart it sets
 * two terminal labels through `hc label`:
 *   claude.session  the documented hook field `session_id`
 *   claude.cwd      the documented hook field `cwd`
 * herdr-core holds labels with the terminal. On 2026-11-24 an isolated core
 * was stopped and started with a labelled, kept terminal in it: the program
 * died, the terminal came back as a fresh shell, and the labels were intact.
 *
 * On SessionEnd with reason `prompt_input_exit` or `logout` — someone ended the
 * session on purpose — it removes them, so `keel resume` doesn't bring back a
 * conversation that was closed. A lost core gives Claude no chance to end
 * with those reasons. `/clear` ends one session and starts another; the start
 * overwrites the label.
 *
 * WHICH CLAUDE GETS THE LABEL
 * A tool can run a nested `claude -p` inside the same terminal, and it inherits
 * $HC_TERMINAL_ID. Its SessionStart would overwrite the label with a headless
 * session nobody wants back. So the hook writes only when the Claude that ran
 * it is the terminal's foreground program, as `hc get` reports it: the nearest
 * ancestor of this process that isn't a shell must be that pid. That relies on
 * how Claude Code spawns hook commands (as its descendants, through a shell),
 * which is observed, not documented — docs/DOCUMENTED-SURFACES.md lists it.
 * Known gaps: a `claude -p` typed at the shell prompt IS the foreground
 * program, so it labels the pane; and a version-manager shim that runs node as
 * a child, rather than exec'ing it, sits between this hook and Claude, so no
 * label is written (refusing is the safe direction).
 *
 * WHAT GETS STORED
 * `keel resume` later types these values into a shell, so only values that
 * need no escaping inside single quotes are stored: an id of letters, digits
 * and dashes, and an absolute path of Unicode letters, marks and digits and
 * `. _ / space + @ , : = ~ ( ) -`. A folder outside that set is not labelled.
 * The rules live in hc-core.mjs, which `keel resume` checks with too.
 *
 * A NO-OP WITHOUT A CORE
 * Any `hc` command starts a core when none is running, and $HC_TERMINAL_ID
 * outlives the core in tmux or a job started from a pane. So before calling
 * hc at all the hook checks that a core is listening on the pane's socket
 * ($HC_TERMINAL_SOCKET, which hc sets in every pane), via /proc/net/unix
 * (coreRunning, in hc-core.mjs). Without /proc (macOS) or a socket path it
 * can't tell, and trusts $HC_TERMINAL_ID.
 *
 * Nothing is transmitted; `hc` talks to the local core. Like every keel hook it
 * fails silent, and gives up within a few seconds on a slow core. `keel doctor`
 * lists the Claude panes herdr-core reports that carry no usable label, which
 * is how a broken or removed hook gets noticed. KEEL_HERDR_OFF=1 disables it.
 */

import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { RESUME_SESSION, RESUME_CWD, coreRunning } from "./hc-core.mjs";

function done() {
  process.stdout.write(JSON.stringify({ continue: true }));
  process.exit(0);
}

if (process.env.KEEL_HERDR_OFF === "1") done();
const terminal = process.env.HC_TERMINAL_ID?.trim();
if (!terminal || !coreRunning()) done();

let input;
try {
  input = JSON.parse(readFileSync(0, "utf-8"));
} catch {
  done();
}

const event = String(input?.hook_event_name ?? "");
const session = String(input?.session_id ?? "");
const cwd = String(input?.cwd ?? "");

const SHELLS = new Set(["sh", "bash", "dash", "zsh", "fish", "ksh", "mksh", "ash", "busybox", "nu"]);

function run(cmd, args, timeout) {
  return execFileSync(cmd, args, { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"], timeout });
}

/** The pid of the nearest ancestor that isn't a shell: the program that ran this hook. */
function spawner() {
  let pid = process.ppid;
  for (let hops = 0; hops < 4 && pid > 1; hops++) {
    const [ppid, ...comm] = run("ps", ["-o", "ppid=,comm=", "-p", String(pid)], 1500).trim().split(/\s+/);
    const name = comm.join(" ").split("/").pop().replace(/^-/, "");
    if (!SHELLS.has(name)) return pid;
    pid = Number(ppid);
  }
  return null;
}

function isForeground() {
  const fg = JSON.parse(run("hc", ["get", terminal, "--json"], 2000))?.foreground?.pid;
  return Number.isInteger(fg) && fg === spawner();
}

try {
  if (event === "SessionStart") {
    if (RESUME_SESSION.test(session) && RESUME_CWD.test(cwd) && isForeground()) {
      run("hc", ["label", terminal, `claude.session=${session}`, `claude.cwd=${cwd}`], 2000);
    }
  } else if (event === "SessionEnd") {
    const reason = String(input?.reason ?? "");
    if ((reason === "prompt_input_exit" || reason === "logout") && isForeground()) {
      run("hc", ["label", terminal, "claude.session=", "claude.cwd="], 2000);
    }
  }
} catch {
  /* no hc, no ps, a slow core: the session goes on without a label */
}

done();
