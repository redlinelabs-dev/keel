/**
 * hc-core.mjs — what the herdr-session hook and bin/keel share about
 * herdr-core. Not a hook itself (hooks.json doesn't run it); it lives in
 * hooks/ so the hook loads nothing from outside hooks/, and the checks that
 * scan hooks/*.mjs (offline, surfaces, env keys) read it too.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Label values `keel resume` will type into a shell. The hook stores only
 * values that pass, and resume re-checks them, because anything that can run
 * `hc label` can write a label.
 *
 * An allowlist, not escaping: Unicode letters, combining marks and digits,
 * and `. _ / space + @ , : = ~ ( ) -`. None of those means anything inside
 * single quotes in sh-family shells, fish, nu or PowerShell, and a UTF-8
 * sequence never contains a quote byte, so there is no quoting scheme to get
 * wrong. The first version escaped instead, and a cold review beat it twice:
 * fish reads `\'` inside single quotes as an escape, and a DEL in a pasted
 * line is a backspace outside bracketed paste. Letters include lookalikes
 * (U+02BC looks like a quote), so a printed plan can look stranger than it
 * is; what runs is still a `cd` to one quoted, literal path.
 */
export const RESUME_SESSION = /^[A-Za-z0-9][A-Za-z0-9-]{7,63}$/;
export const RESUME_CWD = /^\/[\p{L}\p{M}\p{N}._\/ +@,:=~()-]*$/u;

/**
 * Where keel looks for the core's socket: $HC_SOCKET (hc's override), else
 * $HC_TERMINAL_SOCKET (set in every hc pane to its own core's socket), else
 * hc's Linux default under $XDG_RUNTIME_DIR. Null when none says.
 */
function coreSocket(env) {
  if (env.HC_SOCKET) return env.HC_SOCKET;
  if (env.HC_TERMINAL_SOCKET) return env.HC_TERMINAL_SOCKET;
  return env.XDG_RUNTIME_DIR ? join(env.XDG_RUNTIME_DIR, "herdr-core", `${env.HC_SESSION || "default"}.sock`) : null;
}

/**
 * Whether a herdr-core is running, without starting one.
 *
 * Every `hc` command, `hc server status` included, starts a core when none is
 * running (seen 2026-11-24), so asking hc is not a way to find out. Nor is the
 * socket file: a core killed with SIGKILL leaves it behind. /proc/net/unix
 * lists the sockets something is listening on, and the dead core's path was
 * gone from it (same day). Nor is $HC_TERMINAL_ID alone: tmux, an editor or a
 * nohup'd job started from an hc pane keeps it after the core is gone.
 *
 * Where there's no /proc (macOS) or no known socket path (none of the three
 * variables above set), this can't tell, and falls back to trusting
 * $HC_TERMINAL_ID. A socket moved by hc's config file isn't read: outside a
 * pane, doctor then finds no core and stays quiet, the direction that starts
 * nothing.
 */
export function coreRunning(env = process.env) {
  const sock = coreSocket(env);
  let table = null;
  try {
    table = readFileSync("/proc/net/unix", "utf-8");
  } catch { /* not Linux */ }
  if (!sock || table === null) return Boolean(env.HC_TERMINAL_ID);
  return table.split("\n").some((line) => line.endsWith(` ${sock}`));
}
