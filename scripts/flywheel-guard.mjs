#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { FENCE_GLOBS } from "./flywheel-fence.mjs";

const TERMINAL = new Set(["closed", "done", "completed", "cancelled", "canceled", "tombstone"]);
const ZERO_SHA = /^0+$/;
const RED = new Set(["failure", "error", "cancelled", "timed_out", "action_required", "stale", "startup_failure"]);
// Completed conclusions that decide nothing (an `if:` that was false, a needed job that failed):
// they never outrank a real conclusion, and a name with only them is undecided (#21 review, NB1).
const UNDECIDED = new Set(["skipped", "neutral"]);
const UNAUTHENTICATED_HTTP = new Set([401, 403, 404]);
// A trailer line as git defines it: token, colon, value; continuation lines start with
// whitespace. git strips comment lines and the `commit -v` scissors cut AFTER commit-msg
// runs, so the hook reads through the former and never writes below the latter.
const TRAILER_LINE = /^([A-Za-z0-9-]+):[ \t]*(.*)$/;
const COMMENT_LINE = /^#/;
const SCISSORS = /^# -+ >8 -+$/;

function fail(message) {
  console.error(`flywheel-guard: BLOCKED: ${message}`);
  return 1;
}

function warn(message) {
  console.error(`flywheel-guard: ${message}`);
}

function git(cwd, args, options = {}) {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    input: options.input,
    timeout: options.timeout,
    env: { ...process.env, ...(options.env || {}) },
  });
  if (result.status !== 0 && !options.allowFailure) {
    throw new Error((result.stderr || result.stdout || `git ${args.join(" ")} failed`).trim());
  }
  return result;
}

function repository() {
  const probe = git(process.cwd(), ["rev-parse", "--show-toplevel"], { allowFailure: true });
  if (probe.status !== 0) return null;
  const root = fs.realpathSync(probe.stdout.trim());
  const gitDirRaw = git(root, ["rev-parse", "--git-dir"]).stdout.trim();
  const gitDir = path.resolve(root, gitDirRaw);
  try {
    fs.accessSync(gitDir, fs.constants.R_OK | fs.constants.W_OK);
  } catch {
    return { root, gitDir, writable: false };
  }
  return { root, gitDir, writable: true };
}

function loadConfig(root) {
  const file = process.env.FLYWHEEL_GUARD_CONFIG || path.join(root, "flywheel.guard.json");
  return { file, value: JSON.parse(fs.readFileSync(file, "utf8")) };
}

function normalized(value) {
  let resolved = path.resolve(value);
  try { resolved = fs.realpathSync(resolved); } catch {}
  resolved = resolved.replaceAll("\\", "/").replace(/\/$/, "");
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

// Identity classes. `lane:<slug>` is an orchestrator-dispatched lane — not a worker clone,
// not the owner. Human semantics on the pull-request route; on the direct route (a push that
// lands on main) it is held to the worker contract and fails closed (pre-push, below).
function identity(raw = process.env.FLYWHEEL_AGENT_ID || "") {
  const match = /^(worker|human):([^\s:][^\r\n]*)$|^(lane):([A-Za-z0-9][A-Za-z0-9._-]*)$/.exec(raw.trim());
  return match ? { class: match[1] || match[3], name: (match[2] || match[4]).trim(), raw: raw.trim() } : null;
}

// The fail-closed classes: a worker, or a lane that pre-push found landing commits on main.
const strict = (who) => who?.class === "worker" || who?.strict === true;

function cloneIdentity(config, root, who) {
  const clone = (config.workerClones || []).find((entry) => normalized(entry.path) === normalized(root));
  if (clone && (!who || who.class !== "worker" || who.name !== clone.alias)) {
    throw new Error(`registered worker clone ${clone.path} requires FLYWHEEL_AGENT_ID=worker:${clone.alias}`);
  }
  if (who?.class === "worker" && !clone) {
    throw new Error(`worker:${who.name} is not anchored to this clone path`);
  }
  return clone || null;
}

function stagedPaths(root) {
  const out = git(root, ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"]).stdout;
  return out.split("\0").filter(Boolean).map((item) => item.replaceAll("\\", "/"));
}

function parseRpcText(text) {
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) return JSON.parse(trimmed);
  const data = trimmed.split(/\r?\n/).filter((line) => line.startsWith("data:"));
  if (!data.length) throw new Error("Agent Mail returned neither JSON nor an MCP event stream");
  return JSON.parse(data.at(-1).slice(5).trim());
}

function unwrapRpc(rpc) {
  if (rpc.error) throw new Error(rpc.error.message || JSON.stringify(rpc.error));
  const result = rpc.result;
  if (result?.isError) {
    throw new Error(result.content?.map((part) => part.text).filter(Boolean).join(" ") || "Agent Mail tool error");
  }
  if (result?.structuredContent) return result.structuredContent;
  const text = result?.content?.find((part) => typeof part.text === "string")?.text;
  if (text) {
    try { return JSON.parse(text); } catch { return text; }
  }
  const resourceText = result?.contents?.find((part) => typeof part.text === "string")?.text;
  if (resourceText) {
    try { return JSON.parse(resourceText); } catch { return resourceText; }
  }
  return result;
}

// Resolve lazily once per hook process, including absence; never log credential contents.
let mailAuth;
async function mcpRequest(config, method, params) {
  if (!mailAuth) {
    const file = process.env.FLYWHEEL_AGENT_MAIL_TOKEN_FILE || "/home/kevin/.config/flywheel/agent-mail-token";
    let value = process.env.FLYWHEEL_AGENT_MAIL_TOKEN?.trim() || undefined;
    try { value ??= fs.readFileSync(file, "utf8"); } catch { value = ""; }
    mailAuth = { file, token: value.trim() };
  }
  const { file, token } = mailAuth;
  const attempts = 2;
  let last;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.mailTimeoutMs || 650);
    try {
      const response = await fetch(config.agentMailUrl || "http://127.0.0.1:8765/mcp/", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "mcp-protocol-version": "2025-06-18",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: `${process.pid}-${attempt}`, method, params }),
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`Agent Mail HTTP ${response.status}${[401, 403].includes(response.status) ? `: authentication rejected; check FLYWHEEL_AGENT_MAIL_TOKEN or token file ${file} (FLYWHEEL_AGENT_MAIL_TOKEN_FILE)` : ""}`);
      return unwrapRpc(parseRpcText(await response.text()));
    } catch (error) {
      last = error;
      if (/^Agent Mail HTTP (401|403):/.test(error.message)) break;
    } finally {
      clearTimeout(timer);
    }
  }
  const reason = last?.name === "AbortError" ? "Agent Mail timeout" : (last?.message || "Agent Mail unavailable");
  // Like GitHub redaction, cover echoed RPC/parser/transport errors, even for short tokens.
  throw new Error(token ? reason.replaceAll(token, "[redacted]") : reason);
}

async function callTool(config, name, arguments_) {
  return mcpRequest(config, "tools/call", { name, arguments: arguments_ });
}

function globRegex(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replaceAll("**", "\0").replaceAll("*", "[^/]*").replaceAll("\0", ".*").replaceAll("?", "[^/]");
  return new RegExp(`^${escaped}$`);
}

function overlaps(pathname, pattern) {
  try { return globRegex(pattern).test(pathname) || globRegex(pathname).test(pattern); } catch { return pathname === pattern; }
}

function resourceRows(value) {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.reservations)) return value.reservations;
  if (Array.isArray(value?.file_reservations)) return value.file_reservations;
  return [];
}

async function reservationCheck(config, clone, paths) {
  if (!paths.length) return { conflicts: [], expired: [] };
  const agentName = clone?.mailAgent || config.observerAgent;
  if (!agentName) throw new Error("no registered Agent Mail observer for this identity");
  if (!config.agentMailProjectKey) throw new Error("Agent Mail project key is not configured");
  const checked = await callTool(config, "check_file_reservation_conflicts", {
    project_key: config.agentMailProjectKey,
    agent_name: agentName,
    paths,
  });
  let rows = [];
  try {
    const uri = `resource://file_reservations/${encodeURIComponent(config.agentMailProjectKey)}?active_only=false`;
    rows = resourceRows(await mcpRequest(config, "resources/read", { uri }));
  } catch (error) {
    warn(`reservation metadata enrichment unavailable: ${error.message}`);
  }
  const now = Date.now();
  const expired = rows.filter((row) => !row.released_ts && Date.parse(row.expires_ts) <= now && paths.some((p) => overlaps(p, row.path_pattern)));
  const conflicts = (checked.conflicts || []).map((conflict) => ({
    path: conflict.path,
    holders: (conflict.holders || []).map((holder) => {
      const row = rows.find((candidate) => candidate.agent === holder.agent && candidate.path_pattern === holder.path_pattern);
      return { ...holder, thread: row?.reason || "unrecorded" };
    }),
  }));
  return { conflicts, expired };
}

function reportReservations(result) {
  for (const row of result.expired) warn(`expired reservation ignored: ${row.path_pattern} held by ${row.agent}`);
  for (const conflict of result.conflicts) {
    for (const holder of conflict.holders) {
      warn(`conflict: ${conflict.path} held by ${holder.agent} (thread ${holder.thread})`);
    }
  }
}

function appendAudit(gitDir, event) {
  fs.appendFileSync(path.join(gitDir, "flywheel-guard-audit.jsonl"), `${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`, { mode: 0o600 });
}

// Audit rows are evidence, not gates. Every fail-open path writes one, and a write failure
// on top of an already-degraded path must never be the thing that blocks a human. Returns
// whether the row landed, so a caller that REQUIRES durable evidence can fail closed.
function recordAudit(gitDir, event, label) {
  try { appendAudit(gitDir, event); return true; }
  catch (error) {
    warn(`WARNING: could not record the ${label} audit row: ${error.message}`);
    return false;
  }
}

async function allowBypass(config, repo, who, phase) {
  const reason = process.env.FLYWHEEL_GUARD_BYPASS?.trim();
  if (!reason) return { bypassed: false };
  const recorded = recordAudit(repo.gitDir, { kind: "bypass", phase, identity: who?.raw || "unset", reason }, "bypass");
  // A worker bypass that leaves no durable evidence is not a bypass, it is an unlogged
  // override — §5 requires the row. Human class keeps the fail-open contract: the warning
  // is the evidence, and a human is answerable for it.
  if (!recorded && who?.class === "worker") {
    return { bypassed: false, blocked: `bypass refused: the audit row could not be written, and a worker bypass must leave durable evidence` };
  }
  const audit = config.audit || {};
  if (audit.sender && audit.recipient) {
    try {
      await callTool(config, "send_message", {
        project_key: config.agentMailProjectKey,
        sender_name: audit.sender,
        to: [audit.recipient],
        subject: `[flywheel-guard] bypass ${phase}`,
        body_md: `Identity: ${who?.raw || "unset"}\nReason: ${reason}`,
        thread_id: "flywheel-guard-bypass",
      });
    } catch (error) { warn(`bypass allowed; Mail audit failed: ${error.message}`); }
  } else warn("bypass allowed; Mail audit identities are not configured");
  return { bypassed: true };
}

function paragraphTrailers(lines) {
  const entries = [];
  for (const line of lines) {
    const match = TRAILER_LINE.exec(line);
    if (match) entries.push({ key: match[1], value: match[2].trim() });
    else if (/^[ \t]+\S/.test(line) && entries.length) entries.at(-1).value += ` ${line.trim()}`;
    else return null;
  }
  return entries;
}

// The trailer block, parsed as git does rather than by scanning every line: the trailing
// paragraph(s) made ONLY of `Key: value` lines, comment lines ignored, never the subject — a
// prose line that starts with a key is prose (canary d8d8fd4 lost its identity trailer to the
// old any-line scan). Every trailing trailer-only paragraph counts, review-sweep's rule, so
// both tools read one message alike: pre-fix worker commits carry `Bead:` and
// `Flywheel-Identity:` as separate paragraphs. `head` and `block` are the raw lines, `tail` the scissors cut.
function splitTrailers(message) {
  const all = message.replace(/\r\n?/g, "\n").replace(/\s+$/, "").split("\n");
  const cut = all.findIndex((line) => SCISSORS.test(line));
  const lines = cut < 0 ? all : all.slice(0, cut);
  let start = lines.length;
  let trailers = [];
  for (let end = lines.length; end > 0;) {
    let from = end;
    while (from > 0 && lines[from - 1].trim()) from -= 1;
    const entries = paragraphTrailers(lines.slice(from, end).filter((line) => !COMMENT_LINE.test(line)));
    if (!entries || from === 0) break;
    trailers = [...entries, ...trailers];
    start = from;
    for (end = from; end > 0 && !lines[end - 1].trim();) end -= 1;
  }
  return { head: lines.slice(0, start), block: lines.slice(start), trailers, tail: cut < 0 ? [] : all.slice(cut) };
}

const trailerBlock = (message) => splitTrailers(message).trailers;

// `Bead: none`, optionally `none (<reason>)`: an explicit no-bead declaration. Human and lane
// class may write it; a worker commit, or a lane's commit landing on main, still requires a
// resolvable id. `none` is never looked up, by this tool or by review-sweep.
const NO_BEAD = /^none(?:\s*\(.*\))?$/i;

function appendTrailer(file, key, value) {
  const { head, block, trailers, tail } = splitTrailers(fs.readFileSync(file, "utf8"));
  // Never the same trailer twice (the drill commits carried `Bead:` twice); one paragraph, so
  // git's last-paragraph parser sees every trailer; RAW lines, never re-serialised, the new one
  // above trailing `#` lines: a bare URL parses as a `https:` trailer and must not become `https: //`.
  const seen = new Set();
  const keep = trailers.map((entry) => { const id = `${entry.key.toLowerCase()}\n${entry.value}`; return !seen.has(id) && seen.add(id); });
  let index = -1;
  const lines = block.filter((line) => {
    if (TRAILER_LINE.test(line)) index += 1;
    return line.trim() && (COMMENT_LINE.test(line) || keep[index] !== false);
  });
  if (!trailers.some((entry) => entry.key.toLowerCase() === key.toLowerCase())) {
    lines.splice(lines.findLastIndex((line) => !COMMENT_LINE.test(line)) + 1, 0, `${key}: ${String(value).replace(/[\r\n]+/g, " ").slice(0, 180)}`);
  }
  const top = head.join("\n").replace(/\s+$/, "");
  fs.writeFileSync(file, `${top ? `${top}\n\n` : ""}${[...lines, ...tail].join("\n")}\n`, "utf8");
}

function requireNativeBr(binary) {
  if (process.platform !== "linux") throw new Error("worker bead validation requires WSL/Linux");
  const magic = fs.readFileSync(binary).subarray(0, 4);
  if (!magic.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) throw new Error(`refusing non-ELF br binary: ${binary}`);
}

function beadRecord(value) {
  if (Array.isArray(value)) return value[0];
  return value?.issue || value;
}

function validateBead(config, root, alias, message, runner = spawnSync, klass = "worker") {
  // Read from the trailer block, never from any line: a prose-quoted id must not reach br.
  const beads = trailerBlock(message).filter((entry) => entry.key.toLowerCase() === "bead");
  const id = beads.find((entry) => /^\S+$/.test(entry.value) && !NO_BEAD.test(entry.value))?.value;
  if (!id) throw new Error(`${klass} commits require a Bead: <id> trailer${beads.some((entry) => NO_BEAD.test(entry.value)) ? "; `Bead: none` declares no bead and is not an id" : ""}`);
  const binary = config.br?.binary;
  const database = config.br?.database;
  if (!binary || !database) throw new Error("native br binary/database is not configured");
  let databaseStat;
  try { databaseStat = fs.statSync(database); }
  catch { throw new Error(`shared Beads database is missing: ${database}`); }
  if (!databaseStat.isFile()) throw new Error(`shared Beads database is not a regular file: ${database}`);
  requireNativeBr(binary);
  const result = runner(binary, [
    "--db", database,
    "--no-auto-import",
    "--no-auto-flush",
    "--lock-timeout", "5000",
    "--actor", alias,
    "show", id, "--json",
  ], {
    cwd: root,
    encoding: "utf8",
    env: process.env,
  });
  if (result.status !== 0) throw new Error(`Bead ${id} does not exist in the shared database`);
  const record = beadRecord(JSON.parse(result.stdout));
  const status = String(record?.status || record?.state || "").toLowerCase();
  if (TERMINAL.has(status)) throw new Error(`Bead ${id} is terminal (${status})`);
  const assignee = String(record?.assignee || record?.owner || "");
  if (![alias, `${klass}:${alias}`].includes(assignee)) throw new Error(`Bead ${id} is assigned to ${assignee || "nobody"}, not ${alias}`);
  return id;
}

function outgoing(stdin, root) {
  const updates = stdin.trim().split(/\r?\n/).filter(Boolean).map((line) => line.split(/\s+/));
  const paths = new Set();
  for (const [, localSha, , remoteSha] of updates) {
    if (!localSha || ZERO_SHA.test(localSha)) continue;
    const args = remoteSha && !ZERO_SHA.test(remoteSha)
      ? ["diff", "--name-only", "-z", `${remoteSha}..${localSha}`]
      : ["diff-tree", "--no-commit-id", "--name-only", "-r", "-z", localSha];
    for (const item of git(root, args).stdout.split("\0").filter(Boolean)) paths.add(item.replaceAll("\\", "/"));
  }
  return [...paths];
}

// The commits an update to `refs/heads/main` would land: the direct route, as pre-push sees it.
function mainCommits(stdin, root) {
  const shas = [];
  for (const [, localSha, remoteRef, remoteSha] of stdin.trim().split(/\r?\n/).filter(Boolean).map((line) => line.split(/\s+/))) {
    if (remoteRef !== "refs/heads/main" || !localSha || ZERO_SHA.test(localSha)) continue;
    const range = remoteSha && !ZERO_SHA.test(remoteSha) ? `${remoteSha}..${localSha}` : localSha;
    shas.push(...git(root, ["rev-list", range]).stdout.split(/\s+/).filter(Boolean));
  }
  return shas;
}

// The ref updates in a pre-push stdin, as tuples, WITHOUT mainCommits' rev-list: the janitor
// exception has to count the refs the push touches, not the commits one of them lands.
// `mainCommits` (above) is exported and used by the lane direct-route check; it stays as it is.
function mainRefUpdates(stdin) {
  return stdin.trim().split(/\r?\n/).filter(Boolean)
    .map((line) => line.split(/\s+/))
    .filter(([, localSha]) => localSha && !ZERO_SHA.test(localSha));
}

// The AGENTS.md §9 critical-path fence lives in `scripts/flywheel-fence.mjs`, imported
// statically at the top of this file and re-exported below: a constant in code, never a key
// read from flywheel.guard.json, because an exception that admits a push onto a RED main must
// not depend on a key a clone could soften. It was split out of this file so a growing fence
// cannot buy headroom out of the guard's 1010-line ceiling (RULING-fence-globs.md revision 5).
// Condition 6 refuses to revert a commit that touched one of these — `git revert` is a fence
// edit that neither the Claude edit fence nor DCG watches, because they gate edits and
// commands, not replayed inverses.

const JANITOR_MARKER = "janitor-revert-of";
const SHA40 = /^[0-9a-f]{40}$/i;

// The janitor exception: the ONE push a strict class may land on a red `main` — the exact
// inverse of the very commit GitHub judged red, carried by a resolvable bead that names it.
// Everything is derived from the pushed ref as pre-push stdin reports it, and from `ci.sha`.
// `HEAD` and the local `origin/main` tracking ref appear nowhere below: `git push origin
// <other-sha>:refs/heads/main` leaves HEAD a genuine exact inverse while pushing something
// else, so a HEAD-derived predicate admits an arbitrary tree. Every git read uses
// `allowFailure`; any failure of any condition returns `{ok:false}` and the caller falls
// through to `redMainGate` exactly as today.
//
// Evaluation order is 1-4, 6, 7, 8, then 5: conditions 5's `br` reads run only once the push
// is already known to be a single-commit exact inverse onto the judged head. All eight must
// hold, so the order changes no verdict — only how many subprocesses a doomed push spends.
function janitorException(config, repo, stdin, ci, who, runner = spawnSync) {
  const root = repo.root;
  let attempted = false;
  const refuse = (reason) => ({ ok: false, reason, attempted });
  const rev = (spec) => {
    const result = git(root, ["rev-parse", "--verify", spec], { allowFailure: true });
    return result.status === 0 ? result.stdout.trim() : "";
  };
  const message = (sha) => {
    const result = git(root, ["log", "-1", "--format=%B", sha], { allowFailure: true });
    return result.status === 0 ? result.stdout : null;
  };
  const trailerValues = (trailers, key) => trailers.filter((entry) => entry.key.toLowerCase() === key).map((entry) => entry.value.trim());

  // 1. Exactly one ref update, and it is refs/heads/main. A push that also updates another
  //    ref is refused: the exception reasons about one ref and must not authorise a second.
  const updates = mainRefUpdates(stdin);
  if (updates.length !== 1) return refuse(`the push updates ${updates.length} refs; a janitor revert pushes refs/heads/main alone`);
  const [, localSha, remoteRef, remoteSha] = updates[0];
  if (remoteRef !== "refs/heads/main") return refuse(`the push updates ${remoteRef}, not refs/heads/main`);
  if (!SHA40.test(localSha)) return refuse("the pushed sha is not a 40-hex object name");

  const pushedMessage = message(localSha);
  if (pushedMessage === null) return refuse(`the pushed commit ${localSha.slice(0, 12)} is unreadable`);
  const pushedTrailers = trailerBlock(pushedMessage);
  const markers = trailerValues(pushedTrailers, JANITOR_MARKER);
  // From here on a refusal is worth reporting: the push is trying to be a janitor revert.
  attempted = markers.length > 0;

  // 2. Fast-forward from the live red head: the remote side of the update is the very sha
  //    `githubMainStatus` judged. This is what makes "the red head" and "what git is pushing
  //    onto" the same object. A create of refs/heads/main is refused.
  if (!remoteSha || ZERO_SHA.test(remoteSha)) return refuse("the push creates refs/heads/main rather than fast-forwarding the red head");
  if (!SHA40.test(remoteSha) || !SHA40.test(String(ci.sha || ""))) return refuse("the pushed-onto sha or the judged head is not a 40-hex object name");
  if (remoteSha !== ci.sha) return refuse(`the push lands on ${remoteSha.slice(0, 12)}, not the judged red head ${ci.sha.slice(0, 12)}`);

  // 3. Exactly one commit, it is the pushed sha, and its single parent is the red head.
  //    One-commit alone would still admit a merge whose second parent is already upstream.
  const landing = mainCommits(stdin, root);
  if (landing.length !== 1 || landing[0] !== localSha) return refuse(`the push lands ${landing.length} commits on main; a janitor revert lands exactly one`);
  const parentLine = git(root, ["rev-list", "--parents", "-n", "1", localSha], { allowFailure: true });
  if (parentLine.status !== 0) return refuse(`the parents of ${localSha.slice(0, 12)} are unreadable`);
  const parents = parentLine.stdout.trim().split(/\s+/).filter(Boolean).slice(1);
  if (parents.length !== 1) return refuse(`the pushed commit has ${parents.length} parents; a janitor revert has exactly one`);
  if (parents[0] !== ci.sha) return refuse("the pushed commit's parent is not the red head");

  // 4. Exact inverse by TREE EQUALITY, never `git patch-id`: patch-id hashes the diff after
  //    whitespace normalisation, and `git diff` renders any changed binary as the constant
  //    "Binary files a/x and b/x differ", so a "revert" that re-indents a file or swaps a
  //    different blob passes patch-id equality. Given conditions 2 and 3 this is necessary
  //    AND sufficient, and it needs no `-m 1` case: `git revert -m 1 <merge>` produces
  //    exactly the first parent's tree, which is what `^1` names. A root `ci.sha` has no
  //    `^1` and is refused.
  const revertedParent = rev(`${ci.sha}^1`);
  if (!revertedParent) return refuse("the red head has no first parent (root commit); there is nothing to revert to");
  const pushedTree = rev(`${localSha}^{tree}`);
  const targetTree = rev(`${revertedParent}^{tree}`);
  if (!pushedTree || !targetTree) return refuse("the pushed or target tree is unreadable");
  if (pushedTree !== targetTree) return refuse("the pushed commit is not the exact inverse of the red head: its tree differs from the red head's parent");

  // 6. The reverted commit touches no fence path. Without this the design would mechanically
  //    authorise a worker to revert the guard itself on a red main. TWO-TREE form against
  //    condition 4's `revertedParent`, never one-argument `diff-tree <sha>`: the one-argument
  //    form prints NOTHING for a merge commit, so a merge red head — the shape condition 4
  //    deliberately admits via `^1` — would show an empty fence set and pass vacuously.
  const touched = git(root, ["diff-tree", "--no-commit-id", "--name-only", "-r", "-z", revertedParent, ci.sha], { allowFailure: true });
  if (touched.status !== 0) return refuse("the red head's changed paths are unreadable");
  const fenced = touched.stdout.split("\0").filter(Boolean).map((item) => item.replaceAll("\\", "/"))
    .filter((item) => FENCE_GLOBS.some((pattern) => { try { return globRegex(pattern).test(item); } catch { return item === pattern; } }));
  if (fenced.length) return refuse(`the red head touches critical-path ${fenced.join(", ")}; reverting a fenced path is a fenced change and takes the pull-request route`);

  // 7. The trailer, QUANTIFIED: at least one `Janitor-Revert-Of:` entry and EVERY entry with
  //    that key equal to `ci.sha`. Two markers naming different shas is a refusal, not a
  //    match on the first — the fail-closed reading is the only one that cannot be gamed by
  //    appending a second marker to a commit that reverts something else. `trailerBlock` is
  //    order-insensitive, so the marker need not sit directly above `Bead:`.
  if (!markers.length) return refuse("the pushed commit carries no Janitor-Revert-Of: trailer");
  if (!markers.every((value) => value.toLowerCase() === ci.sha.toLowerCase())) {
    return refuse("a Janitor-Revert-Of: trailer names a commit other than the red head; only the current red head is auto-revertible");
  }

  // 8. The reverted commit is not ITSELF a janitor revert. Reverting a revert re-lands a tree
  //    already judged to have broken main; if main is still red after a janitor revert the
  //    cause is not the reverted commit and the next action is a human's. This is the half an
  //    attacker cannot route around: with only the filer's refusal, a worker holding any
  //    marker-carrying bead could still push a revert of a revert by hand.
  const revertedMessage = message(ci.sha);
  if (revertedMessage === null) return refuse(`the red head ${ci.sha.slice(0, 12)} is unreadable`);
  const revertedTrailers = trailerBlock(revertedMessage);
  if (trailerValues(revertedTrailers, JANITOR_MARKER).length) {
    return refuse("the red head is itself a janitor revert; a revert of a revert re-lands a tree already judged broken");
  }

  // 5. A resolvable bead that binds this push to this red head. `validateBead` THROWS rather
  //    than returning false, and an uncaught throw would reach main().catch and block with a
  //    confusing reason instead of the red-main one, so it is wrapped. It returns only the id
  //    and never reads labels, hence the marker test below rather than a `janitor` label.
  let bead;
  try { bead = validateBead(config, root, who.name, pushedMessage, runner); }
  catch (error) { return refuse(error.message); }

  // 5b. Self-revert path first — the breaking agent inside its 30 minutes, whose commit the
  //     loop-run Step 3.4 recipe produces: same `Bead:` and same `Flywheel-Identity:` as the
  //     commit being reverted. No `br` read beyond `validateBead` on this path.
  const same = (key) => {
    const mine = trailerValues(pushedTrailers, key);
    const theirs = trailerValues(revertedTrailers, key);
    return mine.length === 1 && theirs.length === 1 && mine[0] === theirs[0];
  };
  if (same("bead") && same("flywheel-identity")) return { ok: true, bead, sha: localSha, revertsSha: ci.sha, path: "self-revert" };

  // 5a. Janitor path — one `br show` with the identical argv `validateBead` uses, unwrapped
  //     the same way, requiring the literal marker in the record's `description`. That is the
  //     field file-revert-bead.mjs writes the marker into and the field `findExisting` keys
  //     on, so this uses only fields proven to exist; `br`'s label field name in a
  //     `show --json` record is unverified, and the marker is the tighter test anyway because
  //     it binds bead to commit to red head.
  const binary = config.br?.binary;
  const database = config.br?.database;
  if (!binary || !database) return refuse("native br binary/database is not configured");
  const shown = runner(binary, [
    "--db", database,
    "--no-auto-import",
    "--no-auto-flush",
    "--lock-timeout", "5000",
    "--actor", who.name,
    "show", bead, "--json",
  ], { cwd: root, encoding: "utf8", env: process.env });
  if (shown.status !== 0) return refuse(`Bead ${bead} could not be read back for the janitor marker`);
  let record;
  try { record = beadRecord(JSON.parse(shown.stdout)); }
  catch { return refuse(`Bead ${bead} did not return a readable record`); }
  const description = String(record?.description || "");
  if (!description.includes(`Janitor-Revert-Of: ${ci.sha}`)) {
    return refuse(`Bead ${bead} does not carry Janitor-Revert-Of: ${ci.sha.slice(0, 12)} and the push is not a self-revert`);
  }
  return { ok: true, bead, sha: localSha, revertsSha: ci.sha, path: "janitor" };
}

function githubRepo(remote) {
  const match = /github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?$/.exec(remote.trim());
  return match ? { owner: match[1], repo: match[2] } : null;
}

async function boundedFetch(fetchImpl, url, options, timeoutMs) {
  const controller = new AbortController();
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error("GitHub API timeout"));
    }, timeoutMs);
  });
  try {
    return await Promise.race([fetchImpl(url, { ...options, signal: controller.signal }), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

function runRank(run) {
  return [Number(run.run_attempt) || 0, Date.parse(run.completed_at || run.started_at || "") || 0, Number(run.id) || 0];
}

function outranks(run, best) {
  const [current, incumbent] = [runRank(run), runRank(best)];
  for (let index = 0; index < current.length; index += 1) {
    if (current[index] !== incumbent[index]) return current[index] > incumbent[index];
  }
  return true;
}

// The latest COMPLETED run per check whose conclusion decides anything. A re-run in
// progress carries no conclusion, so letting it outrank its own predecessor would erase the
// verdict that predecessor already earned — the whole re-run window would read as if
// nothing had ever run. A skipped/neutral run is completed and equally verdict-less: it
// never outranks a success or a failure, however new it is.
//
// Keyed by workflow run, not by name alone: `build`/`test`/`lint` are ordinary job names
// and two workflows may each publish one. Collapsing them by name would let a passing
// `test` from one workflow supersede a failing `test` from another, so a real red would
// read green in legacy mode. Legacy fixtures retain their suite/app fallback.
function checkKey(run) {
  const suite = run.run_id ?? run.check_suite?.id ?? run.app?.id;
  const name = run.name || "unnamed check";
  return suite === undefined || suite === null ? name : `${suite}::${name}`;
}

function latestCompletedPerName(runs) {
  const byKey = new Map();
  for (const run of runs) {
    if (run.status !== "completed" || UNDECIDED.has(run.conclusion)) continue;
    const key = checkKey(run);
    const best = byKey.get(key);
    if (!best || outranks(run, best)) byKey.set(key, run);
  }
  return [...byKey.values()];
}

// A misconfigured key must not degrade to "unknown forever": a bare string is iterable.
function sentinelNames(value) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((name) => typeof name !== "string" || !name.trim())) {
    throw new Error("redMainCheckNames must be an array of non-empty Actions job names");
  }
  return value.map((name) => name.trim());
}

// Only named checks decide red/green, so a by-design failing foreign job on the same sha
// no longer reds main. Per name the TOP-RANKED COMPLETED run decides (newest, ties by id),
// so a cancelled run superseded by a later one is judged on that later run, and a stale
// queued run cannot pin the name forever. An unfinished run never masks a verdict that
// already exists: while a re-run is in flight the previous conclusion still stands, so a
// red main stays red for the whole re-run window instead of flipping to `pending` and
// letting workers push onto it. A name with NO completed run at all is stalled; one whose
// only completed runs are skipped/neutral is undecided — nothing has tested the head, which
// is not green (the merge window's "deciding run per required check" rule, mirrored here).
function sentinelState(runs, names) {
  const failing = [];
  const missing = [];
  const stalled = [];
  const undecided = [];
  let pending = false;
  for (const name of names) {
    const forName = runs.filter((run) => run.name === name);
    if (!forName.length) { missing.push(name); pending = true; continue; }
    // Per suite, not just per name: if two workflows publish this name, EITHER one going
    // red is a red. A single winner across suites would let one mask the other.
    const latest = latestCompletedPerName(forName);
    if (!latest.length) { (forName.some((run) => run.status === "completed") ? undecided : stalled).push(name); pending = true; continue; }
    if (latest.some((run) => RED.has(run.conclusion))) failing.push(name);
  }
  return { failing, missing, stalled, undecided, pending };
}

const GITHUB_API = "https://api.github.com";
const CHECK_RUN_PAGES = 3;
const ACTION_JOBS_CONCURRENCY = 4;

async function mapConcurrent(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function consume() {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await fn(items[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, consume));
  return results;
}

// Fine-grained PATs used by workers can read Actions. Page workflow runs for
// this exact sha, then read every returned run's first 100 jobs with `filter=all` so prior
// attempts stay visible to the rank rule. Both partial run and partial job lists are
// reported as truncated rather than silently claiming green from incomplete evidence.
async function fetchActionJobs(fetchImpl, repoBase, sha, headers, timeoutMs, maxPages = CHECK_RUN_PAGES) {
  const jobs = [];
  let totalRuns = 0;
  let fetchedRuns = 0;
  let truncated = false;
  for (let page = 1; page <= maxPages; page += 1) {
    const response = await boundedFetch(fetchImpl, `${repoBase}/actions/runs?head_sha=${encodeURIComponent(sha)}&per_page=100&page=${page}`, { headers }, timeoutMs);
    if (!response.ok) throw await httpFailure(response);
    const body = await response.json();
    const batch = body.workflow_runs || [];
    totalRuns = Number(body.total_count) || totalRuns;
    fetchedRuns += batch.length;
    const pages = await mapConcurrent(batch, ACTION_JOBS_CONCURRENCY, async (workflow) => {
      const jobsResponse = await boundedFetch(fetchImpl, `${repoBase}/actions/runs/${workflow.id}/jobs?filter=all&per_page=100`, { headers }, timeoutMs);
      if (!jobsResponse.ok) throw await httpFailure(jobsResponse);
      const jobsBody = await jobsResponse.json();
      const pageJobs = jobsBody.jobs || [];
      const totalJobs = Number(jobsBody.total_count) || pageJobs.length;
      if (pageJobs.length < totalJobs) truncated = true;
      return pageJobs.map((job) => ({
        ...job, check_suite: { id: workflow.id }, run_id: job.run_id ?? workflow.id,
        run_attempt: job.run_attempt ?? workflow.run_attempt,
      }));
    });
    jobs.push(...pages.flat());
    if (!batch.length || fetchedRuns >= totalRuns) break;
  }
  return { runs: jobs, truncated: truncated || fetchedRuns < totalRuns };
}

function withDeadline(promise, timeoutMs, message) {
  let timer;
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs); });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

// GitHub answers 403 for BOTH "no usable credential" and "you are rate limited". Only the
// first is a misconfiguration; a rate-limited 403 is an outage and has to keep the proceed
// semantics. Rate limiting is ONLY ever an explanation for a 403: reading these headers on
// any other status would mean a 401 or a private-repo 404 that merely ARRIVES during an
// exhausted quota reads as an outage and lets workers through — and six lanes sharing one
// IP exhaust the unauthenticated 60/hr budget routinely, so that is an hourly event, not
// a corner case. The body is a second signal for the 403, read under its own deadline
// because boundedFetch has already cleared the fetch timer by the time we get here.
async function httpFailure(response, bodyTimeoutMs = 1000) {
  let limited = false;
  if (response.status === 403) {
    const header = (name) => response.headers?.get?.(name) ?? null;
    limited = header("x-ratelimit-remaining") === "0" || Boolean(header("retry-after"));
    if (!limited) {
      try { limited = /rate limit|secondary rate|abuse detection/i.test(await withDeadline(response.text(), bodyTimeoutMs, "body read timeout")); }
      catch { limited = false; }
    }
  }
  return Object.assign(new Error(`GitHub HTTP ${response.status}`), { status: response.status, limited });
}

// Fleet repositories are PRIVATE: uncredentialed, the halt reads 404, not green. The
// dedicated name wins over an ambient write-scoped one (AGENTS.md §7 for the PAT itself).
function githubReadToken(env = process.env) {
  const name = ["FLYWHEEL_GITHUB_READ_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"].find((key) => String(env[key] ?? "").trim());
  return name ? { name, value: env[name].trim() } : null;
}

// A GitHub error body can echo a request header back, so no output ever carries the token.
function redact(text, token = githubReadToken()?.value) {
  return token && token.length >= 8 ? String(text ?? "").replaceAll(token, "[redacted]") : String(text ?? "");
}

// Test-only seam, an env var and NOT a config key: nothing committed to a clone may
// redirect the status read. Slash-normalized so a real base keeps its credential.
function apiBaseUrl(raw = process.env.FLYWHEEL_GUARD_API_BASE) {
  return String(raw || GITHUB_API).replace(/\/+$/, "");
}

async function githubMainStatus(root, fetchImpl = fetch, mainSha = "", timeoutMs = 5000, checkNames = [], apiBase = apiBaseUrl(), lsRemoteMs = 5000) {
  const remote = git(root, ["remote", "get-url", "origin"]).stdout.trim();
  const repo = githubRepo(remote);
  if (!repo) return { state: "unknown", cause: "unavailable", reason: "origin is not a GitHub repository" };
  // The credential helper is a `gh` spawn, measured 0.8-1.2s on the fleet host, so 1500ms
  // was a hair trigger once an `unavailable` verdict fails closed for workers.
  const head = mainSha ? null : git(root, ["ls-remote", "origin", "refs/heads/main"], { allowFailure: true, timeout: lsRemoteMs });
  const sha = mainSha || (head?.status === 0 ? head.stdout.trim().split(/\s+/)[0] : "");
  // The prefix is grepped by the detection audit and by humans; the parenthetical tells the
  // next investigator a timeout (SIGTERM/ETIMEDOUT) from a failing exit from a missing ref.
  if (!sha) return { state: "unknown", cause: "unavailable", reason: `origin/main HEAD is unavailable (git ls-remote origin refs/heads/main ${head?.signal || head?.error?.code === "ETIMEDOUT" ? `exceeded ${lsRemoteMs}ms` : head?.error ? `failed to spawn (${head.error.code})` : head?.status ? `exit ${head.status}` : "returned no ref"})` };
  const root_ = apiBaseUrl(apiBase);
  const headers = { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28" };
  // The credential is only ever sent to the real API; an overridden base never sees it.
  const token = root_ === GITHUB_API ? githubReadToken() : null;
  if (token) headers.authorization = `Bearer ${token.value}`;
  try {
    const repoBase = `${root_}/repos/${repo.owner}/${repo.repo}`;
    const commitBase = `${repoBase}/commits/${sha}`;
    const [statusResponse, checks] = await Promise.all([
      boundedFetch(fetchImpl, `${commitBase}/status`, { headers }, timeoutMs),
      fetchActionJobs(fetchImpl, repoBase, sha, headers, timeoutMs),
    ]);
    if (!statusResponse.ok) throw await httpFailure(statusResponse);
    const status = await statusResponse.json();
    const runs = checks.runs;
    // Truncation is not safe-by-default: a hidden run may outrank this one, and pending
    // permits pushes — so report it rather than imply safety.
    const extra = { missing: [], stalled: [], undecided: [], truncated: checks.truncated };
    const names = new Set(sentinelNames(checkNames));
    if (names.size) {
      const { failing, missing, stalled, undecided, pending } = sentinelState(runs, names);
      const posted = Array.isArray(status.statuses) && status.statuses.length > 0;
      if (posted && RED.has(status.state)) failing.push(`commit status ${status.state}`);
      Object.assign(extra, { missing, stalled, undecided });
      if (failing.length) return { state: "red", sha, failing, ...extra };
      // Truncation may hide a run that outranks the ones used here, so a green verdict
      // computed from a partial page is not green — it downgrades to pending, never up.
      if (pending || extra.truncated || (posted && status.state === "pending")) return { state: "pending", sha, failing: [], ...extra };
      return { state: "green", sha, failing: [], ...extra };
    }
    // Legacy (no `redMainCheckNames`) still lets ANY check red main, but judges each name
    // on its latest completed run. `filter=all` now returns superseded runs, so without
    // this a cancelled run replaced by a later success would red main permanently.
    const failing = latestCompletedPerName(runs).filter((run) => RED.has(run.conclusion)).map((run) => run.name || "unnamed check");
    if (RED.has(status.state)) failing.unshift(`commit status ${status.state}`);
    if (failing.length) return { state: "red", sha, failing, ...extra };
    if (extra.truncated || status.state === "pending" || runs.some((run) => run.status !== "completed")) return { state: "pending", sha, failing: [], ...extra };
    return { state: "green", sha, failing: [], ...extra };
  } catch (error) {
    // 401/403/404 is a missing or wrong credential, EXCEPT a 403 the headers or body call
    // rate limiting; a network error, abort, timeout, or 5xx is transient. Only the first
    // is a misconfiguration, and only a misconfiguration stops a worker.
    //
    // A credential that was never sent cannot have been rate limited. The guard KNOWS
    // whether it attached one, and that fact outranks anything the response claims: with
    // no token, 401/403/404 is unauthenticated even under an exhausted quota. Otherwise a
    // busy hour on the shared unauthenticated budget would hand every worker a free pass
    // past a halt that has no credential to read with in the first place.
    const unauth = UNAUTHENTICATED_HTTP.has(error.status) && (!token || !error.limited);
    return { state: "unknown", sha, cause: unauth ? "unauthenticated" : "unavailable", reason: redact(error.message, token?.value) };
  }
}

// Worker pushes onto a red main stay blocked. Non-worker pushes proceed (fail-open is the
// human contract) but never silently: pre-push cannot rewrite the commits it is pushing,
// so the red sha goes to the clone-local audit, which the detection audit renders as
// `human-push-on-red-main` for the clones it is pointed at.
function redMainGate(gitDir, ci, who) {
  const failing = (ci.failing || []).join(", ") || "unnamed checks";
  if (strict(who)) return { blocked: true, reason: `origin/main ${ci.sha} has red GitHub checks: ${failing}` };
  // An audit-write failure must never fail-close a human push; it degrades to the warning.
  recordAudit(gitDir, {
    kind: "ci-status",
    value: "red",
    // `unknown`, not `human`: an unset identity lands on the audit's unknown-identity
    // finding, not the human ratification list.
    class: who?.class || "unknown",
    identity: who?.raw || "unset",
    sha: ci.sha || null,
    failing: ci.failing || [],
  }, "red-main");
  warn(`WARNING: origin/main ${ci.sha} is RED (${failing}); ${who?.raw || "unset"} is not worker class so this push proceeds.`);
  warn("WARNING: recorded in .git/flywheel-guard-audit.jsonl; revert or fix main before dispatching workers.");
  return { blocked: false };
}

// `unknown` was one word for two unrelated situations and both proceeded, which is how
// every real push cleared a halt that had never run. Whatever the cause, the halt cannot
// fire: a worker stops, a human proceeds on the record. Canary loop run #1 (2026-09-02) is
// why the outage case stops too — a worker pushed on a 1.5s ls-remote flake under the old rule.
// Which leg failed decides what the worker should DO about it, and only `ci.reason` knows:
// the two ls-remote-leg prefixes are recognised here, everything else is the API leg.
const LEG_REMEDY = [
  [/^origin\/main HEAD is unavailable/, "confirm GitHub is reachable (git fetch origin main), then retry"],
  [/^origin is not a GitHub repository/, "the red-main halt needs a GitHub origin; report it to the owner"],
];
function unknownMainGate(gitDir, ci, who) {
  const unauth = ci.cause === "unauthenticated";
  const blocked = strict(who);
  const remedy = LEG_REMEDY.find(([leg]) => leg.test(ci.reason || ""))?.[1]
    || "GitHub's API did not answer; wait and retry, never bypass, and report it to the owner if it persists";
  // Recorded BEFORE the block, unlike the red path: a red block is already visible as a
  // red main, but a worker stopped by an unreadable halt leaves no other trace anywhere,
  // and the fleet needs to see that its workers are wedged on an unreadable halt.
  recordAudit(gitDir, {
    kind: "ci-status", value: "unknown", cause: unauth ? "unauthenticated" : "unavailable", blocked,
    class: who?.class || "unknown", identity: who?.raw || "unset", sha: ci.sha || null, reason: redact(ci.reason || "unknown"),
  }, "unknown-status");
  if (blocked) return { blocked, reason: unauth
    ? `red-main read is unauthenticated; set FLYWHEEL_GITHUB_READ_TOKEN, or the repository is not visible to it (${redact(ci.reason || "no credential accepted")})`
    : `red-main read is unavailable (${redact(ci.reason || "GitHub unreachable")}); main's verdict is unknown, so a worker push is refused: ${remedy}` };
  warn(`CI-Status: unknown (${unauth ? "unauthenticated" : redact(ci.reason || "GitHub API unavailable")}); proceeding`);
  return { blocked: false };
}

async function enforceReservations(config, clone, paths, who) {
  try {
    const result = await reservationCheck(config, clone, paths);
    reportReservations(result);
    if (result.conflicts.length) return { blocked: true, reason: "active reservation conflict" };
    return { blocked: false };
  } catch (error) {
    if (strict(who)) return { blocked: true, reason: error.message };
    return { blocked: false, failOpen: error.message };
  }
}

async function main() {
  const phaseArg = process.argv.indexOf("--phase");
  const phase = phaseArg >= 0 ? process.argv[phaseArg + 1] : "";
  if (process.env.CI || process.env.VERCEL) return 0;
  const repo = repository();
  if (!repo || !repo.writable) return 0;
  const { file: configFile, value: config } = loadConfig(repo.root);
  const who = identity();
  let clone;
  try { clone = cloneIdentity(config, repo.root, who); } catch (error) { return fail(error.message); }
  const bypass = await allowBypass(config, repo, who, phase);
  if (bypass.blocked) return fail(bypass.blocked);
  if (bypass.bypassed) return 0;
  // Validated on every phase: a worker should learn at commit time that the red-main halt
  // is misconfigured, not after an hour of work at push time.
  let sentinel;
  try { sentinel = sentinelNames(config.redMainCheckNames); }
  catch (error) { return fail(`${configFile}: ${error.message}`); }
  // An explicit `[]` is not "legacy mode, deliberately" — it reads as a configured
  // sentinel while silently restoring all-checks behavior. Omit the key to mean legacy.
  if (Array.isArray(config.redMainCheckNames) && !config.redMainCheckNames.length) {
    return fail(`${configFile}: redMainCheckNames is an empty array; omit the key to choose legacy all-checks mode`);
  }

  if (phase === "pre-commit" || phase === "commit-msg") {
    const result = await enforceReservations(config, clone, stagedPaths(repo.root), who);
    if (result.blocked) return fail(result.reason);
    if (phase === "commit-msg") {
      const messageFile = process.argv.at(-1);
      if (result.failOpen) appendTrailer(messageFile, "Flywheel-Guard", `fail-open ${result.failOpen}`);
      if (who) appendTrailer(messageFile, "Flywheel-Identity", who.raw);
      if (who?.class === "worker") {
        try { validateBead(config, repo.root, who.name, fs.readFileSync(messageFile, "utf8")); }
        catch (error) { return fail(error.message); }
      }
    } else if (result.failOpen) {
      // §11: Mail unreachable + human class fails open and the commit PROCEEDS. Letting
      // this row throw turned the documented fail-open into a hard block.
      recordAudit(repo.gitDir, { kind: "fail-open", phase, identity: who?.raw || "unset", reason: result.failOpen }, "fail-open");
      warn(`fail-open: ${result.failOpen}; commit-msg will add the trailer`);
    }
    return 0;
  }

  if (phase === "pre-push") {
    const stdin = fs.readFileSync(0, "utf8");
    // A lane landing commits on main is on the direct route: each of them needs a resolvable
    // bead, as a worker's would, and every gate below fails closed for it. A lane pushing a
    // branch (the pull-request route) keeps human semantics throughout.
    const landing = who?.class === "lane" ? mainCommits(stdin, repo.root) : [];
    for (const sha of landing) {
      try { validateBead(config, repo.root, who.name, git(repo.root, ["log", "-1", "--format=%B", sha]).stdout, spawnSync, "lane"); }
      catch (error) { return fail(`${who.raw} is pushing ${sha.slice(0, 12)} to main on the direct route: ${error.message}; open a pull request instead`); }
    }
    const pusher = landing.length ? { ...who, strict: true } : who;
    const result = await enforceReservations(config, clone, outgoing(stdin, repo.root), pusher);
    if (result.blocked) return fail(result.reason);
    // Same contract as pre-commit: the row records the fail-open, it does not gate it.
    if (result.failOpen) recordAudit(repo.gitDir, { kind: "fail-open", phase, identity: who?.raw || "unset", reason: result.failOpen }, "fail-open");
    // Each GitHub request gets 5s, the same budget as ls-remote, because an `unavailable` verdict now stops workers; `githubTimeoutMs` in flywheel.guard.json still overrides.
    const ci = await githubMainStatus(repo.root, fetch, "", config.githubTimeoutMs || 5000, sentinel);
    for (const name of ci.missing || []) warn(`configured red-main check "${name}" has no run on ${ci.sha}; treating main as pending`);
    for (const name of ci.stalled || []) warn(`configured red-main check "${name}" has not completed on ${ci.sha}; treating main as pending`);
    for (const name of ci.undecided || []) warn(`configured red-main check "${name}" has only skipped/neutral runs on ${ci.sha}; the head was never tested, treating main as pending`);
    if (ci.truncated) warn(`the Actions job list for ${ci.sha} was truncated after ${CHECK_RUN_PAGES} pages; a hidden run could outrank the one used here`);
    // Truncated AND a configured sentinel absent from everything fetched is the one case
    // where "pending" could be hiding a run we simply never reached. Pushes still proceed
    // (§7: pending proceeds), but the gap becomes a durable audit row rather than silence.
    if (ci.truncated && (ci.missing || []).length) {
      recordAudit(repo.gitDir, { kind: "truncated-missing", sha: ci.sha || null, missing: ci.missing, pages: CHECK_RUN_PAGES }, "truncated-missing");
      warn(`WARNING: ${ci.missing.join(", ")} absent from a truncated Actions job list for ${ci.sha}; recorded as truncated-missing`);
    }
    if (ci.state === "red") {
      // The janitor exception skips redMainGate ONLY: control still reaches the `undecided`
      // and `unknown` blocks below, both unchanged. The audit row is written BEFORE the gate
      // is skipped and a write failure REFUSES the exception — a janitor revert onto a red
      // main with no durable evidence is exactly what allowBypass's own rule exists to stop.
      let exception = { ok: false, reason: "not a strict class", attempted: false };
      if (strict(pusher)) {
        try { exception = janitorException(config, repo, stdin, ci, pusher); }
        catch (error) { exception = { ok: false, reason: error.message, attempted: false }; }
        if (exception.ok) {
          const recorded = recordAudit(repo.gitDir, {
            kind: "janitor-revert",
            sha: exception.sha,
            revertsSha: ci.sha,
            bead: exception.bead,
            identity: pusher.raw,
          }, "janitor-revert");
          if (recorded) {
            warn(`janitor revert ${exception.sha.slice(0, 12)} of red head ${ci.sha.slice(0, 12)} admitted (${exception.path}, bead ${exception.bead}); recorded in .git/flywheel-guard-audit.jsonl`);
          } else {
            exception = { ok: false, reason: "the janitor-revert audit row could not be written", attempted: true };
          }
        }
        if (!exception.ok && exception.attempted) warn(`janitor exception refused: ${exception.reason}`);
      }
      if (!exception.ok) {
        const gate = redMainGate(repo.gitDir, ci, pusher);
        if (gate.blocked) return fail(gate.reason);
      }
    }
    // Pending proceeds — but a sentinel that only ever skipped never tested this head, and a
    // worker does not push onto one no check has judged. The human was warned above and proceeds.
    if ((ci.undecided || []).length && strict(pusher)) {
      // Recorded before the block, like the unauthenticated row: a grey skip is not a red main, and a wedged worker leaves no other trace.
      recordAudit(repo.gitDir, { kind: "ci-status", value: "undecided", blocked: true, class: who.class, identity: who.raw, sha: ci.sha || null, undecided: ci.undecided }, "undecided-status");
      return fail(`origin/main ${ci.sha} was never tested: ${ci.undecided.join(", ")} has only skipped/neutral runs`);
    }
    if (ci.state === "unknown") {
      const gate = unknownMainGate(repo.gitDir, ci, pusher);
      if (gate.blocked) return fail(gate.reason);
    }
    return 0;
  }
  return fail(`unknown phase ${phase || "(missing)"}`);
}

export { apiBaseUrl, appendTrailer, cloneIdentity, FENCE_GLOBS, githubMainStatus, githubReadToken, githubRepo, identity, janitorException, mainCommits, mainRefUpdates, mcpRequest, overlaps, parseRpcText, redact, redMainGate, sentinelNames, trailerBlock, unknownMainGate, unwrapRpc, validateBead };

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => { process.exitCode = code; }).catch((error) => { process.exitCode = fail(error.message); });
}
