#!/usr/bin/env node
// Post-flip fresh-eyes review sweep.
//
// Once a repository flips to the direct-commit route, nothing reviews a change
// before it lands (AGENTS.md section 8: "review happens after landing"). This is
// that review: a read-only pass over the first-parent commits on `main` that
// arrived since the last sweep, emitting one receipt per run.
//
// It never mutates git state and never writes to the Beads store: `br` is only
// ever invoked as `show ... --json`, and only with an explicit `--db`, because a
// bare `br` inside a clone silently creates a private per-clone store, which is
// the split-brain AGENTS.md section 4 forbids.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const SCHEMA = "flywheel.review-sweep-receipt.v1";
const DEFAULT_OUT = "docs/agent-runs/review-sweeps";
const RECEIPT_PATH_PREFIX = `${DEFAULT_OUT}/`;
const FLIP_EVIDENCE = "docs/flip-evidence";
const DEFAULT_BR = "/home/kevin/.local/bin/br";
const SHA = /^[a-f0-9]{40}$/;
const RUN_ID = /^[a-f0-9]{32}$/;
const IDENTITY = /^[A-Za-z0-9:._-]+$/;
const FINDING_REF = /^[A-Za-z0-9._:-]+$/;
const SKIP_CI = /\[(?:skip[ _-](?:ci|actions)|(?:ci|actions)[ _-]skip|no[ _-]ci)\]/i;
const PR_SUBJECT = /\(#\d+\)\s*$/;
const PR_MERGE = /^Merge pull request #\d+\b/;
// GitHub's web-flow committer: every squash or merge that GitHub performs is
// committed as `GitHub <noreply@github.com>`, whatever the author. A commit made
// in a clone and pushed straight to `main` carries the clone's committer.
const GITHUB_COMMITTER = "noreply@github.com";
// A trailer line as git defines it: a token, a colon, a value. Continuation
// lines start with whitespace.
const TRAILER_LINE = /^([A-Za-z0-9-]+):[ \t]*(.*)$/;
const COMMENT_LINE = /^#/;
// The identity grammar, shared with the guard: `worker:<alias>`, `human:<name>`,
// `lane:<slug>` (an orchestrator-dispatched lane — human semantics on the
// pull-request route, worker semantics on the direct route).
const IDENTITY_CLASS = /^(worker|human|lane):(.+)$/;
// `Bead: none`, optionally `none (<reason>)`: an explicit no-bead declaration,
// which the guard accepts from human and lane class and which is never an id
// to look up. An id starts with an alphanumeric character and otherwise uses
// only the portable Beads token characters. Anything else is reported as
// malformed rather than handed to `br show`; in particular, option-looking or
// path-shaped values must never become `br show` argv.
const NO_BEAD = /^none(?:\s*\(.*\))?$/i;
const BEAD_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
// How many merged branch commits a single merge is read through. A merge that
// brought in more than this is still swept — the cap is recorded on the
// receipt as a LOW finding — but the sweep will not read an unbounded history
// into memory because someone merged a thousand-commit branch.
const MERGED_BODY_LIMIT = 200;
const SIZE_LINES = 400;
const SIZE_FILES = 20;
// br lifecycle values. A bead outside this set is a store the sweep does not
// understand, which is reported rather than silently accepted.
const BEAD_STATUS = new Set(["open", "in_progress", "in-progress", "blocked", "closed", "done", "completed", "cancelled", "canceled", "tombstone"]);

function git(cwd, args, options = {}) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", maxBuffer: 32 * 1024 * 1024, timeout: options.timeout || 15000 });
  if (result.status !== 0 && !options.allowFailure) {
    throw new Error((result.stderr || result.stdout || `git ${args.join(" ")} failed`).trim());
  }
  return result;
}

function parseOptions(argv) {
  const out = { repo: "", since: "", db: "", outDir: "", dryRun: false, reviewer: "", br: "" };
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (key === "--dry-run") { out.dryRun = true; continue; }
    const value = argv[++index];
    if (value === undefined) throw new Error(`missing value for ${key}`);
    if (key === "--repo") out.repo = value;
    else if (key === "--since") out.since = value;
    else if (key === "--db") out.db = value;
    else if (key === "--out") out.outDir = value;
    else if (key === "--reviewer") out.reviewer = value;
    else if (key === "--br") out.br = value;
    else throw new Error(`unknown argument: ${key}`);
  }
  if (out.repo && !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(out.repo)) throw new Error("--repo must be owner/name");
  return out;
}

function repositoryRoot(cwd) {
  const probe = git(cwd, ["rev-parse", "--show-toplevel"], { allowFailure: true });
  if (probe.status !== 0) throw new Error("not inside a git repository");
  return fs.realpathSync(probe.stdout.trim());
}

function slugFromRemote(root) {
  const probe = git(root, ["remote", "get-url", "origin"], { allowFailure: true });
  if (probe.status !== 0) throw new Error("no origin remote; pass --repo owner/name");
  const match = /(?:[:/])([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec(probe.stdout.trim());
  if (!match) throw new Error(`cannot derive owner/name from origin url; pass --repo owner/name`);
  return `${match[1]}/${match[2]}`;
}

// AGENTS.md holds the authoritative critical-path list (canary section 9). The
// list is the first fenced block under the heading that names critical paths;
// flywheel.guard.json mirrors it but is explicitly advisory, so the manual wins.
function criticalPathGlobs(root) {
  const file = path.join(root, "AGENTS.md");
  const text = fs.readFileSync(file, "utf8");
  const lines = text.split(/\r?\n/);
  const heading = lines.findIndex((line) => /^#{1,6}\s.*critical\s*path/i.test(line));
  if (heading < 0) throw new Error("AGENTS.md has no critical-path heading");
  let open = -1;
  for (let index = heading + 1; index < lines.length; index += 1) {
    if (/^#{1,6}\s/.test(lines[index])) break;
    if (/^```/.test(lines[index])) { open = index; break; }
  }
  if (open < 0) throw new Error("AGENTS.md critical-path section has no fenced glob list");
  const globs = [];
  for (let index = open + 1; index < lines.length; index += 1) {
    if (/^```/.test(lines[index])) return globs;
    const value = lines[index].trim();
    if (value) globs.push(value);
  }
  throw new Error("AGENTS.md critical-path fence is unterminated");
}

function globToRegExp(glob) {
  let source = "";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*" && glob[index + 1] === "*") {
      index += 1;
      if (glob[index + 1] === "/") { index += 1; source += "(?:.*/)?"; }
      else source += ".*";
    } else if (character === "*") source += "[^/]*";
    else if (character === "?") source += "[^/]";
    else source += character.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${source}$`);
}

function firstMatchingGlob(file, globs) {
  return globs.find((candidate) => globToRegExp(candidate).test(file));
}

function matchesAnyGlob(file, globs) {
  return firstMatchingGlob(file, globs) !== undefined;
}

// The trailer block of a commit message, parsed the way git does rather than
// by scanning every line: a trailer is a `Key: value` line in a trailing
// paragraph made ONLY of trailer lines (continuation lines start with
// whitespace), with git comment lines ignored. A paragraph that mixes prose
// with a `Key:` line is prose, and a
// `Bead: <id>` quoted in the middle of a sentence is never a trailer — treating
// it as one would spawn a real `br show` for an id that was only mentioned,
// and a store error on that lookup would fail the whole nightly sweep.
//
// One deliberate extension over `git interpret-trailers --parse`, which reads
// the LAST paragraph only: every trailing paragraph made only of trailer lines
// is part of the block. The guard's `appendTrailer()` writes
// `Flywheel-Identity:` as its own paragraph after the worker's `Bead:`
// paragraph, so every real worker commit in this program has two trailing
// trailer-only paragraphs, and git's strict rule would drop the `Bead:` line
// from all of them. The suite pins that shape against a real guard message.
function trailerBlock(body) {
  const paragraphs = String(body || "").replace(/\r\n/g, "\n").replace(/\s+$/, "").split(/\n[ \t]*\n/);
  const block = [];
  for (let index = paragraphs.length - 1; index >= 0; index -= 1) {
    const rawLines = paragraphs[index].split("\n");
    const lines = rawLines.filter((line) => !COMMENT_LINE.test(line));
    const entries = [];
    let trailerOnly = rawLines.length > 0;
    for (const line of lines) {
      const match = TRAILER_LINE.exec(line);
      if (match) entries.push({ key: match[1], value: match[2].trim() });
      else if (/^[ \t]+\S/.test(line) && entries.length) entries[entries.length - 1].value += ` ${line.trim()}`;
      else { trailerOnly = false; break; }
    }
    // The subject line is never a trailer, however it is shaped.
    if (!trailerOnly || index === 0) break;
    block.unshift(...entries);
  }
  return block;
}

function trailerValues(body, key) {
  const wanted = key.toLowerCase();
  return trailerBlock(body).filter((entry) => entry.key.toLowerCase() === wanted).map((entry) => entry.value).filter(Boolean);
}

// Trailers are read from the merge commit's own message PLUS, for a merge, the
// messages of the commits it brought in. A merge commit's message is written by
// GitHub and carries none of the branch's `Bead:` / `Flywheel-Identity`
// evidence, so reading only the merge message reports every merged pull request
// as beadless and unattributable — silence that looks exactly like a clean
// result.
//
// `[skip ci]` is the one fact that is NOT folded. The token suppresses CI only
// when it appears in the pushed head commit's own message; a branch commit that
// quoted it in prose, merged by a clean merge commit, suppressed nothing. Folding
// it produced a HIGH on this very branch's merge, whose commits discuss the
// token by name.
function commitFacts(body, extraBodies = []) {
  const bodies = [body, ...extraBodies];
  const values = (key) => bodies.flatMap((text) => trailerValues(text, key));
  // The FIRST recognised identity wins for one commit. Across a folded merge,
  // however, any worker identity makes the aggregate worker-class: choosing a
  // newer human or lane identity would hide worker evidence from the sweep.
  // An unrecognised-only value is still carried so the receipt shows what was
  // there.
  const identities = values("Flywheel-Identity");
  const recognised = identities.filter((value) => IDENTITY_CLASS.test(value));
  const identity = extraBodies.length > 0
    ? recognised.find((value) => value.startsWith("worker:")) || recognised[0] || identities[0] || ""
    : recognised[0] || identities[0] || "";
  const beads = values("Bead");
  return {
    identity,
    identities: [...new Set(identities)],
    identity_class: IDENTITY_CLASS.exec(identity)?.[1] || "unknown",
    // Two Flywheel-Identity lines in ONE message: the guard never writes that.
    identity_duplicated: bodies.some((text) => trailerValues(text, "Flywheel-Identity").length > 1),
    guard_trailers: values("Flywheel-Guard"),
    ci_status_trailers: values("CI-Status"),
    bead_ids: [...new Set(beads.filter((value) => BEAD_ID.test(value) && !NO_BEAD.test(value)))],
    no_bead_declarations: beads.filter((value) => NO_BEAD.test(value)),
    malformed_beads: [...new Set(beads.filter((value) => !BEAD_ID.test(value) && !NO_BEAD.test(value)))],
    skip_ci: SKIP_CI.test(body),
  };
}

// Route classification. Two parents on `main` is a merge, and a merge is
// definitively the pull-request route — structure, not a guess. A single-parent
// commit is what a squash merge produces, and GitHub marks it two ways at once:
// the `(#12)` / `Merge pull request #12` subject AND the `GitHub
// <noreply@github.com>` committer, because GitHub performed the commit. The
// subject alone is not enough — `ci: sneaky (#13)` is one keystroke away from
// anyone — so a single-parent commit is PR-routed only when both agree. A
// subject that claims the route on a locally committed commit is reported as
// direct, with the claim named in the evidence.
function classifyRoute(subject, parents, committerEmail) {
  if (parents.length > 1) return { route: "pull-request", route_evidence: "merge commit (two parents)" };
  const claimed = PR_SUBJECT.test(subject) || PR_MERGE.test(subject);
  const github = String(committerEmail || "").toLowerCase() === GITHUB_COMMITTER;
  if (claimed && github) return { route: "pull-request", route_evidence: "single parent; pull-request subject; committed by GitHub" };
  if (claimed) return { route: "direct", route_evidence: "single parent; subject claims a pull-request route but the committer is not GitHub" };
  return { route: "direct", route_evidence: "single parent; no pull-request marker" };
}

function parseCommit(record) {
  const clean = record.replace(/^\n+|\n+$/g, "");
  if (!clean) return null;
  const [sha, author, email, committer, committerEmail, date, parentField = "", body = ""] = clean.split("\0", 8);
  const subject = body.split(/\r?\n/, 1)[0] || "(no subject)";
  const parents = parentField.split(/\s+/).filter(Boolean);
  return {
    sha,
    short_sha: sha.slice(0, 12),
    author,
    author_email: email,
    committer,
    committer_email: committerEmail,
    date,
    subject,
    body,
    parents,
    merge: parents.length > 1,
    ...classifyRoute(subject, parents, committerEmail),
    ...commitFacts(body),
  };
}

// The commits a merge brought in: reachable from the merge but not from its
// first parent, i.e. the branch that was merged. Bounded: at most `limit`
// bodies are read, and the caller is told when the merge held more.
function mergedBodies(root, commit, limit = MERGED_BODY_LIMIT) {
  if (!commit.merge) return { bodies: [], truncated: false };
  // `A^1..A` is "reachable from A but not from its first parent", which includes
  // A itself — the merge commit whose message is exactly the one with no
  // evidence in it. Carry the sha so it can be dropped; this also keeps every
  // parent of an octopus merge, which `^1..^2` would silently lose. One extra
  // record past the cap (plus the merge itself) is how truncation is detected.
  const result = git(root, ["log", `--max-count=${limit + 2}`, `${commit.sha}^1..${commit.sha}`, "--format=%H%x00%B%x1e"], { allowFailure: true });
  if (result.status !== 0) return { bodies: [], truncated: false };
  const bodies = result.stdout.split("\x1e")
    .map((record) => record.replace(/^\n+|\n+$/g, ""))
    .filter(Boolean)
    .map((record) => record.split("\0", 2))
    .filter(([sha]) => sha !== commit.sha)
    .map(([, body = ""]) => body);
  return { bodies: bodies.slice(0, limit).filter(Boolean), truncated: bodies.length > limit };
}

function resolveCommit(root, revision) {
  const probe = git(root, ["rev-parse", "--verify", "--quiet", `${revision}^{commit}`], { allowFailure: true });
  const sha = probe.stdout.trim().toLowerCase();
  if (probe.status !== 0 || !SHA.test(sha)) throw new Error(`cannot resolve commit: ${revision}`);
  return sha;
}

// Why a receipt is not usable as the next sweep's floor, or "" when it is. The
// floor decides which commits are never looked at again, so a receipt earns
// that role only by being a complete, coherent record of THIS repository whose
// head sits on the first-parent line the sweep walks. Anything less — a receipt
// for another target, one with its two head fields disagreeing, one whose
// findings contradict its outcome, a symlink to a receipt elsewhere, a head
// merged in from a side branch — would let a newer file silently skip a window
// of `main`, or review a range that never landed.
function receiptRejection(file, value, context) {
  let stat;
  try { stat = fs.lstatSync(file); } catch { return "unreadable"; }
  if (stat.isSymbolicLink()) return "symbolic link, not a regular receipt file";
  if (!stat.isFile()) return "not a regular file";
  if (!value || typeof value !== "object") return "not a JSON object";
  if (value.schema !== SCHEMA) return `schema is ${JSON.stringify(value.schema)}, not ${SCHEMA}`;
  if (context.slug && value.targetSlug !== context.slug) return `targetSlug ${JSON.stringify(value.targetSlug)} is not ${context.slug}`;
  const head = String(value.head_sha || "").toLowerCase();
  if (!SHA.test(head)) return "head_sha is not a 40-hex sha";
  if (String(value.observedMainSha || "").toLowerCase() !== head) return "observedMainSha does not equal head_sha";
  if (!Number.isFinite(Date.parse(value.completedAtUtc))) return "completedAtUtc is missing or not a date";
  if (value.ledgerEligible !== true) return "ledgerEligible is not true (an empty-range receipt is not a floor)";
  const reviewed = Array.isArray(value.reviewedCommitShas) ? value.reviewedCommitShas.map((sha) => String(sha).toLowerCase()) : null;
  if (!reviewed || !reviewed.length) return "reviewedCommitShas is empty";
  if (reviewed.some((sha) => !SHA.test(sha))) return "reviewedCommitShas holds a non-sha";
  if (new Set(reviewed).size !== reviewed.length) return "reviewedCommitShas holds duplicates";
  if (!reviewed.includes(head)) return "reviewedCommitShas does not contain head_sha";
  if (value.outcome !== "clean" && value.outcome !== "findings") return `outcome is ${JSON.stringify(value.outcome)}`;
  if (value.verdict !== value.outcome) return "verdict does not equal outcome";
  if (!Array.isArray(value.findingRefs) || value.findingRefs.some((ref) => !FINDING_REF.test(String(ref)))) return "findingRefs is not a list of contract-shaped refs";
  if ((value.findingRefs.length === 0) !== (value.outcome === "clean")) return "findingRefs must be empty exactly when the outcome is clean";
  if (context.firstParentLineage && !context.firstParentLineage().has(head)) return "head_sha is not on the current first-parent lineage of HEAD";
  return "";
}

// The most recent usable sweep receipt names the head it stopped at, so
// consecutive sweeps tile the history with no gap and no re-review. Returns the
// chosen head plus every newer-or-older receipt that was refused, with its
// reason, so the receipt that results can say which files it ignored.
function selectReceipt(outDir, context = {}) {
  if (!fs.existsSync(outDir)) return { head: "", rejected: [] };
  const receipts = [];
  const rejected = [];
  for (const name of fs.readdirSync(outDir).filter((value) => value.endsWith(".json")).sort()) {
    const file = path.join(outDir, name);
    let value = null;
    let reason = "";
    try { value = JSON.parse(fs.readFileSync(file, "utf8")); } catch (error) { reason = `unparseable json: ${error.message}`; }
    reason = reason || receiptRejection(file, value, context);
    if (reason) { rejected.push({ file: name, reason }); continue; }
    receipts.push({ head: String(value.head_sha).toLowerCase(), at: Date.parse(value.completedAtUtc) });
  }
  // Ordered by when the sweep ran, never by filename. Filenames are
  // <date>-<shortsha>, so two sweeps on the same day sort by SHA — and a lexical
  // "latest" would hand the next sweep an OLDER head, silently re-reviewing one
  // range and skipping another.
  receipts.sort((left, right) => left.at - right.at);
  return { head: receipts.at(-1)?.head || "", rejected };
}

function latestReceiptHead(outDir, context = {}) {
  return selectReceipt(outDir, context).head;
}

// The first-parent line from HEAD back to the root, computed once and only if
// a receipt candidate gets as far as the lineage check.
function firstParentLineage(root, head) {
  let cache = null;
  return () => {
    if (!cache) cache = new Set(git(root, ["rev-list", "--first-parent", head]).stdout.split(/\s+/).filter(Boolean));
    return cache;
  };
}

// Before the first sweep there is no prior receipt, so the floor is the commit
// that opened the direct-commit route. It is recorded as a `Flip-Commit:` line
// in docs/flip-evidence/, which is the repository's own flip record.
function flipCommit(root) {
  const directory = path.join(root, FLIP_EVIDENCE);
  if (!fs.existsSync(directory)) return "";
  for (const name of fs.readdirSync(directory).sort()) {
    if (!name.endsWith(".md")) continue;
    const match = /^[ \t>*_-]*Flip-Commit\**\s*:\**\s*`?([a-f0-9]{40})`?\s*$/im
      .exec(fs.readFileSync(path.join(directory, name), "utf8"));
    if (match) return match[1].toLowerCase();
  }
  return "";
}

function resolveSince(root, options, outDir, context) {
  if (options.since) return { sha: resolveCommit(root, options.since), source: "argument", rejectedReceipts: [] };
  const { head, rejected } = selectReceipt(outDir, context);
  if (head) return { sha: resolveCommit(root, head), source: "previous-receipt", rejectedReceipts: rejected };
  const flip = flipCommit(root);
  if (flip) return { sha: resolveCommit(root, flip), source: "flip-evidence", rejectedReceipts: rejected };
  throw new Error(`no --since, no usable prior receipt in ${path.relative(root, outDir) || DEFAULT_OUT}, and no Flip-Commit: <sha> line in ${FLIP_EVIDENCE}/`);
}

function commitRange(root, since, head, mergedBodyLimit = MERGED_BODY_LIMIT) {
  if (since === head) return [];
  const ancestor = git(root, ["merge-base", "--is-ancestor", since, head], { allowFailure: true });
  if (ancestor.status !== 0) throw new Error(`--since ${since.slice(0, 12)} is not an ancestor of ${head.slice(0, 12)}`);
  const format = "%H%x00%an%x00%ae%x00%cn%x00%ce%x00%aI%x00%P%x00%B%x1e";
  const out = git(root, ["log", "--first-parent", `--format=${format}`, `${since}..${head}`]).stdout;
  const commits = out.split("\x1e").map(parseCommit).filter(Boolean);
  for (const commit of commits) {
    const { bodies, truncated } = mergedBodies(root, commit, mergedBodyLimit);
    commit.merged_truncated = truncated;
    if (!bodies.length) continue;
    commit.merged_commits = bodies.length;
    Object.assign(commit, commitFacts(commit.body, bodies));
  }
  return commits;
}

// What the commit changed on `main`: its tree against its FIRST parent's tree,
// as an explicit two-tree diff. `diff-tree -m --first-parent <sha>` looked
// equivalent and is not — for a merge it emits one diff per parent, so the
// receipt double-counted every merge (the other parent's diff is the whole of
// `main` since the branch point) and attributed the previous pull request's
// files to this one. A root commit has no parent and is diffed against the
// empty tree.
function diffTreeArgs(commit, ...flags) {
  return commit.parents.length
    ? ["diff-tree", "--no-commit-id", "-r", ...flags, `${commit.sha}^1`, commit.sha]
    : ["diff-tree", "--no-commit-id", "-r", ...flags, "--root", commit.sha];
}

function commitFiles(root, commit, globs) {
  const numstat = git(root, diffTreeArgs(commit, "--numstat")).stdout;
  const files = [];
  for (const line of numstat.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const [added, deleted, ...rest] = line.split("\t");
    const file = rest.join("\t");
    if (!file) continue;
    // Fence order decides ties; keep the exact first match for review evidence.
    const glob = firstMatchingGlob(file, globs);
    files.push({
      path: file,
      added: added === "-" ? null : Number(added),
      deleted: deleted === "-" ? null : Number(deleted),
      critical_path: glob !== undefined,
      ...(glob === undefined ? {} : { critical_path_glob: glob }),
    });
  }
  const stat = git(root, diffTreeArgs(commit, "--stat")).stdout
    .split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  return { files, stat };
}

// The same ELF check the guard (requireNativeBr) and the detection audit use. A
// Windows `br.exe` shim on PATH cannot read the WSL shared store, and letting it
// through would turn every bead into a false "unresolved".
function requireNativeBr(binary) {
  let stat;
  try { stat = fs.statSync(binary); } catch { throw new Error(`native br binary is missing: ${binary}`); }
  if (!stat.isFile()) throw new Error(`native br binary is not a regular file: ${binary}`);
  const magic = Buffer.alloc(4);
  const descriptor = fs.openSync(binary, "r");
  try { fs.readSync(descriptor, magic, 0, 4, 0); } finally { fs.closeSync(descriptor); }
  if (!magic.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    throw new Error(`refusing non-ELF br binary: ${binary}`);
  }
}

function beadLookup(binary, database, id, slug, runner = spawnSync) {
  requireNativeBr(binary);
  const result = runner(binary, [
    "--db", database,
    "--no-auto-import",
    "--no-auto-flush",
    "--lock-timeout", "5000",
    "--actor", "review-sweep-v1",
    "show", id, "--json",
  ], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 15000 });
  if (result.error) throw new Error(`br could not be executed: ${result.error.message}`);
  let payload = null;
  try { payload = JSON.parse(result.stdout || ""); } catch { payload = null; }
  if (result.status !== 0) {
    // br exits 3 with ISSUE_NOT_FOUND for a bead that genuinely is not there.
    // EVERY other non-zero exit — 7 CONFIG_ERROR for an unreachable store, a
    // lock timeout, a shim that cannot open the database — means the sweep does
    // not know, and "does not know" must never be rendered as "absent". An
    // absent bead ships a `br create` command a reviewer might actually run, so
    // a broken store would manufacture exactly the findings this script exists
    // to avoid. A broken br is a sweep ERROR (exit 1).
    if (payload?.error?.code === "ISSUE_NOT_FOUND") {
      return { id, state: "unresolved", detail: "not present in the configured shared store" };
    }
    const detail = payload?.error?.code || String(result.stderr || "").trim() || `exit ${result.status}`;
    throw new Error(`br show ${id} failed against ${database}: ${detail}`);
  }
  if (payload === null) throw new Error(`br show ${id} returned unparseable json`);
  const issue = Array.isArray(payload) ? payload[0] : (payload.issues?.[0] || (payload.id ? payload : null));
  if (!issue) throw new Error(`br show ${id} exited 0 but returned no issue`);
  if (issue.id !== id) return { id, state: "mismatch", detail: `store returned ${issue.id}` };
  if (!BEAD_STATUS.has(String(issue.status || ""))) return { id, state: "mismatch", detail: `unrecognized status ${issue.status || "(none)"}` };
  const name = slug.split("/")[1] || "";
  const home = String(issue.source_repo_path || "");
  if (home && name && !home.split(/[\\/]/).includes(name)) return { id, state: "mismatch", detail: `bead is homed in ${home}` };
  return { id, state: "resolved", detail: String(issue.status) };
}

function finding(severity, code, sha, evidence) {
  return { severity, code, commit: sha, evidence };
}

function analyze(commits) {
  const findings = [];
  for (const commit of commits) {
    if (commit.skip_ci) {
      findings.push(finding("HIGH", "skip-ci-token", commit.sha, "the commit's own message carries a documented CI skip token, which suppressed CI for the push that landed it; the main-status sentinel is how red main is detected"));
    }
    const critical = commit.files.filter((file) => file.critical_path)
      .map((file) => `${file.path} (matched by ${file.critical_path_glob})`);
    if (critical.length && commit.route === "direct") {
      findings.push(finding("HIGH", "critical-path-direct", commit.sha, `pull-request-only paths landed by direct commit (${commit.route_evidence}): ${critical.join(", ")}`));
    }
    // Sweep receipts are the durable review record and therefore cannot attest
    // to direct edits of their own history. Such edits are HIGH even though the
    // receipt directory is not part of the pull-request-only critical fence.
    const receiptPaths = commit.files.filter((file) => file.path.startsWith(RECEIPT_PATH_PREFIX)).map((file) => file.path);
    if (receiptPaths.length && commit.route === "direct") {
      findings.push(finding("HIGH", "receipt-touched-direct", commit.sha, `review-sweep receipt paths changed by direct commit (${commit.route_evidence}): ${receiptPaths.join(", ")}`));
    }
    if (commit.merged_truncated) {
      findings.push(finding("LOW", "merge-evidence-truncated", commit.sha, `merge brought in more than ${MERGED_BODY_LIMIT} commits; only the newest ${MERGED_BODY_LIMIT} were read for trailers, so identity and bead evidence for the rest is unread`));
    }
    if (commit.identity_class === "unknown") {
      // A squash-merged or merged pull request is authored by GitHub, where no
      // local hook runs, so it can never carry the trailer. That is a real gap
      // with no local remedy and the pull request is its own review evidence —
      // recorded, but not at the severity of an untrailered direct commit,
      // which is a commit nobody can attribute and nobody reviewed. A trailer
      // that IS there but outside the grammar is named, not called absent.
      const why = commit.identities.length
        ? `Flywheel-Identity trailer present but outside the worker:/human:/lane: grammar (${commit.identities.join(", ")})`
        : "no Flywheel-Identity trailer";
      if (commit.route === "pull-request") {
        findings.push(finding("LOW", "missing-identity-pr-route", commit.sha, `${why}; commit was authored by GitHub on the pull-request route, where no local guard hook runs`));
      } else {
        findings.push(finding("MEDIUM", "missing-identity", commit.sha, `${why} on a direct commit`));
      }
    }
    if (commit.identity_duplicated) {
      findings.push(finding("LOW", "duplicate-identity", commit.sha, `more than one Flywheel-Identity trailer in one message (${commit.identities.join(", ")}); the first recognised one, ${commit.identity_class === "unknown" ? "none" : commit.identity}, was used`));
    }
    // The guard's bead contract: a worker always needs a resolvable id, and so
    // does a lane whose commit landed on main by the direct route. Human class,
    // and a lane on the pull-request route, may declare `Bead: none` instead.
    const needsId = commit.identity_class === "worker" || (commit.identity_class === "lane" && commit.route === "direct");
    if (needsId && !commit.bead_ids.length) {
      const declared = commit.no_bead_declarations.length ? "declares `Bead: none`, which is not an id" : "carries no Bead: trailer";
      findings.push(finding("MEDIUM", "missing-bead", commit.sha, `${commit.identity_class}-class commit on the ${commit.route} route ${declared}; a resolvable bead id is required`));
    } else if (commit.no_bead_declarations.length) {
      findings.push(finding("LOW", "no-bead-declared", commit.sha, `Bead: ${commit.no_bead_declarations[0]} — explicit no-bead declaration by ${commit.identity_class} class; informational, nothing was looked up`));
    }
    for (const value of commit.malformed_beads) {
      findings.push(finding("MEDIUM", "malformed-bead", commit.sha, `Bead: ${value} — neither a portable bead id nor a \`none\` declaration; not looked up`));
    }
    for (const bead of commit.beads) {
      if (bead.state === "unresolved") findings.push(finding("MEDIUM", "unresolved-bead", commit.sha, `Bead: ${bead.id} — ${bead.detail}`));
      if (bead.state === "mismatch") findings.push(finding("MEDIUM", "bead-mismatch", commit.sha, `Bead: ${bead.id} — ${bead.detail}`));
    }
    for (const value of commit.guard_trailers.filter((item) => /^fail-open\b/i.test(item))) {
      findings.push(finding("LOW", "guard-fail-open", commit.sha, `Flywheel-Guard: ${value} — reconcile against the Agent Mail log`));
    }
    for (const value of commit.ci_status_trailers.filter((item) => /^unknown\b/i.test(item))) {
      findings.push(finding("LOW", "ci-status-unknown", commit.sha, `CI-Status: ${value} — main status was unreadable at push time`));
    }
    if (commit.size_flag) {
      findings.push(finding("LOW", "oversized-commit", commit.sha, `${commit.lines_changed} lines across ${commit.files_changed} files exceeds the ${SIZE_LINES}-line / ${SIZE_FILES}-file review budget`));
    }
  }
  return findings;
}

function beadCommands(findings, database) {
  const db = database || "<shared store>";
  // A no-bead declaration is already the explicit, reviewed decision not to
  // create a bead. Keep the informational finding in the receipt, but never
  // turn that declaration into a command that would create junk follow-up work.
  return findings.filter((item) => item.code !== "no-bead-declared").map((item) => {
    const title = `review sweep ${item.code} at ${item.commit.slice(0, 12)}`;
    const description = `${item.severity}: ${item.evidence} (commit ${item.commit})`;
    return `br --db ${JSON.stringify(db)} create ${JSON.stringify(title)} -l flywheel-queue -d ${JSON.stringify(description)}`;
  });
}

function cell(value, limit = 200) {
  const flat = String(value ?? "").replaceAll("|", "\\|").replace(/\s+/g, " ");
  return flat.length > limit ? `${flat.slice(0, limit - 1)}…` : flat;
}

// Finding evidence is never truncated. `critical-path-direct` lists the exact
// paths that landed without review, and a commit touching a dozen of them would
// have the tail of that list — the part naming the files a reviewer must go
// look at — cut off at 200 characters.
function evidenceCell(value) {
  return cell(value, Number.MAX_SAFE_INTEGER);
}

function render(receipt) {
  const lines = [
    `# Review sweep — ${receipt.targetSlug} — ${receipt.completedAtUtc.slice(0, 10)}`,
    "",
    `- Run ID: \`${receipt.runId}\``,
    `- Reviewer: \`${receipt.reviewerIdentity}\``,
    `- Range: \`${receipt.since_sha.slice(0, 12)}\`..\`${receipt.head_sha.slice(0, 12)}\` (first-parent, exclusive of \`since\`)`,
    `- Since resolved from: ${receipt.since_source}${receipt.since_rejected_receipts.length ? ` (${receipt.since_rejected_receipts.length} receipt file(s) refused as a floor — see below)` : ""}`,
    `- Beads store: ${receipt.beadStore ? `\`${receipt.beadStore}\`` : "not consulted (no `Bead:` trailer in range)"}`,
    ...(receipt.criticalPathFence ? [`- Critical-path fence: \`${receipt.criticalPathFence.source}\` (${receipt.criticalPathFence.globCount} globs)`] : []),
    `- Commits reviewed: ${receipt.commits.length}`,
    `- Completed UTC: \`${receipt.completedAtUtc}\``,
    `- Verdict: **${receipt.verdict}** (decided by HIGH/MEDIUM findings; ${receipt.findings.length} total, ${receipt.findingRefs.length} blocking)`,
    "",
    "## Commits",
    "",
    "| Commit | Author | Date | Route | Identity | Beads | Files | Lines | Subject |",
    "|---|---|---|---|---|---|---|---|---|",
  ];
  if (!receipt.commits.length) lines.push("| none | — | — | — | — | — | — | — | — |");
  for (const commit of receipt.commits) {
    const beads = [
      ...commit.beads.map((bead) => `${bead.id} (${bead.state})`),
      ...commit.no_bead_declarations.map(() => "none (declared)"),
      ...commit.malformed_beads.map((value) => `${value} (malformed)`),
    ].join(", ") || "—";
    lines.push(`| \`${commit.short_sha}\` | ${cell(commit.author)} | ${cell(commit.date)} | ${commit.route}${commit.merged_commits ? ` (merge of ${commit.merged_commits}${commit.merged_truncated ? "+" : ""})` : ""} | ${cell(commit.identity || commit.identity_class)} | ${cell(beads)} | ${commit.files_changed} | ${commit.lines_changed} | ${cell(commit.subject)} |`);
  }
  if (receipt.since_rejected_receipts.length) {
    lines.push("", "## Receipt files refused as the `--since` floor", "", "| File | Reason |", "|---|---|");
    for (const item of receipt.since_rejected_receipts) lines.push(`| \`${cell(item.file)}\` | ${cell(item.reason)} |`);
  }
  lines.push("", "## Findings", "", "| Severity | Code | Commit | Evidence |", "|---|---|---|---|");
  if (!receipt.findings.length) lines.push("| none | — | — | — |");
  for (const item of receipt.findings) {
    lines.push(`| ${item.severity} | ${cell(item.code)} | \`${item.commit.slice(0, 12)}\` | ${evidenceCell(item.evidence)} |`);
  }
  lines.push("", "## Reviewer notes", "");
  if (!receipt.commits.length) lines.push("_No commits in range._");
  for (const commit of receipt.commits) {
    lines.push(`### \`${commit.short_sha}\` — ${commit.subject}`, "", "```", ...commit.stat, "```", "", `**Reviewer note:** ${commit.reviewer_note || "_(empty — fill in during the sweep)_"}`, "");
  }
  lines.push(
    "## Queued bead commands",
    "",
    "Findings are **not** filed automatically. A reviewer decides which of these",
    "are real and runs the command; the label is `flywheel-queue`.",
    "",
  );
  if (!receipt.queuedBeadCommands.length) lines.push("_None — the sweep is clean._", "");
  else lines.push("```sh", ...receipt.queuedBeadCommands, "```", "");
  lines.push(
    "## Critical-path globs applied",
    "",
    "```",
    ...receipt.criticalPathGlobs,
    "```",
    "",
    `Ledger-eligible: **${receipt.ledgerEligible ? "yes" : "no"}**. Promotion authorized: **no**.`,
  );
  return `${lines.join("\n")}\n`;
}

function writeExclusive(file, value) {
  const descriptor = fs.openSync(file, "wx", 0o644);
  try {
    fs.writeFileSync(descriptor, value, "utf8");
    fs.fsyncSync(descriptor);
  } finally { fs.closeSync(descriptor); }
}

function run(argv = [], runtime = {}) {
  const options = parseOptions(argv);
  const root = repositoryRoot(runtime.cwd || process.cwd());
  const slug = options.repo || slugFromRemote(root);
  const outDir = path.resolve(root, options.outDir || DEFAULT_OUT);
  const head = resolveCommit(root, "HEAD");
  const since = resolveSince(root, options, outDir, { slug, firstParentLineage: firstParentLineage(root, head) });
  const globs = criticalPathGlobs(root);
  const commits = commitRange(root, since.sha, head, runtime.mergedBodyLimit || MERGED_BODY_LIMIT);

  for (const commit of commits) {
    const { files, stat } = commitFiles(root, commit, globs);
    commit.files = files;
    commit.stat = stat;
    commit.files_changed = files.length;
    commit.lines_changed = files.reduce((sum, file) => sum + (file.added || 0) + (file.deleted || 0), 0);
    commit.size_flag = commit.lines_changed > SIZE_LINES || commit.files_changed > SIZE_FILES;
    commit.reviewer_note = "";
    commit.beads = [];
  }

  const needsStore = commits.some((commit) => commit.bead_ids.length);
  if (needsStore && !options.db) {
    throw new Error("commits in range carry Bead: trailers; --db <shared store path> is required (a bare `br` would create a private per-clone store)");
  }
  if (options.db) {
    const stat = fs.statSync(options.db);
    if (!stat.isFile()) throw new Error(`--db is not a regular file: ${options.db}`);
  }
  const lookup = runtime.beadLookup || ((id) => beadLookup(options.br || DEFAULT_BR, options.db, id, slug));
  for (const commit of commits) {
    commit.beads = commit.bead_ids.map((id) => lookup(id));
  }

  const findings = analyze(commits);
  // The verdict is decided by HIGH and MEDIUM only. LOW findings are structural
  // facts about the pull-request route — GitHub authors every merge commit, and
  // any real pull request exceeds a 400-line budget — so counting them would put
  // every sweep at "findings" and exit 2 forever, which is indistinguishable
  // from a sweep that found something and trains a reviewer to ignore the
  // verdict. LOWs are still recorded in full, and still ship a `br create` line.
  const blocking = findings.filter((item) => item.severity !== "LOW");
  const verdict = blocking.length ? "findings" : "clean";
  const reviewer = options.reviewer || process.env.FLYWHEEL_AGENT_ID || "human:unattributed";
  if (!IDENTITY.test(reviewer)) throw new Error(`reviewer identity must match ${IDENTITY}`);
  const runId = runtime.runId || crypto.randomBytes(16).toString("hex");
  if (!RUN_ID.test(runId)) throw new Error("run id must be 32 lowercase hex characters");
  const completedAtUtc = (runtime.now || new Date()).toISOString();
  // The ledger contract requires findingRefs to be empty exactly when the
  // outcome is clean, so the refs track the blocking set, not every LOW note.
  const findingRefs = [...new Set(blocking.map((item) => `${item.code}:${item.commit.slice(0, 12)}`))];
  if (findingRefs.some((ref) => !FINDING_REF.test(ref))) throw new Error("finding reference is not contract-shaped");
  const reviewedCommitShas = commits.map((commit) => commit.sha.toLowerCase());
  const base = path.join(outDir, `${completedAtUtc.slice(0, 10)}-${head.slice(0, 12)}`);

  const receipt = {
    schema: SCHEMA,
    // The control plane's flywheel-source-observation-receipt-v1 review-sweep
    // contract (flywheel-operations/scripts/source-observation.mjs) reads these
    // exact field names, so a receipt can be lifted into the ledger unchanged.
    observationKind: "review-sweep",
    runId,
    targetSlug: slug,
    reviewerIdentity: reviewer,
    completedAtUtc,
    observedMainSha: head,
    reviewedCommitShas,
    outcome: verdict,
    findingRefs,
    promotionAuthorized: false,
    // A sweep whose range is empty has no reviewed commits, and the ledger
    // contract requires a non-empty set containing the observed head, so it is
    // an honest local record rather than ledger input.
    ledgerEligible: reviewedCommitShas.includes(head),
    head_sha: head,
    since_sha: since.sha,
    since_source: since.source,
    since_rejected_receipts: since.rejectedReceipts,
    verdict,
    beadStore: options.db || null,
    criticalPathGlobs: globs,
    // Add explainability only when a file matched, preserving receipts with no
    // critical paths byte-for-byte. Existing v1 fields retain their meaning.
    ...(commits.some((commit) => commit.files.some((file) => file.critical_path))
      ? { criticalPathFence: { source: "AGENTS.md", globCount: globs.length } } : {}),
    reportPath: `${path.basename(base)}.md`,
    commits: commits.map((commit) => ({
      sha: commit.sha,
      short_sha: commit.short_sha,
      author: commit.author,
      author_email: commit.author_email,
      committer: commit.committer,
      committer_email: commit.committer_email,
      date: commit.date,
      subject: commit.subject,
      route: commit.route,
      route_evidence: commit.route_evidence,
      merge: commit.merge,
      parents: commit.parents,
      merged_commits: commit.merged_commits || 0,
      merged_truncated: Boolean(commit.merged_truncated),
      identity: commit.identity,
      identities: commit.identities,
      identity_class: commit.identity_class,
      identity_duplicated: commit.identity_duplicated,
      guard_trailers: commit.guard_trailers,
      ci_status_trailers: commit.ci_status_trailers,
      beads: commit.beads,
      no_bead_declarations: commit.no_bead_declarations,
      malformed_beads: commit.malformed_beads,
      skip_ci: commit.skip_ci,
      size_flag: commit.size_flag,
      files_changed: commit.files_changed,
      lines_changed: commit.lines_changed,
      files: commit.files,
      stat: commit.stat,
      reviewer_note: commit.reviewer_note,
    })),
    findings,
    queuedBeadCommands: beadCommands(findings, options.db),
  };

  const markdown = render(receipt);
  const written = [];
  if (!options.dryRun) {
    fs.mkdirSync(outDir, { recursive: true });
    const jsonPath = `${base}.json`;
    const markdownPath = `${base}.md`;
    // Re-running a sweep for a head already swept today is an ordinary thing to
    // do — a nightly job firing twice, a reviewer repeating the command. It is
    // not an error, and it must never overwrite a receipt someone has already
    // annotated. Check the pair before opening either member so a partial pair
    // is rejected without creating its missing peer; `wx` remains the race-safe
    // backstop if another writer arrives after this check.
    if (fs.existsSync(jsonPath) || fs.existsSync(markdownPath)) {
      const existingPath = fs.existsSync(markdownPath) ? markdownPath : jsonPath;
      return { receipt, markdown, written, alreadySwept: existingPath, dryRun: false, outDir, exitCode: 3 };
    }
    try {
      writeExclusive(jsonPath, `${JSON.stringify(receipt, null, 2)}\n`);
      writeExclusive(markdownPath, markdown);
    } catch (error) {
      if (error.code === "EEXIST") return { receipt, markdown, written, alreadySwept: markdownPath, dryRun: false, outDir, exitCode: 3 };
      throw error;
    }
    written.push(jsonPath, markdownPath);
  }
  return { receipt, markdown, written, alreadySwept: "", dryRun: options.dryRun, outDir, exitCode: blocking.length ? 2 : 0 };
}

export {
  analyze, beadCommands, beadLookup, classifyRoute, commitFacts, criticalPathGlobs, firstMatchingGlob, flipCommit, globToRegExp,
  latestReceiptHead, matchesAnyGlob, parseCommit, parseOptions, receiptRejection, render, requireNativeBr, run,
  selectReceipt, trailerBlock, trailerValues,
};

// process.argv[1] is undefined when this module is imported by a runtime that
// did not launch from a file (a REPL, an embedder). pathToFileURL(undefined)
// throws, so importing the module for its exports would crash on the import.
const entryPoint = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";

if (import.meta.url === entryPoint) {
  try {
    const result = run(process.argv.slice(2));
    if (result.alreadySwept) console.error(`review-sweep: already swept for this head; ${result.alreadySwept} exists and was left untouched`);
    console.log(JSON.stringify({
      verdict: result.receipt.verdict,
      head_sha: result.receipt.head_sha,
      since_sha: result.receipt.since_sha,
      commits: result.receipt.commits.length,
      findings: result.receipt.findings.length,
      blocking: result.receipt.findingRefs.length,
      alreadySwept: Boolean(result.alreadySwept),
      written: result.written,
      dryRun: result.dryRun,
    }));
    process.exitCode = result.exitCode;
  } catch (error) {
    console.error(`review-sweep: ${error.message}`);
    process.exitCode = 1;
  }
}
