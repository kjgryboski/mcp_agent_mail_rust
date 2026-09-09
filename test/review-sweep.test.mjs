import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { trailerBlock as guardTrailerBlock } from "../scripts/flywheel-guard.mjs";
import { beadLookup, classifyRoute, criticalPathGlobs, firstMatchingGlob, globToRegExp, matchesAnyGlob, parseCommit, parseOptions, run, trailerBlock, trailerValues } from "../scripts/review-sweep.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = path.join(ROOT, "scripts", "review-sweep.mjs");
const NOW = new Date("2026-09-02T00:00:00.000Z");
const RUN_ID = "0123456789abcdef0123456789abcdef";
const SCHEMA = "flywheel.review-sweep-receipt.v1";
const SLUG = "owner/fixture-repo";

const AGENTS = [
  "# Fixture manual",
  "",
  "## 9. Critical paths — pull request only",
  "",
  "```",
  ".github/workflows/**",
  "scripts/flywheel-guard.mjs",
  "AGENTS.md",
  "```",
  "",
  "## 10. Something else",
  "",
].join("\n");

// GitHub's web-flow committer, which is what every squash or merge performed by
// GitHub carries. A fixture commit made "by GitHub" sets these.
const GITHUB_ENV = { GIT_COMMITTER_NAME: "GitHub", GIT_COMMITTER_EMAIL: "noreply@github.com" };

function git(dir, args, options = {}) {
  const env = options.env ? { ...process.env, ...options.env } : process.env;
  const result = spawnSync("git", args, { cwd: dir, encoding: "utf8", input: options.input, env });
  if (result.status !== 0 && !options.allowFailure) {
    throw new Error(`git ${args.join(" ")}: ${result.stderr || result.stdout}`);
  }
  return result.stdout;
}

function commit(dir, files, message, options = {}) {
  for (const [file, body] of Object.entries(files)) {
    const target = path.join(dir, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, body);
    git(dir, ["add", "--", file]);
  }
  git(dir, ["commit", "-q", "-F", "-"], { input: message, env: options.github ? GITHUB_ENV : undefined });
  return git(dir, ["rev-parse", "HEAD"]).trim();
}

function fixture() {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "review-sweep-")));
  git(dir, ["init", "-q", "-b", "main"]);
  git(dir, ["config", "user.name", "Fixture"]);
  git(dir, ["config", "user.email", "fixture@example.invalid"]);
  git(dir, ["config", "commit.gpgsign", "false"]);
  git(dir, ["config", "core.hooksPath", path.join(dir, ".nohooks")]);
  git(dir, ["remote", "add", "origin", `https://github.com/${SLUG}.git`]);
  const base = commit(dir, { "AGENTS.md": AGENTS }, "seed: fixture manual");
  return { dir, base };
}

function sweep(dir, argv, runtime = {}) {
  return run(argv, { cwd: dir, now: NOW, runId: RUN_ID, ...runtime });
}

const resolved = (id) => ({ id, state: "resolved", detail: "open" });
const unresolved = (id) => ({ id, state: "unresolved", detail: "not present in the configured shared store" });
const neverLookedUp = (id) => { throw new Error(`beadLookup must not run for ${id}`); };

// Same fixture the guard suite uses: the ELF magic bytes, so requireNativeBr()
// runs for real, while the process itself is injected.
function nativeBrFixture(dir) {
  const binary = path.join(dir, ".fixture-br");
  fs.writeFileSync(binary, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  fs.chmodSync(binary, 0o755);
  return binary;
}

function store(dir) {
  const database = path.join(dir, "beads.db");
  fs.writeFileSync(database, "fixture store");
  return { binary: nativeBrFixture(dir), database };
}

// A complete, coherent receipt for `head` — every field the floor selection
// validates — so a test can break exactly one thing at a time.
function validReceipt(head, at, overrides = {}) {
  return {
    schema: SCHEMA,
    observationKind: "review-sweep",
    runId: RUN_ID,
    targetSlug: SLUG,
    reviewerIdentity: "human:Fixture",
    completedAtUtc: at,
    observedMainSha: head,
    reviewedCommitShas: [head],
    outcome: "clean",
    findingRefs: [],
    promotionAuthorized: false,
    ledgerEligible: true,
    head_sha: head,
    verdict: "clean",
    ...overrides,
  };
}

function writeReceipt(dir, name, value) {
  const outDir = path.join(dir, "docs/agent-runs/review-sweeps");
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, name), `${JSON.stringify(value, null, 2)}\n`);
  return outDir;
}

// br's real exit codes, confirmed against /home/kevin/.local/bin/br:
// 0 found, 3 + ISSUE_NOT_FOUND genuinely absent, 7 + CONFIG_ERROR store broken.
const brFound = (issue) => ({ status: 0, stdout: JSON.stringify([issue]), stderr: "" });
const brNotFound = (id) => ({ status: 3, stdout: JSON.stringify({ error: { code: "ISSUE_NOT_FOUND", message: `Issue not found: ${id}` } }), stderr: "" });
const brConfigError = { status: 7, stdout: JSON.stringify({ error: { code: "CONFIG_ERROR", message: "Could not canonicalize database lock authority parent" } }), stderr: "" };

test("the br invocation pins --db and the no-auto global flags, and reads a real bead", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "review-sweep-br-"));
  const { binary, database } = store(dir);
  const seen = [];
  const runner = (_binary, args) => {
    seen.push(args);
    return brFound({ id: "afc-1", status: "in_progress", source_repo_path: "/home/kevin/flywheel-beads/fixture-repo/authoritative" });
  };
  assert.deepEqual(
    beadLookup(binary, database, "afc-1", SLUG, runner),
    { id: "afc-1", state: "resolved", detail: "in_progress" },
  );
  const args = seen[0];
  // Deleting any of these three from the production argv must fail this test.
  // --db is the split-brain guard: without it br creates a private per-clone
  // store. The no-auto pair is what keeps the sweep read-only.
  assert.deepEqual(args.slice(0, 2), ["--db", database]);
  assert.equal(args.includes("--no-auto-import"), true, "--no-auto-import missing: the sweep would import into the shared store");
  assert.equal(args.includes("--no-auto-flush"), true, "--no-auto-flush missing: the sweep would rewrite the JSONL projection");
  assert.deepEqual(args.slice(-3), ["show", "afc-1", "--json"]);
  assert.equal(args[args.indexOf("--actor") + 1], "review-sweep-v1");
});

test("a broken br is a sweep error, never an absent bead", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "review-sweep-br-broken-"));
  const { binary, database } = store(dir);

  // The whole point: an unreachable store must NOT read as "not present", which
  // would ship a br create command for a bead that may well exist.
  assert.throws(
    () => beadLookup(binary, database, "afc-1", SLUG, () => brConfigError),
    /br show afc-1 failed against .*CONFIG_ERROR/,
  );
  assert.throws(
    () => beadLookup(binary, database, "afc-1", SLUG, () => ({ status: 1, stdout: "", stderr: "database is locked" })),
    /database is locked/,
  );
  assert.throws(
    () => beadLookup(binary, database, "afc-1", SLUG, () => ({ error: new Error("spawn ENOENT") })),
    /br could not be executed/,
  );
  assert.throws(
    () => beadLookup(binary, database, "afc-1", SLUG, () => ({ status: 0, stdout: "not json" })),
    /unparseable json/,
  );

  // Only a real ISSUE_NOT_FOUND is an absent bead.
  assert.deepEqual(beadLookup(binary, database, "afc-404", SLUG, () => brNotFound("afc-404")).state, "unresolved");

  // A Windows br.exe shim cannot read the WSL store; it is refused before it
  // runs. The PE header's NUL bytes are written as escapes: a literal NUL in
  // this source file makes git treat the whole test suite as binary.
  const shim = path.join(dir, "br.exe");
  fs.writeFileSync(shim, "MZ\x00\x00 not an elf");
  let ran = false;
  assert.throws(() => beadLookup(shim, database, "afc-1", SLUG, () => { ran = true; return brFound({}); }), /non-ELF br binary/);
  assert.equal(ran, false, "the ELF check must run before br is spawned");
  assert.throws(() => beadLookup(path.join(dir, "absent"), database, "afc-1", "owner/x", () => brFound({})), /native br binary is missing/);
});

test("a bead homed in another repository is a mismatch, not a resolution", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "review-sweep-br-home-"));
  const { binary, database } = store(dir);
  const foreign = () => brFound({ id: "afc-1", status: "open", source_repo_path: "/home/kevin/flywheel-beads/some-other-repo/authoritative" });
  assert.equal(beadLookup(binary, database, "afc-1", SLUG, foreign).state, "mismatch");
  const weird = () => brFound({ id: "afc-1", status: "banana", source_repo_path: "/home/kevin/flywheel-beads/fixture-repo/authoritative" });
  assert.equal(beadLookup(binary, database, "afc-1", SLUG, weird).state, "mismatch");
});

test("critical-path globs come from the AGENTS.md fence, and the glob matcher is path-segment aware", () => {
  const { dir } = fixture();
  assert.deepEqual(criticalPathGlobs(dir), [".github/workflows/**", "scripts/flywheel-guard.mjs", "AGENTS.md"]);
  assert.equal(globToRegExp(".github/workflows/**").test(".github/workflows/main-status.yml"), true);
  assert.equal(globToRegExp(".github/workflows/**").test(".github/workflows/nested/a.yml"), true);
  assert.equal(globToRegExp("scripts/*.mjs").test("scripts/nested/a.mjs"), false);
  assert.equal(matchesAnyGlob("README.md", [".github/workflows/**", "AGENTS.md"]), false);
  assert.equal(matchesAnyGlob("AGENTS.md", [".github/workflows/**", "AGENTS.md"]), true);
});

test("firstMatchingGlob gives overlapping globs priority in fence order", () => {
  const globs = [".github/**", ".github/workflows/**"];
  const file = ".github/workflows/main-status.yml";
  assert.equal(firstMatchingGlob(file, globs), ".github/**");
  assert.equal(firstMatchingGlob(file, [...globs].reverse()), ".github/workflows/**");
});

test("firstMatchingGlob returns undefined for a non-matching file", () => {
  assert.equal(firstMatchingGlob("README.md", [".github/**", ".github/workflows/**"]), undefined);
});

test("matchesAnyGlob agrees with firstMatchingGlob across fixture paths", () => {
  const { dir } = fixture();
  const globs = criticalPathGlobs(dir);
  for (const file of ["README.md", "AGENTS.md", "scripts/nested/a.mjs", ".github/workflows/nested/a.yml"]) {
    assert.equal(matchesAnyGlob(file, globs), firstMatchingGlob(file, globs) !== undefined, file);
  }
});

// The sweep reads the AGENTS.md fence rather than flywheel.guard.json, because
// the manual is the authority and the config key is explicitly advisory. A
// renumbered section or a reformatted fence would silently leave the sweep with
// zero globs and every direct critical-path commit unflagged, so pin both the
// parse and the agreement with the mirror.
test("this repository's own critical-path fence parses and agrees with the advisory mirror", () => {
  const globs = criticalPathGlobs(ROOT);
  assert.ok(globs.length >= 10, `expected the real critical-path list, got ${JSON.stringify(globs)}`);
  assert.equal(globs.includes("scripts/flywheel-guard.mjs"), true);
  const mirror = JSON.parse(fs.readFileSync(path.join(ROOT, "flywheel.guard.json"), "utf8")).criticalPathGlobs.globs;
  assert.deepEqual(globs, mirror);
});

// Trailers are the trailing trailer-only paragraphs of the message, as git
// defines a trailer block — not any line anywhere that happens to start with
// `Bead:`. The shape the guard actually writes (a worker's `Bead:` paragraph,
// then `Flywheel-Identity:` appended as its OWN paragraph) is the one that must
// parse, because `git interpret-trailers --parse` reads the last paragraph only
// and drops the Bead line from every real worker commit in this program.
test("trailers are parsed from the trailing trailer block, in the shape the guard writes", () => {
  const guardShaped = [
    "docs: record L0 fire drill",
    "",
    "Bead: afc-u2o",
    "",
    "Flywheel-Identity: worker:codex-o03",
    "",
  ].join("\n");
  assert.deepEqual(trailerBlock(guardShaped), [
    { key: "Bead", value: "afc-u2o" },
    { key: "Flywheel-Identity", value: "worker:codex-o03" },
  ]);
  assert.deepEqual(trailerValues(guardShaped, "Bead"), ["afc-u2o"]);
  assert.deepEqual(trailerValues(guardShaped, "flywheel-identity"), ["worker:codex-o03"], "trailer keys are case-insensitive, as in git");

  // Prose is prose. A `Bead:` mentioned in a sentence, or a `Key:` line inside
  // a paragraph that also holds prose, is not a trailer.
  const prose = [
    "review-sweep: parse trailers properly",
    "",
    "Bead: fake-1 is what a prose-quoted id looks like, and this",
    "paragraph also says Flywheel-Identity: worker:nobody in passing.",
    "",
    "Flywheel-Identity: human:Kevin",
  ].join("\n");
  assert.deepEqual(trailerBlock(prose), [{ key: "Flywheel-Identity", value: "human:Kevin" }]);
  assert.deepEqual(trailerValues(prose, "Bead"), []);

  // A last paragraph mixing prose and a trailer line is prose, as git rules.
  assert.deepEqual(trailerBlock("subject\n\nsome prose\nFlywheel-Identity: human:Kevin\n"), []);
  // The subject line is never a trailer, and continuation lines fold.
  assert.deepEqual(trailerBlock("Bead: not-a-trailer\n"), []);
  assert.deepEqual(trailerBlock("subject\n\nCI-Status: unknown (origin/main HEAD\n  is unavailable)\n"), [{ key: "CI-Status", value: "unknown (origin/main HEAD is unavailable)" }]);
  assert.deepEqual(trailerBlock(""), []);
});

test("comment lines inside the trailer region are transparent and agree with the guard", () => {
  const messages = [
    "subject\n\nBead: afc-u2o\n# editor guidance\nFlywheel-Identity: worker:codex-o03\n",
    "subject\n\nBead: afc-u2o\n\n# comment-only paragraph\n\nFlywheel-Identity: worker:codex-o03\n",
    "subject\n\nBead: afc-u2o\n# trailing editor guidance\n",
  ];
  for (const message of messages) {
    assert.deepEqual(trailerBlock(message), guardTrailerBlock(message), JSON.stringify(message));
  }
  assert.deepEqual(trailerBlock(messages[0]), [
    { key: "Bead", value: "afc-u2o" },
    { key: "Flywheel-Identity", value: "worker:codex-o03" },
  ]);
});

test("a Bead: id quoted in prose never reaches br, and needs no --db", () => {
  const { dir, base } = fixture();
  const sha = commit(dir, { "docs/prose.md": "p\n" }, [
    "docs: talk about a bead without citing one",
    "",
    "Earlier work used Bead: afc-old for this; see the ledger. That line is",
    "prose, and a real br show against it would fail the nightly sweep on a",
    "store error for an id nobody cited.",
    "",
    "Flywheel-Identity: human:Kevin",
  ].join("\n"));
  // No --db: a prose-only mention must not make the store mandatory either.
  const result = sweep(dir, ["--since", base, "--dry-run"], { beadLookup: neverLookedUp });
  const row = result.receipt.commits.find((item) => item.sha === sha);
  assert.deepEqual(row.beads, [], "no bead id was cited, so nothing was looked up");
  assert.equal(row.identity_class, "human");
  assert.equal(result.receipt.findings.some((item) => item.code.includes("bead")), false);
});

test("route: two parents, or a PR subject committed by GitHub, is pull-request; a claimed subject on a local commit is direct", () => {
  assert.equal(classifyRoute("anything at all", ["p1", "p2"], "fixture@example.invalid").route, "pull-request");
  assert.equal(classifyRoute("guard: squash (#12)", ["p1"], "noreply@github.com").route, "pull-request");
  assert.equal(classifyRoute("Merge pull request #12 from x/y", ["p1"], "NoReply@GitHub.com").route, "pull-request");
  const spoofed = classifyRoute("ci: sneaky (#13)", ["p1"], "fixture@example.invalid");
  assert.equal(spoofed.route, "direct");
  assert.match(spoofed.route_evidence, /subject claims a pull-request route but the committer is not GitHub/);
  assert.equal(classifyRoute("docs: plain", ["p1"], "noreply@github.com").route, "direct", "a GitHub committer without a PR subject is not evidence of review");
  assert.equal(classifyRoute("docs: plain", [], "fixture@example.invalid").route, "direct");
});

test("trailered worker commits are clean where untrailered ones are findings", () => {
  const { dir, base } = fixture();
  const trailered = commit(dir, { "docs/a.md": "a\n" }, [
    "docs: trailered worker commit",
    "",
    "Flywheel-Identity: worker:codex-o01",
    "Bead: fix-001",
  ].join("\n"));
  const bare = commit(dir, { "docs/b.md": "b\n" }, "docs: no trailers at all");

  const result = sweep(dir, ["--since", base, "--db", path.join(dir, "AGENTS.md"), "--dry-run"], {
    beadLookup: resolved,
  });
  const codes = (sha) => result.receipt.findings.filter((item) => item.commit === sha).map((item) => item.code);
  assert.deepEqual(codes(trailered), []);
  assert.deepEqual(codes(bare), ["missing-identity"]);
  const row = result.receipt.commits.find((item) => item.sha === trailered);
  assert.equal(row.identity_class, "worker");
  assert.deepEqual(row.beads, [resolved("fix-001")]);
  assert.equal(row.reviewer_note, "");
  assert.equal(result.receipt.verdict, "findings");
  assert.equal(result.exitCode, 2);
});

test("a receipt without critical paths preserves the existing JSON and Markdown", () => {
  const { dir, base } = fixture();
  const sha = commit(dir, { "docs/plain.md": "plain\n" }, "docs: plain landing\n\nFlywheel-Identity: human:Fixture\n");
  const result = sweep(dir, ["--since", base, "--reviewer", "human:Reviewer", "--dry-run"]);
  const normalize = (value) => value
    .replaceAll(sha, "<head>").replaceAll(base, "<base>")
    .replaceAll(sha.slice(0, 12), "<head-short>").replaceAll(base.slice(0, 12), "<base-short>")
    .replaceAll(result.receipt.commits[0].date, "<commit-date>");
  const digest = (value) => crypto.createHash("sha256").update(normalize(value)).digest("hex");
  // Baselines captured before adding glob explainability; only Git's variable
  // commit hashes and date are normalized, not any receipt field or evidence.
  assert.deepEqual({
    json: digest(JSON.stringify(result.receipt)),
    markdown: digest(result.markdown),
  }, {
    json: "507ae70e18b555417d8a148d4f34081b961d7dc23959e0add4cb52a1ecce0fd1",
    markdown: "e4efdd26d7815a8bf0895e1cebc18fdd0fab310cdd783f125937b18422d45ca5",
  });
});

test("documented CI skip tokens in the body are HIGH", () => {
  for (const token of ["[skip ci]", "[ci skip]", "[no ci]", "[skip actions]", "[actions skip]"]) {
    const { dir, base } = fixture();
    const sha = commit(dir, { "docs/c.md": "c\n" }, [
      "docs: quiet landing",
      "",
      `Skipping the sentinel because it is slow ${token}`,
      "",
      "Flywheel-Identity: human:Kevin",
    ].join("\n"));
    const result = sweep(dir, ["--since", base, "--dry-run"]);
    const item = result.receipt.findings.find((finding) => finding.code === "skip-ci-token");
    assert.equal(item?.severity, "HIGH", token);
    assert.equal(item.commit, sha, token);
    assert.equal(result.receipt.commits[0].skip_ci, true, token);
  }
});

test("a pull-request-only path landed direct is HIGH; the same path via a GitHub squash merge is not", () => {
  const { dir, base } = fixture();
  const direct = commit(dir, { ".github/workflows/main-status.yml": "name: x\n" }, [
    "ci: land a workflow straight onto main",
    "",
    "Flywheel-Identity: human:Kevin",
  ].join("\n"));
  const routed = commit(dir, { "scripts/flywheel-guard.mjs": "// guard\n" }, [
    "guard: land the guard through review (#42)",
    "",
    "Flywheel-Identity: human:Kevin",
  ].join("\n"), { github: true });

  const result = sweep(dir, ["--since", base, "--dry-run"]);
  const codes = (sha) => result.receipt.findings.filter((item) => item.commit === sha).map((item) => item.code);
  assert.deepEqual(codes(direct), ["critical-path-direct"]);
  assert.equal(result.receipt.findings.find((item) => item.commit === direct).severity, "HIGH");
  assert.deepEqual(codes(routed), []);
  assert.equal(result.receipt.commits.find((item) => item.sha === routed).route, "pull-request");
  assert.equal(result.receipt.commits.find((item) => item.sha === direct).files[0].critical_path, true);
});

test("critical-path evidence names the first matching fence glob without truncating files", () => {
  const { dir } = fixture();
  const manual = AGENTS.replace(".github/workflows/**", ".github/**\n.github/workflows/**");
  const base = commit(dir, { "AGENTS.md": manual }, "docs: overlapping fixture globs");
  const files = Object.fromEntries(Array.from({ length: 12 }, (_, index) => [
    `.github/workflows/long-workflow-name-${index}.yml`, "name: fixture\n",
  ]));
  files["scripts/flywheel-guard.mjs"] = "// fixture\n";
  files["docs/plain.md"] = "plain\n";
  const sha = commit(dir, files, "ci: fixture direct landing\n\nFlywheel-Identity: human:Fixture\n");
  const result = sweep(dir, ["--since", base, "--reviewer", "human:Reviewer"]);
  const receipt = JSON.parse(fs.readFileSync(result.written.find((file) => file.endsWith(".json")), "utf8"));
  assert.equal(receipt.schema, SCHEMA);
  assert.deepEqual(receipt.criticalPathFence, { source: "AGENTS.md", globCount: 4 });
  assert.match(result.markdown.split("## Commits")[0], /Critical-path fence: `AGENTS.md` \(4 globs\)/);
  const finding = receipt.findings.find((item) => item.code === "critical-path-direct");
  assert.equal(finding.severity, "HIGH");
  assert.equal(finding.commit, sha);
  const globs = criticalPathGlobs(dir);
  for (const file of receipt.commits[0].files) {
    const matchedGlob = firstMatchingGlob(file.path, globs);
    if (file.critical_path) assert.equal(file.critical_path_glob, matchedGlob, file.path);
    else assert.equal(matchedGlob, undefined, file.path);
    if (file.path === "docs/plain.md") {
      assert.deepEqual(file, { path: file.path, added: 1, deleted: 0, critical_path: false });
      assert.equal(finding.evidence.includes(file.path), false);
      continue;
    }
    const expected = file.path.startsWith(".github/") ? ".github/**" : "scripts/flywheel-guard.mjs";
    assert.equal(file.critical_path, true);
    assert.equal(file.critical_path_glob, expected);
    const evidence = `${file.path} (matched by ${expected})`;
    assert.ok(finding.evidence.includes(evidence), evidence);
    assert.ok(result.markdown.includes(evidence), evidence);
  }
  assert.ok(finding.evidence.length > 200, "exercise the never-truncate evidence contract");
  // The additive provenance and per-file fields remain usable as a v1 floor.
  const next = sweep(dir, ["--reviewer", "human:Reviewer", "--dry-run"]);
  assert.equal(next.receipt.since_sha, sha);
  assert.deepEqual(next.receipt.since_rejected_receipts, []);
});

test("review-sweep receipt paths changed directly are HIGH; pull-request routed changes are not", () => {
  const { dir, base } = fixture();
  const direct = commit(dir, { "docs/agent-runs/review-sweeps/direct.json": "{}\n" }, [
    "docs: alter a review-sweep receipt directly",
    "",
    "Flywheel-Identity: human:Kevin",
  ].join("\n"));
  const routed = commit(dir, { "docs/agent-runs/review-sweeps/routed.json": "{}\n" }, [
    "docs: alter a review-sweep receipt through review (#43)",
    "",
    "Flywheel-Identity: human:Kevin",
  ].join("\n"), { github: true });

  const result = sweep(dir, ["--since", base, "--dry-run"]);
  const directFinding = result.receipt.findings.find((item) => item.commit === direct && item.code === "receipt-touched-direct");
  assert.equal(directFinding?.severity, "HIGH");
  assert.match(directFinding.evidence, /docs\/agent-runs\/review-sweeps\/direct\.json/);
  assert.equal(result.receipt.findings.some((item) => item.commit === routed && item.code === "receipt-touched-direct"), false);
});

// The subject suffix is one keystroke away from anyone. `ci: sneaky (#13)` made
// in a clone and pushed straight to main used to escape critical-path-direct
// entirely; the committer is what GitHub cannot be talked into faking.
test("a PR-shaped subject on a locally committed single-parent commit does not exempt a critical path", () => {
  const { dir, base } = fixture();
  const sneaky = commit(dir, { ".github/workflows/sentinel.yml": "name: sneaky\n" }, [
    "ci: sneaky (#13)",
    "",
    "Flywheel-Identity: human:Kevin",
  ].join("\n"));
  const result = sweep(dir, ["--since", base, "--dry-run"]);
  const row = result.receipt.commits.find((item) => item.sha === sneaky);
  assert.equal(row.route, "direct");
  assert.equal(row.committer_email, "fixture@example.invalid");
  const item = result.receipt.findings.find((finding) => finding.code === "critical-path-direct");
  assert.equal(item?.severity, "HIGH");
  assert.match(item.evidence, /subject claims a pull-request route but the committer is not GitHub/);
  assert.match(item.evidence, /\.github\/workflows\/sentinel\.yml/);
  assert.equal(result.exitCode, 2);
});

test("a missing identity trailer is MEDIUM on the direct route and LOW on the pull-request route", () => {
  const { dir, base } = fixture();
  const direct = commit(dir, { "docs/x.md": "x\n" }, "docs: untrailered direct commit");
  const routed = commit(dir, { "docs/y.md": "y\n" }, "docs: untrailered squash merge (#9)", { github: true });
  const result = sweep(dir, ["--since", base, "--dry-run"]);
  const at = (sha) => result.receipt.findings.find((item) => item.commit === sha);
  assert.equal(at(direct).code, "missing-identity");
  assert.equal(at(direct).severity, "MEDIUM");
  assert.equal(at(routed).code, "missing-identity-pr-route");
  assert.equal(at(routed).severity, "LOW");
});

test("an unresolved bead id is a finding, and the shared store is mandatory when a Bead trailer exists", () => {
  const { dir, base } = fixture();
  const sha = commit(dir, { "docs/d.md": "d\n" }, [
    "docs: cite a bead that is not in the store",
    "",
    "Flywheel-Identity: worker:codex-o01",
    "Bead: afc-nope",
  ].join("\n"));

  assert.throws(() => sweep(dir, ["--since", base, "--dry-run"]), /--db <shared store path> is required/);

  const result = sweep(dir, ["--since", base, "--db", path.join(dir, "AGENTS.md"), "--dry-run"], {
    beadLookup: unresolved,
  });
  const item = result.receipt.findings.find((finding) => finding.code === "unresolved-bead");
  assert.equal(item.severity, "MEDIUM");
  assert.equal(item.commit, sha);
  assert.match(item.evidence, /afc-nope/);
  assert.deepEqual(result.receipt.findingRefs, [`unresolved-bead:${sha.slice(0, 12)}`]);
  assert.equal(result.receipt.queuedBeadCommands.length, 1);
  assert.match(result.receipt.queuedBeadCommands[0], /-l flywheel-queue/);
});

test("--since defaults to the Flip-Commit recorded in docs/flip-evidence/", () => {
  const { dir, base } = fixture();
  commit(dir, { "docs/flip-evidence/2026-09-01-flip.md": `- **Flip-Commit:** \`${base}\`\n` }, "docs: record the flip commit");
  const after = commit(dir, { "docs/e.md": "e\n" }, "docs: after the flip");

  const result = sweep(dir, ["--dry-run"]);
  assert.equal(result.receipt.since_sha, base);
  assert.equal(result.receipt.since_source, "flip-evidence");
  assert.equal(result.receipt.head_sha, after);
  assert.equal(result.receipt.commits.length, 2);
});

test("--since defaults to the head of the most recent receipt, and a receipt is written per run", () => {
  const { dir, base } = fixture();
  const first = commit(dir, { "docs/f.md": "f\n" }, "docs: first landing");
  const one = sweep(dir, ["--since", base]);
  assert.equal(one.written.length, 2);
  assert.equal(one.receipt.head_sha, first);
  assert.equal(fs.existsSync(path.join(dir, "docs/agent-runs/review-sweeps", "2026-09-02-" + first.slice(0, 12) + ".json")), true);

  const second = commit(dir, { "docs/g.md": "g\n" }, "docs: second landing");
  const two = sweep(dir, [], { runId: "fedcba9876543210fedcba9876543210" });
  assert.equal(two.receipt.since_sha, first);
  assert.equal(two.receipt.since_source, "previous-receipt");
  assert.deepEqual(two.receipt.since_rejected_receipts, []);
  assert.deepEqual(two.receipt.reviewedCommitShas, [second]);
});

// The program merges with merge commits, so this is the shape the receipt will
// actually meet. GitHub writes the merge message and it carries none of the
// branch's trailers; reading only that message reports a merged pull request
// as beadless and unattributable — silence that reads as clean.
test("a merge commit's trailers come from the branch it merged; [skip ci] does not, because only the merge's own message could suppress CI", () => {
  const { dir, base } = fixture();
  git(dir, ["checkout", "-q", "-b", "feature", base]);
  commit(dir, { "docs/feature.md": "feature\n" }, [
    "feat: the real work, with the real trailers",
    "",
    "The guard rejects a [skip ci] token, and this sentence quotes one — the",
    "way this branch's own commits do when they describe the check.",
    "",
    "Flywheel-Identity: worker:codex-o01",
    "Bead: afc-123",
  ].join("\n"));
  git(dir, ["checkout", "-q", "main"]);
  git(dir, ["merge", "-q", "--no-ff", "feature", "-m", "Merge pull request #42 from kjgryboski/feature"], { env: GITHUB_ENV });
  const merge = git(dir, ["rev-parse", "HEAD"]).trim();

  const result = sweep(dir, ["--since", base, "--db", path.join(dir, "AGENTS.md"), "--dry-run"], { beadLookup: resolved });
  const row = result.receipt.commits.find((item) => item.sha === merge);
  assert.equal(row.merge, true);
  assert.equal(row.parents.length, 2);
  assert.equal(row.merged_commits, 1);
  assert.equal(row.merged_truncated, false);
  assert.equal(row.route, "pull-request");
  assert.deepEqual(row.beads, [resolved("afc-123")]);
  assert.equal(row.identity_class, "worker");
  // Trailers were found, so none of the "missing" findings may fire.
  assert.equal(result.receipt.findings.some((item) => item.code.startsWith("missing-")), false);
  // The token lives in a branch commit's prose. The push that landed the merge
  // had the merge commit as its head, whose message carries no token, so CI
  // ran. Folding the branch bodies here produced a HIGH on this very branch's
  // simulated merge, whose commits discuss the token by name.
  assert.equal(row.skip_ci, false, "a token in a merged branch commit did not suppress CI for the merge");
  assert.equal(result.receipt.findings.some((item) => item.code === "skip-ci-token"), false);
  assert.equal(result.receipt.verdict, "clean");
});

test("a [skip ci] token in the merge commit's own message is still HIGH", () => {
  const { dir, base } = fixture();
  git(dir, ["checkout", "-q", "-b", "feature", base]);
  commit(dir, { "docs/feature.md": "feature\n" }, "feat: ordinary branch commit\n\nFlywheel-Identity: human:Kevin\n");
  git(dir, ["checkout", "-q", "main"]);
  git(dir, ["merge", "-q", "--no-ff", "feature", "-m", "Merge feature quietly [skip ci]"]);
  const merge = git(dir, ["rev-parse", "HEAD"]).trim();
  const result = sweep(dir, ["--since", base, "--dry-run"]);
  const row = result.receipt.commits.find((item) => item.sha === merge);
  assert.equal(row.skip_ci, true);
  const item = result.receipt.findings.find((finding) => finding.code === "skip-ci-token");
  assert.equal(item?.severity, "HIGH");
  assert.equal(item.commit, merge);
});

// `diff-tree -m --first-parent` emitted one diff per parent, so a merge's
// receipt row double-counted: the second parent's diff is everything `main`
// gained since the branch point, and it was attributed to this merge. Both
// parent diffs are non-empty here on purpose; the row must show only what the
// merge brought onto main.
test("a merge commit's files are its diff against its first parent only", () => {
  const { dir, base } = fixture();
  git(dir, ["checkout", "-q", "-b", "feature", base]);
  const branchCommit = commit(dir, { "docs/feature.md": "one\ntwo\nthree\n" }, "feat: three lines on the branch\n\nFlywheel-Identity: human:Kevin\n");
  git(dir, ["checkout", "-q", "main"]);
  // main moves on after the branch point: a previous pull request's work.
  const previous = commit(dir, { "AGENTS.md": `${AGENTS}\n## 11. Landed on main first\n\nfive\nlines\nof\nprose\nhere\n` }, "docs: previous PR, on main before the merge (#41)", { github: true });
  git(dir, ["merge", "-q", "--no-ff", "feature", "-m", "Merge pull request #42 from kjgryboski/feature"], { env: GITHUB_ENV });
  const merge = git(dir, ["rev-parse", "HEAD"]).trim();
  assert.notEqual(git(dir, ["diff", "--stat", `${merge}^2`, merge]).trim(), "", "fixture: the second-parent diff must be non-empty");

  const result = sweep(dir, ["--since", base, "--dry-run"]);
  const row = result.receipt.commits.find((item) => item.sha === merge);
  assert.deepEqual(row.files.map((file) => file.path), ["docs/feature.md"], "AGENTS.md belongs to #41, not to this merge");
  assert.equal(row.files_changed, 1);
  assert.equal(row.lines_changed, 3);
  assert.equal(row.stat.filter((line) => line.includes("AGENTS.md")).length, 0);
  assert.equal(row.stat.filter((line) => line.includes("docs/feature.md")).length, 1, "one stat line per file, not one per parent");
  // The previous PR still owns its own row.
  const previousRow = result.receipt.commits.find((item) => item.sha === previous);
  assert.deepEqual(previousRow.files.map((file) => file.path), ["AGENTS.md"]);
  // Sanity: a branch commit's own row shape is unchanged by the two-tree form.
  assert.equal(git(dir, ["rev-parse", `${merge}^2`]).trim(), branchCommit);
});

// A parentless commit can only enter a range through an unrelated-history
// merge: --since is main's base, HEAD is a merge whose FIRST parent is an
// orphan root, so the first-parent walk is [merge, root]. The root diffs
// against the empty tree; the merge diffs against the root.
test("a root commit in range diffs against the empty tree", () => {
  const { dir, base } = fixture();
  const onMain = commit(dir, { "docs/m.md": "m\n" }, "docs: on main\n\nFlywheel-Identity: human:Kevin\n");
  git(dir, ["checkout", "-q", "--orphan", "orphan"]);
  git(dir, ["rm", "-rfq", "--cached", "."]);
  fs.rmSync(path.join(dir, "docs"), { recursive: true });
  const root = commit(dir, { "AGENTS.md": AGENTS, "docs/root.md": "r\n" }, "seed: orphan root\n\nFlywheel-Identity: human:Kevin\n");
  git(dir, ["merge", "-q", "--allow-unrelated-histories", "--no-ff", "main", "-m", "Merge main\n\nFlywheel-Identity: human:Kevin\n"]);
  const head = git(dir, ["rev-parse", "HEAD"]).trim();
  const result = sweep(dir, ["--since", base, "--dry-run"]);
  assert.deepEqual(result.receipt.commits.map((item) => item.sha), [head, root]);
  const rootRow = result.receipt.commits[1];
  assert.deepEqual(rootRow.parents, []);
  assert.deepEqual(rootRow.files.map((file) => file.path).sort(), ["AGENTS.md", "docs/root.md"]);
  const mergeRow = result.receipt.commits[0];
  assert.deepEqual(mergeRow.files.map((file) => file.path), ["docs/m.md"], "the merge's own diff is what main brought to the orphan line");
  assert.equal(onMain.length, 40);
});

test("two parents mean pull-request route even with no PR subject at all", () => {
  const { dir, base } = fixture();
  git(dir, ["checkout", "-q", "-b", "side", base]);
  commit(dir, { "scripts/flywheel-guard.mjs": "// guard\n" }, "guard: work on a branch");
  git(dir, ["checkout", "-q", "main"]);
  git(dir, ["merge", "-q", "--no-ff", "side", "-m", "just some merge"]);
  const merge = git(dir, ["rev-parse", "HEAD"]).trim();
  const result = sweep(dir, ["--since", base, "--dry-run"]);
  const row = result.receipt.commits.find((item) => item.sha === merge);
  assert.equal(row.route, "pull-request", "parent count is structural; it must not depend on the subject");
  assert.equal(result.receipt.findings.some((item) => item.code === "critical-path-direct"), false);
});

// A squashed merge lands GitHub's subject on a SINGLE-parent commit, where the
// parent count says nothing. The subject rule plus the GitHub committer is what
// carries that case — and the committer is what a spoofed subject lacks.
test("a single-parent commit with a merge subject is pull-request routed only when GitHub committed it", () => {
  const { dir, base } = fixture();
  const squashed = commit(dir, { "scripts/flywheel-guard.mjs": "// guard\n" }, [
    "Merge pull request #42 from kjgryboski/feature",
    "",
    "guard: work that reached main through review",
  ].join("\n"), { github: true });
  const result = sweep(dir, ["--since", base, "--dry-run"]);
  const row = result.receipt.commits.find((item) => item.sha === squashed);
  assert.equal(row.parents.length, 1);
  assert.equal(row.merge, false);
  assert.equal(row.route, "pull-request");
  assert.equal(row.committer_email, "noreply@github.com");
  assert.equal(
    result.receipt.findings.some((item) => item.code === "critical-path-direct"),
    false,
    "dropping the merge-subject rule would flag a reviewed change as an unreviewed direct commit",
  );

  const local = commit(dir, { "scripts/flywheel-guard.mjs": "// guard v2\n" }, [
    "Merge pull request #43 from kjgryboski/feature",
    "",
    "guard: same subject, committed in a clone",
  ].join("\n"));
  const again = sweep(dir, ["--since", squashed, "--dry-run"]);
  assert.equal(again.receipt.commits.find((item) => item.sha === local).route, "direct");
  assert.equal(again.receipt.findings.some((item) => item.code === "critical-path-direct" && item.commit === local), true);
});

test("reading a merge through is bounded, and hitting the bound is recorded as a LOW finding", () => {
  const { dir, base } = fixture();
  git(dir, ["checkout", "-q", "-b", "feature", base]);
  for (let index = 0; index < 4; index += 1) {
    commit(dir, { [`docs/f${index}.md`]: `${index}\n` }, `feat: branch commit ${index}\n\nFlywheel-Identity: worker:codex-o01\nBead: afc-${index}\n`);
  }
  git(dir, ["checkout", "-q", "main"]);
  git(dir, ["merge", "-q", "--no-ff", "feature", "-m", "Merge pull request #50 from kjgryboski/feature"], { env: GITHUB_ENV });
  const merge = git(dir, ["rev-parse", "HEAD"]).trim();

  const unbounded = sweep(dir, ["--since", base, "--db", path.join(dir, "AGENTS.md"), "--dry-run"], { beadLookup: resolved });
  const full = unbounded.receipt.commits.find((item) => item.sha === merge);
  assert.equal(full.merged_commits, 4);
  assert.equal(full.merged_truncated, false);
  assert.deepEqual(full.beads.map((bead) => bead.id).sort(), ["afc-0", "afc-1", "afc-2", "afc-3"]);

  const bounded = sweep(dir, ["--since", base, "--db", path.join(dir, "AGENTS.md"), "--dry-run"], { beadLookup: resolved, mergedBodyLimit: 2 });
  const row = bounded.receipt.commits.find((item) => item.sha === merge);
  assert.equal(row.merged_commits, 2);
  assert.equal(row.merged_truncated, true);
  assert.equal(row.beads.length, 2, "only the commits within the bound are read");
  const item = bounded.receipt.findings.find((finding) => finding.code === "merge-evidence-truncated");
  assert.equal(item?.severity, "LOW");
  assert.equal(item.commit, merge);
  assert.equal(bounded.receipt.verdict, "clean", "a LOW does not decide the verdict");
});

test("the verdict is decided by HIGH and MEDIUM only; LOW findings are recorded but never block", () => {
  const { dir, base } = fixture();
  // A squash-merged pull request: LOW missing-identity-pr-route plus LOW oversized.
  commit(dir, { "docs/big.md": `${"line\n".repeat(500)}` }, "docs: a large squash merge (#7)", { github: true });
  const low = sweep(dir, ["--since", base, "--dry-run"]);
  assert.equal(low.receipt.findings.length, 2);
  assert.equal(low.receipt.findings.every((item) => item.severity === "LOW"), true);
  assert.equal(low.receipt.verdict, "clean");
  assert.equal(low.receipt.outcome, "clean");
  assert.deepEqual(low.receipt.findingRefs, [], "the ledger contract requires empty refs when the outcome is clean");
  assert.equal(low.exitCode, 0);
  assert.equal(low.receipt.queuedBeadCommands.length, 2, "LOW findings are still queued for a human to judge");

  // One MEDIUM flips it.
  commit(dir, { "docs/direct.md": "d\n" }, "docs: untrailered direct commit");
  const blocking = sweep(dir, ["--since", base, "--dry-run"]);
  assert.equal(blocking.receipt.verdict, "findings");
  assert.equal(blocking.receipt.findingRefs.length, 1);
  assert.equal(blocking.exitCode, 2);
});

test("re-sweeping a head already swept today is exit 3 and never overwrites the receipt", () => {
  const { dir, base } = fixture();
  commit(dir, { "docs/z.md": "z\n" }, "docs: a landing");
  const first = sweep(dir, ["--since", base]);
  assert.equal(first.written.length, 2);
  const receiptPath = first.written[1];
  fs.appendFileSync(receiptPath, "\n**Reviewer note:** I read this and it is fine.\n");
  const annotated = fs.readFileSync(receiptPath, "utf8");

  const again = sweep(dir, ["--since", base], { runId: "aaaabbbbccccddddaaaabbbbccccdddd" });
  assert.equal(again.exitCode, 3);
  assert.deepEqual(again.written, []);
  assert.match(again.alreadySwept, /\.md$/);
  assert.equal(fs.readFileSync(receiptPath, "utf8"), annotated, "a reviewer's annotation must survive a re-run");
});

test("a partial pre-existing receipt pair is rejected without creating its missing peer", () => {
  for (const existingExtension of ["json", "md"]) {
    const { dir, base } = fixture();
    const head = commit(dir, { "docs/z.md": "z\n" }, "docs: a landing");
    const outDir = path.join(dir, "docs/agent-runs/review-sweeps");
    fs.mkdirSync(outDir, { recursive: true });
    const receiptBase = path.join(outDir, `${NOW.toISOString().slice(0, 10)}-${head.slice(0, 12)}`);
    const existing = `${receiptBase}.${existingExtension}`;
    const missing = `${receiptBase}.${existingExtension === "json" ? "md" : "json"}`;
    fs.writeFileSync(existing, "existing receipt member\n");

    const result = sweep(dir, ["--since", base]);

    assert.equal(result.exitCode, 3, existingExtension);
    assert.deepEqual(result.written, [], existingExtension);
    assert.equal(fs.readFileSync(existing, "utf8"), "existing receipt member\n", existingExtension);
    assert.equal(fs.existsSync(missing), false, `${existingExtension}: missing peer must stay absent`);
  }
});

test("--since from a prior receipt follows completedAtUtc, not the filename", () => {
  const { dir } = fixture();
  const first = commit(dir, { "docs/one.md": "1\n" }, "docs: one");
  const second = commit(dir, { "docs/two.md": "2\n" }, "docs: two");
  // Same day, and the NEWER sweep sorts first by filename — which is what a
  // lexical "latest" would get wrong, handing back the older head.
  writeReceipt(dir, "2026-09-02-aaaaaaaaaaaa.json", validReceipt(second, "2026-09-02T10:00:00.000Z"));
  writeReceipt(dir, "2026-09-02-zzzzzzzzzzzz.json", validReceipt(first, "2026-09-02T09:00:00.000Z"));

  const result = sweep(dir, ["--dry-run"]);
  assert.equal(result.receipt.since_sha, second, "the newest sweep by completedAtUtc wins, whatever the filenames sort to");
  assert.equal(result.receipt.since_source, "previous-receipt");
  assert.deepEqual(result.receipt.since_rejected_receipts, []);
});

// The floor decides which commits are never looked at again. A newer receipt
// that is not a complete, coherent record of THIS repository's first-parent
// line must not become the floor, however new it is — each case below is a
// newer candidate that would otherwise silently skip a window of main or
// review a range that never landed. The older valid receipt wins every time.
test("a newer receipt that is not a coherent floor is refused, with its reason on the receipt", () => {
  const { dir } = fixture();
  const first = commit(dir, { "docs/one.md": "1\n" }, "docs: one");
  // A side branch merged in: an ancestor of HEAD, but not on its first-parent line.
  git(dir, ["checkout", "-q", "-b", "side", first]);
  const sideways = commit(dir, { "docs/side.md": "s\n" }, "docs: on a side branch");
  git(dir, ["checkout", "-q", "main"]);
  git(dir, ["merge", "-q", "--no-ff", "side", "-m", "Merge pull request #1 from x/side"], { env: GITHUB_ENV });
  const merged = git(dir, ["rev-parse", "HEAD"]).trim();
  const second = commit(dir, { "docs/two.md": "2\n" }, "docs: two");
  const OLD = "2026-09-02T01:00:00.000Z";
  const NEW = "2026-09-02T02:00:00.000Z";

  const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), "review-sweep-elsewhere-"));
  const foreignFile = path.join(elsewhere, "2026-09-02-symlink-target.json");
  fs.writeFileSync(foreignFile, JSON.stringify(validReceipt(second, NEW)));

  const cases = [
    ["cross-target", validReceipt(second, NEW, { targetSlug: "owner/some-other-repo" }), /targetSlug/],
    ["incomplete", validReceipt(second, NEW, { completedAtUtc: undefined }), /completedAtUtc/],
    ["ledger-ineligible", validReceipt(second, NEW, { ledgerEligible: false }), /ledgerEligible/],
    ["head-mismatched", validReceipt(second, NEW, { observedMainSha: first }), /observedMainSha/],
    ["finding-inconsistent", validReceipt(second, NEW, { findingRefs: ["missing-identity:abcdefabcdef"] }), /findingRefs must be empty/],
    ["verdict-disagrees", validReceipt(second, NEW, { verdict: "findings" }), /verdict/],
    ["reviewed-set-misses-head", validReceipt(second, NEW, { reviewedCommitShas: [first] }), /reviewedCommitShas does not contain/],
    ["off-lineage", validReceipt(sideways, NEW), /not on the current first-parent lineage/],
    ["unknown-sha", validReceipt("f".repeat(40), NEW), /not on the current first-parent lineage/],
    ["wrong-schema", validReceipt(second, NEW, { schema: "flywheel.session-receipt.v1" }), /schema/],
    ["malformed", "{ this is not json", /unparseable json/],
    ["symlinked", null, /symbolic link/],
  ];

  for (const [name, value, reason] of cases) {
    const caseDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), `review-sweep-floor-${name}-`)));
    // Each case gets its own clone so one candidate is tested at a time.
    git(caseDir, ["clone", "-q", dir, "repo"]);
    const repo = path.join(caseDir, "repo");
    git(repo, ["config", "core.hooksPath", path.join(repo, ".nohooks")]);
    git(repo, ["remote", "set-url", "origin", `https://github.com/${SLUG}.git`]);
    const outDir = writeReceipt(repo, "2026-09-02-000000000000.json", validReceipt(first, OLD));
    const candidate = path.join(outDir, "2026-09-02-ffffffffffff.json");
    if (name === "symlinked") fs.symlinkSync(foreignFile, candidate);
    else fs.writeFileSync(candidate, typeof value === "string" ? value : JSON.stringify(value));

    const result = sweep(repo, ["--dry-run"]);
    assert.equal(result.receipt.since_sha, first, `${name}: the newer invalid receipt must not become the floor`);
    assert.equal(result.receipt.since_source, "previous-receipt");
    assert.equal(result.receipt.since_rejected_receipts.length, 1, name);
    assert.equal(result.receipt.since_rejected_receipts[0].file, "2026-09-02-ffffffffffff.json");
    assert.match(result.receipt.since_rejected_receipts[0].reason, reason, name);
    assert.match(result.markdown, /Receipt files refused as the `--since` floor/);
    assert.deepEqual(result.receipt.reviewedCommitShas, [second, merged], `${name}: the range is first..HEAD`);
  }

  // Control: the same newer receipt, valid, IS the floor.
  const control = writeReceipt(dir, "2026-09-02-000000000000.json", validReceipt(first, OLD));
  fs.writeFileSync(path.join(control, "2026-09-02-ffffffffffff.json"), JSON.stringify(validReceipt(second, NEW)));
  const accepted = sweep(dir, ["--dry-run"]);
  assert.equal(accepted.receipt.since_sha, second);
  assert.deepEqual(accepted.receipt.since_rejected_receipts, []);
  assert.deepEqual(accepted.receipt.commits, []);
});

test("--dry-run writes nothing", () => {
  const { dir, base } = fixture();
  commit(dir, { "docs/h.md": "h\n" }, "docs: unreviewed landing");
  const result = sweep(dir, ["--since", base, "--dry-run"]);
  assert.equal(result.dryRun, true);
  assert.deepEqual(result.written, []);
  assert.equal(fs.existsSync(path.join(dir, "docs/agent-runs")), false);
  assert.match(result.markdown, /# Review sweep — owner\/fixture-repo/);
});

test("the receipt carries the control plane's review-sweep contract fields verbatim", () => {
  const { dir, base } = fixture();
  const sha = commit(dir, { "docs/i.md": "i\n" }, [
    "docs: a well-formed landing",
    "",
    "Flywheel-Identity: human:Kevin",
  ].join("\n"));
  const result = sweep(dir, ["--since", base, "--reviewer", "human:Reviewer", "--dry-run"]);
  const receipt = result.receipt;
  assert.equal(receipt.schema, SCHEMA);
  assert.equal(receipt.observationKind, "review-sweep");
  assert.equal(receipt.runId, RUN_ID);
  assert.equal(receipt.targetSlug, SLUG);
  assert.equal(receipt.reviewerIdentity, "human:Reviewer");
  assert.equal(receipt.observedMainSha, receipt.head_sha);
  assert.deepEqual(receipt.reviewedCommitShas, [sha]);
  assert.equal(receipt.reviewedCommitShas.includes(receipt.observedMainSha), true);
  assert.equal(receipt.ledgerEligible, true);
  assert.equal(receipt.outcome, "clean");
  assert.deepEqual(receipt.findingRefs, []);
  assert.equal(receipt.promotionAuthorized, false);
  assert.equal(result.exitCode, 0);
  // A receipt the sweep writes is one the sweep will accept as its next floor.
  const written = sweep(dir, ["--since", base, "--reviewer", "human:Reviewer"]);
  const next = sweep(dir, ["--dry-run"], { runId: "fedcba9876543210fedcba9876543210" });
  assert.equal(next.receipt.since_sha, written.receipt.head_sha);
  assert.deepEqual(next.receipt.since_rejected_receipts, []);
});

test("size flags fire past the review budget and empty ranges stay honest", () => {
  const { dir, base } = fixture();
  commit(dir, { "docs/big.md": `${"line\n".repeat(500)}` }, "docs: a very large landing");
  const large = sweep(dir, ["--since", base, "--dry-run"]);
  assert.equal(large.receipt.commits[0].size_flag, true);
  assert.equal(large.receipt.findings.some((item) => item.code === "oversized-commit"), true);

  const head = git(dir, ["rev-parse", "HEAD"]).trim();
  const empty = sweep(dir, ["--since", head, "--dry-run"]);
  assert.deepEqual(empty.receipt.commits, []);
  assert.equal(empty.receipt.verdict, "clean");
  assert.equal(empty.receipt.ledgerEligible, false);
});

test("the CLI exits 2 on findings, 0 when clean, and 1 on a bad range", () => {
  const { dir, base } = fixture();
  commit(dir, { "docs/j.md": "j\n" }, "docs: no identity trailer");
  const findings = spawnSync(process.execPath, [SCRIPT, "--since", base, "--dry-run"], { cwd: dir, encoding: "utf8" });
  assert.equal(findings.status, 2);
  assert.equal(JSON.parse(findings.stdout).findings, 1);

  const clean = spawnSync(process.execPath, [SCRIPT, "--since", "HEAD", "--dry-run"], { cwd: dir, encoding: "utf8" });
  assert.equal(clean.status, 0);

  const bad = spawnSync(process.execPath, [SCRIPT, "--since", "0".repeat(40), "--dry-run"], { cwd: dir, encoding: "utf8" });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /review-sweep: cannot resolve commit/);

  // A sha that resolves but is not on main's first-parent line is refused too:
  // sweeping it would silently report a range that never landed.
  git(dir, ["checkout", "-q", "-b", "sidebranch", base]);
  const sideways = commit(dir, { "docs/k.md": "k\n" }, "docs: never merged");
  git(dir, ["checkout", "-q", "main"]);
  const offline = spawnSync(process.execPath, [SCRIPT, "--since", sideways, "--dry-run"], { cwd: dir, encoding: "utf8" });
  assert.equal(offline.status, 1);
  assert.match(offline.stderr, /is not an ancestor of/);
});

test("option and trailer parsing refuse malformed input", () => {
  assert.throws(() => parseOptions(["--nope", "x"]), /unknown argument/);
  assert.throws(() => parseOptions(["--repo", "not-a-slug"]), /owner\/name/);
  assert.throws(() => parseOptions(["--since"]), /missing value/);
  assert.deepEqual(parseOptions(["--dry-run", "--repo", "a/b"]).dryRun, true);
  const record = (committerEmail, parents, body) => ["abc", "A", "a@b", "C", committerEmail, "2026-09-01T00:00:00Z", parents, body].join("\0");
  const parsed = parseCommit(record("noreply@github.com", "p1", "subject (#7)\n\nBead: x-1\nBead: x-2\nFlywheel-Identity: worker:o01\n"));
  assert.deepEqual(parsed.bead_ids, ["x-1", "x-2"]);
  assert.equal(parsed.route, "pull-request");
  assert.equal(parsed.identity_class, "worker");
  assert.equal(parsed.committer_email, "noreply@github.com");
  assert.equal(parsed.merge, false);
  const spoofed = parseCommit(record("a@b", "p1", "subject (#7)\n\nFlywheel-Identity: worker:o01\n"));
  assert.equal(spoofed.route, "direct");
  const merged = parseCommit(record("a@b", "p1 p2", "no pr marker at all\n"));
  assert.equal(merged.merge, true);
  assert.equal(merged.route, "pull-request");
});

// The trailer grammar after the fleet's first sweep (control plane,
// fleet-review-sweep-run): `Bead: none (<reason>)` is a declaration the guard
// accepts from human and lane class, `lane:<slug>` is a recognised class, and
// the first recognised identity wins over a later one. The evidence must say
// what is there, not "no trailer" when one is present.
test("`Bead: none (reason)` is a declaration, not an id: nothing is looked up, --db is not required, and the finding is LOW", () => {
  const { dir, base } = fixture();
  const declared = commit(dir, { "docs/n.md": "n\n" }, [
    "ci: run the vendored guard tests",
    "",
    "Flywheel-Identity: human:orchestrator-lane",
    "Bead: none (CI coverage for vendored guard tests)",
  ].join("\n"));
  const bare = commit(dir, { "docs/o.md": "o\n" }, "docs: bare declaration\n\nFlywheel-Identity: human:Kevin\nBead: none\n");
  const capitalized = commit(dir, { "docs/q.md": "q\n" }, "docs: capitalized declaration\n\nFlywheel-Identity: human:Kevin\nBead: None (owner-approved)\n");
  const result = sweep(dir, ["--since", base, "--dry-run"], { beadLookup: neverLookedUp });
  for (const sha of [declared, bare, capitalized]) {
    const row = result.receipt.commits.find((item) => item.sha === sha);
    assert.deepEqual(row.beads, [], "a declaration is never looked up");
    assert.equal(row.identity_class, "human");
    const codes = result.receipt.findings.filter((item) => item.commit === sha).map((item) => [item.severity, item.code]);
    assert.deepEqual(codes, [["LOW", "no-bead-declared"]]);
  }
  assert.deepEqual(result.receipt.commits.find((item) => item.sha === declared).no_bead_declarations, ["none (CI coverage for vendored guard tests)"]);
  assert.match(result.receipt.findings[0].evidence, /explicit no-bead declaration by human class; informational/);
  assert.equal(result.receipt.verdict, "clean");
  assert.equal(result.exitCode, 0);
  assert.deepEqual(result.receipt.queuedBeadCommands, [], "no declaration may queue a bead creation command");
  assert.match(result.markdown, /none \(declared\)/, "the Beads column says what the trailer declared");

  // A declaration beside a real id: the id is looked up, the declaration is noted.
  const mixed = commit(dir, { "docs/p.md": "p\n" }, "docs: composite\n\nFlywheel-Identity: human:orchestrator-lane\nBead: none (follow-up)\nBead: afc-real\n");
  const both = sweep(dir, ["--since", base, "--db", path.join(dir, "AGENTS.md"), "--dry-run"], { beadLookup: resolved });
  const row = both.receipt.commits.find((item) => item.sha === mixed);
  assert.deepEqual(row.beads, [resolved("afc-real")], "the id was looked up, the declaration was not");
  assert.deepEqual(row.no_bead_declarations, ["none (follow-up)"]);
  assert.deepEqual(both.receipt.findings.filter((item) => item.commit === mixed).map((item) => item.code), ["no-bead-declared"]);
});

test("a worker declaring `Bead: none` is missing-bead, MEDIUM, and never a lookup", () => {
  const { dir, base } = fixture();
  const sha = commit(dir, { "docs/w.md": "w\n" }, "docs: worker says none\n\nFlywheel-Identity: worker:codex-o01\nBead: none (workers may not)\n");
  const result = sweep(dir, ["--since", base, "--dry-run"], { beadLookup: neverLookedUp });
  const item = result.receipt.findings.find((finding) => finding.commit === sha);
  assert.deepEqual([item.severity, item.code], ["MEDIUM", "missing-bead"]);
  assert.match(item.evidence, /worker-class commit on the direct route declares `Bead: none`, which is not an id; a resolvable bead id is required/);
  assert.equal(result.receipt.findings.some((finding) => finding.code === "no-bead-declared"), false, "the declaration is not additionally informational for a worker");
  assert.equal(result.exitCode, 2);
});

test("lane: is a recognised class — human semantics on the pull-request route, worker semantics on the direct route", () => {
  const { dir, base } = fixture();
  const routed = commit(dir, { "docs/l1.md": "1\n" }, [
    "fix(guard): trailer grammar (#23)",
    "",
    "Flywheel-Identity: lane:guard-sweep-grammar-fix",
    "Bead: none (grammar fix; no bead exists)",
  ].join("\n"), { github: true });
  const directNone = commit(dir, { "docs/l2.md": "2\n" }, "docs: lane lands direct\n\nFlywheel-Identity: lane:some-lane\nBead: none (no bead)\n");
  const directBare = commit(dir, { "docs/l3.md": "3\n" }, "docs: lane lands direct, silent\n\nFlywheel-Identity: lane:some-lane\n");
  const directBead = commit(dir, { "docs/l4.md": "4\n" }, "docs: lane lands direct, with a bead\n\nFlywheel-Identity: lane:some-lane\nBead: afc-9\n");
  const result = sweep(dir, ["--since", base, "--db", path.join(dir, "AGENTS.md"), "--dry-run"], { beadLookup: resolved });
  const rows = Object.fromEntries(result.receipt.commits.map((item) => [item.sha, item]));
  const codes = (sha) => result.receipt.findings.filter((item) => item.commit === sha).map((item) => [item.severity, item.code]);
  assert.equal(rows[routed].identity_class, "lane");
  assert.equal(rows[routed].identity, "lane:guard-sweep-grammar-fix");
  assert.deepEqual(codes(routed), [["LOW", "no-bead-declared"]], "no missing-identity-pr-route: the trailer is recognised");
  assert.deepEqual(codes(directNone), [["MEDIUM", "missing-bead"]]);
  assert.match(result.receipt.findings.find((item) => item.commit === directNone).evidence, /lane-class commit on the direct route declares `Bead: none`/);
  assert.deepEqual(codes(directBare), [["MEDIUM", "missing-bead"]]);
  assert.match(result.receipt.findings.find((item) => item.commit === directBare).evidence, /lane-class commit on the direct route carries no Bead: trailer/);
  assert.deepEqual(codes(directBead), []);
  assert.deepEqual(rows[directBead].beads, [resolved("afc-9")]);
});

test("with two Flywheel-Identity lines the FIRST recognised one wins and the duplicate is a LOW finding; an unrecognised trailer is named, not called absent", () => {
  const { dir, base } = fixture();
  // fliff cb1256b4's shape: the recognised human line first, a lane line second. `.at(-1)`
  // let the second override the first; the class is human and the lane is recorded.
  const twice = commit(dir, { "docs/t.md": "t\n" }, [
    "fliff: declarations (#1367)",
    "",
    "Flywheel-Identity: human:orchestrator-lane",
    "Flywheel-Identity: lane:fliff-1367-declarations",
    "Bead: none (declarations)",
  ].join("\n"), { github: true });
  const bogusFirst = commit(dir, { "docs/u.md": "u\n" }, "docs: unrecognised then recognised\n\nFlywheel-Identity: owner:Kevin\nFlywheel-Identity: human:Kevin\n");
  const onlyBogusRouted = commit(dir, { "docs/v.md": "v\n" }, "docs: unrecognised only (#8)\n\nFlywheel-Identity: owner:Kevin\n", { github: true });
  const onlyBogusDirect = commit(dir, { "docs/x.md": "x\n" }, "docs: unrecognised only, direct\n\nFlywheel-Identity: owner:Kevin\n");
  const result = sweep(dir, ["--since", base, "--dry-run"], { beadLookup: neverLookedUp });
  const rows = Object.fromEntries(result.receipt.commits.map((item) => [item.sha, item]));
  const at = (sha, code) => result.receipt.findings.find((item) => item.commit === sha && item.code === code);

  assert.equal(rows[twice].identity, "human:orchestrator-lane");
  assert.equal(rows[twice].identity_class, "human");
  assert.deepEqual(rows[twice].identities, ["human:orchestrator-lane", "lane:fliff-1367-declarations"]);
  assert.equal(rows[twice].identity_duplicated, true);
  assert.deepEqual(result.receipt.findings.filter((item) => item.commit === twice).map((item) => [item.severity, item.code]).sort(), [["LOW", "duplicate-identity"], ["LOW", "no-bead-declared"]]);
  assert.match(at(twice, "duplicate-identity").evidence, /more than one Flywheel-Identity trailer in one message \(human:orchestrator-lane, lane:fliff-1367-declarations\); the first recognised one, human:orchestrator-lane, was used/);

  assert.equal(rows[bogusFirst].identity, "human:Kevin", "first RECOGNISED, not first");
  assert.equal(rows[bogusFirst].identity_class, "human");
  assert.ok(at(bogusFirst, "duplicate-identity"));

  assert.equal(rows[onlyBogusRouted].identity_class, "unknown");
  assert.equal(rows[onlyBogusRouted].identity, "owner:Kevin", "the receipt still shows what was there");
  assert.equal(at(onlyBogusRouted, "missing-identity-pr-route").severity, "LOW");
  assert.match(at(onlyBogusRouted, "missing-identity-pr-route").evidence, /^Flywheel-Identity trailer present but outside the worker:\/human:\/lane: grammar \(owner:Kevin\); commit was authored by GitHub/);
  assert.equal(at(onlyBogusDirect, "missing-identity").severity, "MEDIUM");
  assert.match(at(onlyBogusDirect, "missing-identity").evidence, /^Flywheel-Identity trailer present but outside the worker:\/human:\/lane: grammar \(owner:Kevin\) on a direct commit$/);
  assert.equal(rows[onlyBogusDirect].identity_duplicated, false);
});

test("a merge retains distinct identities and classifies conservatively as worker when any folded member is worker", () => {
  const { dir, base } = fixture();
  git(dir, ["checkout", "-q", "-b", "feature", base]);
  commit(dir, { "docs/f1.md": "1\n" }, "feat: older branch commit\n\nFlywheel-Identity: worker:codex-o03\nBead: afc-merge\n");
  commit(dir, { "docs/f2.md": "2\n" }, "feat: newer branch commit\n\nFlywheel-Identity: lane:fleet-review-sweep-vendor\nBead: none (vendoring)\n");
  git(dir, ["checkout", "-q", "main"]);
  git(dir, ["merge", "-q", "--no-ff", "feature", "-m", "Merge pull request #367 from kjgryboski/feature"], { env: GITHUB_ENV });
  const merge = git(dir, ["rev-parse", "HEAD"]).trim();
  const result = sweep(dir, ["--since", base, "--db", path.join(dir, "AGENTS.md"), "--dry-run"], { beadLookup: resolved });
  const row = result.receipt.commits.find((item) => item.sha === merge);
  assert.equal(row.identity, "worker:codex-o03", "worker evidence wins even when a newer branch commit is lane class");
  assert.equal(row.identity_class, "worker");
  assert.deepEqual(row.identities, ["lane:fleet-review-sweep-vendor", "worker:codex-o03"]);
  assert.equal(row.identity_duplicated, false);
  assert.deepEqual(row.beads, [resolved("afc-merge")]);
  assert.deepEqual(result.receipt.findings.filter((item) => item.commit === merge).map((item) => item.code), ["no-bead-declared"]);
  assert.equal(result.receipt.verdict, "clean");
});

test("malformed Bead values are bounded findings and never reach br argv", () => {
  const { dir, base } = fixture();
  const sha = commit(dir, { "docs/m.md": "m\n" }, [
    "docs(audit): dependabot alert (#1337)",
    "",
    "Flywheel-Identity: human:orchestrator-lane",
    "Bead: kfx-komplex-launch-d03-k9v [kxl-d03]",
    "Bead: --help",
    "Bead: afc/escape",
  ].join("\n"), { github: true });
  // No --db: a value the guard would never look up must not make the store mandatory.
  const result = sweep(dir, ["--since", base, "--dry-run"], { beadLookup: neverLookedUp });
  const row = result.receipt.commits.find((item) => item.sha === sha);
  assert.deepEqual(row.beads, [], "nothing was looked up");
  assert.deepEqual(row.malformed_beads, ["kfx-komplex-launch-d03-k9v [kxl-d03]", "--help", "afc/escape"]);
  const items = result.receipt.findings.filter((finding) => finding.code === "malformed-bead");
  assert.equal(items.length, 3);
  assert.ok(items.every((item) => item.severity === "MEDIUM" && item.commit === sha));
  assert.match(items[0].evidence, /Bead: kfx-komplex-launch-d03-k9v \[kxl-d03\] — neither a portable bead id nor a `none` declaration; not looked up/);
  assert.match(items[1].evidence, /Bead: --help .* not looked up/);
  assert.match(items[2].evidence, /Bead: afc\/escape .* not looked up/);
  assert.match(result.markdown, /kfx-komplex-launch-d03-k9v \[kxl-d03\] \(malformed\)/);
  assert.equal(result.exitCode, 2);
});
