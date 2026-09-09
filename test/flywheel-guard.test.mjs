import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { apiBaseUrl, appendTrailer, cloneIdentity, FENCE_GLOBS, githubMainStatus, githubReadToken, githubRepo, identity, janitorException, mainCommits, mainRefUpdates, overlaps, parseRpcText, redact, redMainGate, sentinelNames, trailerBlock, unknownMainGate, unwrapRpc, validateBead } from "../scripts/flywheel-guard.mjs";
import { trailerBlock as sweepTrailerBlock } from "../scripts/review-sweep.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const guard = path.join(root, "scripts", "flywheel-guard.mjs");

function git(cwd, ...args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" });
}

function repo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-guard-test-"));
  git(dir, "init", "-b", "main");
  git(dir, "config", "user.name", "Flywheel Test");
  git(dir, "config", "user.email", "flywheel-test@example.invalid");
  fs.writeFileSync(path.join(dir, "file.txt"), "guard test\n");
  git(dir, "add", "file.txt");
  return dir;
}

function nativeBrFixture(dir) {
  const binary = path.join(dir, ".fixture-br");
  fs.writeFileSync(binary, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  fs.chmodSync(binary, 0o755);
  return binary;
}

// Port 1 refuses the connection instantly, so the fail-open tests that point here
// spend no real time regardless of the budget.
const UNREACHABLE_MAIL = "http://127.0.0.1:1/mcp/";

function config(dir, overrides = {}) {
  const value = {
    version: 1,
    agentMailUrl: UNREACHABLE_MAIL,
    agentMailProjectKey: dir,
    mailTimeoutMs: 20,
    observerAgent: "CalmRiver",
    workerClones: [],
    br: { binary: nativeBrFixture(dir), database: "/tmp/not-used.db" },
    ...overrides,
  };
  // A test pointing at a live localhost stub needs that stub to ANSWER; the 20ms
  // default is a budget for the unreachable URL above, where the value is
  // irrelevant. Applied to a real HTTP round trip on a loaded runner it makes the
  // guard fail open instead, which writes an extra `fail-open` audit row and
  // breaks every assertion that counts rows or asserts the reachable-Mail path.
  // That is a false red that says nothing about the guard. Raising it only makes
  // the intended path more likely to be the one exercised — no test here relies on
  // a live-but-slow server timing out, and any that wants one can still pass
  // `mailTimeoutMs` explicitly. The value is the production one from
  // flywheel.guard.json and the guard's own fallback, so the tests run against
  // the budget real sessions get rather than an invented one.
  if (!("mailTimeoutMs" in overrides) && value.agentMailUrl !== UNREACHABLE_MAIL) {
    value.mailTimeoutMs = 650;
  }
  const file = path.join(dir, "flywheel.guard.json");
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
  return file;
}

function run(cwd, args, env = {}, input = "") {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [guard, ...args], {
      cwd,
      env: { ...process.env, FLYWHEEL_AGENT_MAIL_TOKEN: "", FLYWHEEL_AGENT_MAIL_TOKEN_FILE: path.join(os.tmpdir(), "flywheel-missing-mail-token"), ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(input);
  });
}

function rpc(id, value, resource = false) {
  const result = resource
    ? { contents: [{ uri: "resource://file_reservations/test", text: JSON.stringify(value) }] }
    : { structuredContent: value, content: [{ type: "text", text: JSON.stringify(value) }] };
  return JSON.stringify({ jsonrpc: "2.0", id, result });
}

test("identity and GitHub remote parsing are strict", () => {
  assert.deepEqual(identity("worker:codex-o01"), { class: "worker", name: "codex-o01", raw: "worker:codex-o01" });
  assert.deepEqual(identity("human:Kevin"), { class: "human", name: "Kevin", raw: "human:Kevin" });
  assert.equal(identity("codex-o01"), null);
  // `lane:<slug>`: an orchestrator-dispatched lane. Slug only — no whitespace, no empty name.
  assert.deepEqual(identity("lane:guard-sweep-grammar-fix"), { class: "lane", name: "guard-sweep-grammar-fix", raw: "lane:guard-sweep-grammar-fix" });
  assert.equal(identity("lane:"), null);
  assert.equal(identity("lane:two words"), null);
  assert.equal(identity("lane:-leading-dash"), null);
  assert.equal(identity("owner:Kevin"), null);
  assert.deepEqual(githubRepo("git@github.com:kjgryboski/bookclub.git"), { owner: "kjgryboski", repo: "bookclub" });
});

test("reservation overlap handles exact paths and globs", () => {
  assert.equal(overlaps("src/lib.mjs", "src/**"), true);
  assert.equal(overlaps("README.md", "src/**"), false);
  assert.equal(overlaps("docs/*.md", "docs/plan.md"), true);
});

test("MCP JSON and event-stream responses unwrap", () => {
  const body = rpc(1, { conflict_free: true });
  assert.equal(unwrapRpc(parseRpcText(body)).conflict_free, true);
  assert.equal(unwrapRpc(parseRpcText(`event: message\ndata: ${body}\n\n`)).conflict_free, true);
});


for (const source of ["env", "file", "missing", "empty-file", "empty-env", "whitespace-env"]) {
  test(`Mail bearer source ${source} authenticates every conflict and metadata request`, async (t) => {
    const dir = repo();
    const tokenFile = path.join(dir, "mail-token");
    const token = Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
    if (source !== "missing") fs.writeFileSync(tokenFile, source === "empty-file" ? " \n" : ` ${token}\n`, { mode: 0o600 });
    t.after(() => { if (fs.existsSync(tokenFile)) fs.writeFileSync(tokenFile, ""); });
    const expected = ["env", "file", "empty-env", "whitespace-env"].includes(source) ? `Bearer ${token}` : undefined;
    const calls = [];
    const mail = await listen((request, body, response) => {
      const parsed = JSON.parse(body);
      calls.push({ method: parsed.method, matched: request.headers.authorization === expected });
      // A mid-process rotation must not change the credential on the enrichment read.
      if (source === "file") fs.writeFileSync(tokenFile, "rotated-fixture-value\n");
      response.writeHead(200, { "content-type": "application/json" });
      response.end(rpc(parsed.id, parsed.method === "resources/read" ? [] : { conflicts: [] }, parsed.method === "resources/read"));
    });
    t.after(() => mail.server.close());
    const configFile = config(dir, { agentMailUrl: `${mail.url}/mcp/` });
    const result = await run(dir, ["--phase", "pre-commit"], {
      FLYWHEEL_AGENT_ID: "human:fixture",
      FLYWHEEL_GUARD_CONFIG: configFile,
      FLYWHEEL_AGENT_MAIL_TOKEN: source === "env" ? ` ${token}\n` : source === "empty-env" ? "" : source === "whitespace-env" ? " \n" : undefined,
      FLYWHEEL_AGENT_MAIL_TOKEN_FILE: tokenFile,
    });
    assert.equal(result.code, 0);
    assert.equal(result.stderr, "");
    assert.deepEqual(calls, [
      { method: "tools/call", matched: true },
      { method: "resources/read", matched: true },
    ]);
  });
}

test("Mail environment bearer wins over a different file; audit calls use it too", async (t) => {
  const dir = repo();
  const tokenFile = path.join(dir, "mail-token");
  fs.writeFileSync(tokenFile, "unused-file-fixture-value\n", { mode: 0o600 });
  t.after(() => fs.writeFileSync(tokenFile, ""));
  const token = ["environment", "fixture", "value"].join("-");
  const calls = [];
  const mail = await listen((request, body, response) => {
    const parsed = JSON.parse(body);
    calls.push({ name: parsed.params.name, matched: request.headers.authorization === `Bearer ${token}` });
    response.writeHead(200);
    response.end(rpc(parsed.id, {}));
  });
  t.after(() => mail.server.close());
  const configFile = config(dir, { agentMailUrl: `${mail.url}/mcp/`, audit: { sender: "CalmRiver", recipient: "CalmRiver" } });
  const result = await run(dir, ["--phase", "pre-commit"], {
    FLYWHEEL_AGENT_ID: "human:fixture",
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_BYPASS: "synthetic audit test",
    FLYWHEEL_AGENT_MAIL_TOKEN: token,
    FLYWHEEL_AGENT_MAIL_TOKEN_FILE: tokenFile,
  });
  assert.equal(result.code, 0);
  assert.deepEqual(calls, [{ name: "send_message", matched: true }]);
});

test("Mail retries cache the first file read, including a missing file", async (t) => {
  for (const present of [false, true]) {
    const dir = repo();
    const tokenFile = path.join(dir, "mail-token");
    const token = ["retry", "fixture", "value"].join("-");
    if (present) fs.writeFileSync(tokenFile, token, { mode: 0o600 });
    t.after(() => fs.writeFileSync(tokenFile, ""));
    const calls = [];
    const mail = await listen((request, body, response) => {
      const parsed = JSON.parse(body);
      calls.push(request.headers.authorization === (present ? `Bearer ${token}` : undefined));
      fs.writeFileSync(tokenFile, "new-file-fixture-value", { mode: 0o600 });
      response.writeHead(calls.length === 1 ? 503 : 200);
      response.end(rpc(parsed.id, parsed.method === "resources/read" ? [] : { conflicts: [] }, parsed.method === "resources/read"));
    });
    t.after(() => mail.server.close());
    const configFile = config(dir, { agentMailUrl: `${mail.url}/mcp/` });
    const result = await run(dir, ["--phase", "pre-commit"], {
      FLYWHEEL_AGENT_ID: "human:fixture", FLYWHEEL_GUARD_CONFIG: configFile,
      FLYWHEEL_AGENT_MAIL_TOKEN: undefined, FLYWHEEL_AGENT_MAIL_TOKEN_FILE: tokenFile,
    });
    assert.equal(result.code, 0);
    assert.equal(result.stderr, "");
    assert.deepEqual(calls, [true, true, true]);
  }
});

for (const failure of ["401", "403", "rpc", "tool", "malformed"]) {
  test(`Mail ${failure} preserves worker/human outage policy and redacts echoed credentials`, async (t) => {
    // A short value proves Mail redaction has no GitHub-style minimum-length exception.
    const token = failure === "malformed" ? "xyz" : ["echoed", "fixture", "value"].join("-");
    let requests = 0;
    const mail = await listen((request, body, response) => {
      requests += 1;
      const parsed = JSON.parse(body);
      response.writeHead(Number(failure) || 200, { "content-type": "application/json" });
      const message = `rejected ${request.headers.authorization}`;
      response.end(failure === "malformed" ? `{"echo":${token}}` : JSON.stringify({
        jsonrpc: "2.0", id: parsed.id,
        ...(failure === "tool" ? { result: { isError: true, content: [{ type: "text", text: message }] } } : { error: { message } }),
      }));
    });
    t.after(() => mail.server.close());
    for (const klass of ["worker", "human"]) {
      const dir = repo();
      const tokenFile = path.join(dir, "missing-mail-token");
      const configFile = config(dir, {
        agentMailUrl: `${mail.url}/mcp/`,
        workerClones: klass === "worker" ? [{ alias: "fixture", path: dir, mailAgent: "CalmRiver" }] : [],
      });
      const env = {
        FLYWHEEL_AGENT_ID: `${klass}:fixture`, FLYWHEEL_GUARD_CONFIG: configFile,
        FLYWHEEL_AGENT_MAIL_TOKEN: token, FLYWHEEL_AGENT_MAIL_TOKEN_FILE: tokenFile,
      };
      requests = 0;
      const result = await run(dir, ["--phase", "pre-commit"], env);
      assert.equal(requests, ["401", "403"].includes(failure) ? 1 : 2);
      assert.equal(result.code, klass === "worker" ? 1 : 0);
      assert.equal((result.stdout + result.stderr).includes(token), false, "credential must not reach console output");
      assert.match(result.stderr, klass === "worker" ? /BLOCKED/ : /fail-open/);
      if (["401", "403"].includes(failure)) {
        assert.ok(result.stderr.includes(`Agent Mail HTTP ${failure}: authentication rejected`));
        assert.ok(result.stderr.includes(tokenFile));
      } else {
        assert.match(result.stderr, /\[redacted\]/);
      }
      if (klass === "human") {
        const audit = fs.readFileSync(path.join(dir, ".git", "flywheel-guard-audit.jsonl"), "utf8");
        assert.equal(audit.includes(token), false, "credential must not reach audit rows");
        const message = path.join(dir, "message.txt");
        fs.writeFileSync(message, "test: Mail failure\n");
        requests = 0;
        const commit = await run(dir, ["--phase", "commit-msg", message], env);
        assert.equal(requests, ["401", "403"].includes(failure) ? 1 : 2);
        assert.equal(commit.code, 0);
        const text = fs.readFileSync(message, "utf8");
        assert.match(text, /Flywheel-Guard: fail-open/);
        assert.equal(text.includes(token), false, "credential must not reach trailers");
      }
    }
  });
}

test("Mail auth failure on optional metadata and audit remains a warning", async (t) => {
  const dir = repo();
  const token = ["optional", "fixture", "value"].join("-");
  const mail = await listen((request, body, response) => {
    const parsed = JSON.parse(body);
    const optional = parsed.method === "resources/read" || parsed.params.name === "send_message";
    response.writeHead(optional ? 401 : 200);
    response.end(optional ? request.headers.authorization : rpc(parsed.id, { conflicts: [] }));
  });
  t.after(() => mail.server.close());
  const configFile = config(dir, {
    agentMailUrl: `${mail.url}/mcp/`,
    workerClones: [{ alias: "fixture", path: dir, mailAgent: "CalmRiver" }],
    audit: { sender: "CalmRiver", recipient: "CalmRiver" },
  });
  for (const bypass of ["", "synthetic audit test"]) {
    const result = await run(dir, ["--phase", "pre-commit"], {
      FLYWHEEL_AGENT_ID: "worker:fixture", FLYWHEEL_GUARD_CONFIG: configFile,
      FLYWHEEL_AGENT_MAIL_TOKEN: token, FLYWHEEL_GUARD_BYPASS: bypass,
    });
    assert.equal(result.code, 0);
    assert.match(result.stderr, bypass ? /Mail audit failed: Agent Mail HTTP 401/ : /metadata enrichment unavailable: Agent Mail HTTP 401/);
    assert.equal(result.stderr.includes(token), false);
  }
});

test("live main status classifies red, pending, green, and unreachable", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const response = (value, ok = true, status = 200) => ({ ok, status, json: async () => value });
  const cases = [
    [{ state: "failure" }, [], "red"],
    [{ state: "success" }, [{ status: "in_progress", conclusion: null }], "pending"],
    [{ state: "success" }, [{ status: "completed", conclusion: "success" }], "green"],
  ];
  for (const [combined, jobs, expected] of cases) {
    const result = await sentinelStatus(dir, jobs, undefined, combined);
    assert.equal(result.state, expected);
  }
  const unknown = await githubMainStatus(dir, async () => response({}, false, 503), "b".repeat(40));
  assert.equal(unknown.state, "unknown");
});

const SENTINEL = ["Offline contract suite"];
// The attended repository_dispatch canary lifecycle parks a by-design failing
// `credential_failure` job on the same main sha; a superseded weekly drill leaves
// `cancelled`. Neither may red main once the sentinel names are configured.
const POLLUTION = [
  { name: "credential_failure", status: "completed", conclusion: "failure", id: 1, completed_at: "2026-09-01T10:00:00Z" },
  { name: "Weekly drill", status: "completed", conclusion: "cancelled", id: 2, completed_at: "2026-09-01T10:01:00Z" },
];
const sentinelRun = (conclusion, id, minute, status = "completed", second = "00") => ({
  name: SENTINEL[0], status, conclusion, id,
  completed_at: status === "completed" ? `2026-09-01T10:${minute}:${second}Z` : null,
  started_at: `2026-09-01T10:${minute}:${second}Z`,
});

const seenUrls = [];

function actionPage(pageJobs, page) {
  const groups = new Map();
  for (const job of pageJobs) {
    const runId = Number(job.run_id ?? job.check_suite?.id ?? (page * 1000 + 1));
    if (!groups.has(runId)) groups.set(runId, { workflow: { id: runId, run_attempt: 1 }, jobs: [] });
    const group = groups.get(runId);
    const attempt = Number(job.run_attempt) || 1;
    group.workflow.run_attempt = Math.max(group.workflow.run_attempt, attempt);
    group.jobs.push({ ...job, run_id: runId, run_attempt: attempt });
  }
  return [...groups.values()];
}

// Dispatches by URL because the status, workflow-run list, and per-run jobs reads happen
// concurrently. Existing fixtures describe jobs; this helper wraps them in Actions API
// response shapes. `extraPages` supplies workflow-run page 2 onward.
async function sentinelStatus(dir, checkJobs, checkNames, combined = { state: "pending", statuses: [] }, checksBody = {}, extraPages = []) {
  const response = (value) => ({ ok: true, status: 200, json: async () => value });
  const pages = [checkJobs, ...extraPages].map((jobs, index) => actionPage(jobs, index + 1));
  const jobsByRun = new Map(pages.flat().map(({ workflow, jobs }) => [workflow.id, jobs]));
  const defaultTotal = pages.reduce((sum, page) => sum + page.length, 0);
  return githubMainStatus(dir, async (url) => {
    seenUrls.push(url);
    if (url.includes("/commits/") && url.endsWith("/status")) return response(combined);
    const jobsMatch = /\/actions\/runs\/(\d+)\/jobs/.exec(url);
    if (jobsMatch) {
      const jobs = jobsByRun.get(Number(jobsMatch[1])) || [];
      return response({ jobs, total_count: checksBody.job_total_count ?? jobs.length });
    }
    if (url.includes("/actions/runs?")) {
      const page = Number(/[?&]page=(\d+)/.exec(url)?.[1] || 1);
      return response({ workflow_runs: (pages[page - 1] || []).map(({ workflow }) => workflow), total_count: checksBody.total_count ?? defaultTotal });
    }
    throw new Error(`unexpected GitHub URL: ${url}`);
  }, "d".repeat(40), 1500, checkNames);
}

test("named sentinel checks decide red-main and ignore foreign pollution", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");

  const green = await sentinelStatus(dir, [...POLLUTION, sentinelRun("success", 3, "05")], SENTINEL);
  assert.equal(green.state, "green", "a passing sentinel outranks a by-design failing foreign job");

  const missing = await sentinelStatus(dir, POLLUTION, SENTINEL);
  assert.equal(missing.state, "pending", "no run of the named check on HEAD proceeds as pending");
  assert.deepEqual(missing.missing, SENTINEL, "the absent check is reported so pre-push can warn");

  const running = await sentinelStatus(dir, [sentinelRun(null, 4, "06", "in_progress")], SENTINEL);
  assert.equal(running.state, "pending");

  // Winner LAST in array order and with the LOWER id, so only completed_at can pick it.
  // Kills a "first completed run in array order wins" mutant and a "max by id" mutant.
  const superseded = await sentinelStatus(dir, [sentinelRun("cancelled", 90, "07"), sentinelRun("success", 5, "20")], SENTINEL);
  assert.equal(superseded.state, "green", "a cancelled run replaced by a later success is green");

  const cancelledLatest = await sentinelStatus(dir, [sentinelRun("success", 91, "07"), sentinelRun("cancelled", 6, "20")], SENTINEL);
  assert.equal(cancelledLatest.state, "red", "the top-ranked run of the named check decides");
  assert.deepEqual(cancelledLatest.failing, SENTINEL);

  // Winner in the MIDDLE with the lowest id: kills array-first, array-last and max-by-id
  // in one fixture, so no positional rule can satisfy the whole set.
  const middle = await sentinelStatus(dir, [sentinelRun("cancelled", 40, "05"), sentinelRun("success", 7, "30"), sentinelRun("cancelled", 99, "10")], SENTINEL);
  assert.equal(middle.state, "green", "position in the response never decides");

  // Same second: only the id can break the tie. Winner last, then winner first, so the
  // tie-break cannot be an array-order rule in disguise either.
  const tieGreen = await sentinelStatus(dir, [sentinelRun("cancelled", 50, "30", "completed", "07"), sentinelRun("success", 51, "30", "completed", "07")], SENTINEL);
  assert.equal(tieGreen.state, "green", "a same-second tie is broken by the higher run id");

  const tieRed = await sentinelStatus(dir, [sentinelRun("cancelled", 53, "30", "completed", "07"), sentinelRun("success", 52, "30", "completed", "07")], SENTINEL);
  assert.equal(tieRed.state, "red", "and the tie-break is direction-symmetric");

  const sentinelFailure = await sentinelStatus(dir, [...POLLUTION, sentinelRun("failure", 9, "12")], SENTINEL);
  assert.equal(sentinelFailure.state, "red");
  assert.deepEqual(sentinelFailure.failing, SENTINEL, "only the named check is reported as failing");

  const postedRed = await sentinelStatus(dir, [sentinelRun("success", 10, "13")], SENTINEL, { state: "failure", statuses: [{ state: "failure" }] });
  assert.equal(postedRed.state, "red", "a posted combined commit status still counts");
});

test("a stale unfinished run cannot pin the sentinel to pending forever", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");

  // `filter=all` returns the abandoned queued run alongside the real one. Asking "is any
  // run unfinished?" would read pending forever; the top-ranked run is the later success.
  const stale = [sentinelRun(null, 20, "01", "queued"), sentinelRun("success", 21, "40")];
  const outranked = await sentinelStatus(dir, stale, SENTINEL);
  assert.equal(outranked.state, "green", "an older unfinished run is outranked, not obeyed");
  assert.deepEqual(outranked.stalled, [], "and it is not reported as stalling the check");

  const stalled = await sentinelStatus(dir, [sentinelRun(null, 23, "40", "in_progress")], SENTINEL);
  assert.equal(stalled.state, "pending", "with no completed run at all there is no verdict yet");
  assert.deepEqual(stalled.stalled, SENTINEL, "and pre-push warns rather than going quiet");
});

// A re-run of the sentinel on a red main creates a window in which the newest run for the
// name is unfinished. Ranking across unfinished runs discarded the completed conclusion
// for that window, so main read `pending` and every worker was free to push onto a head
// that was still red. The verdict comes from the top-ranked COMPLETED run; an unfinished
// run only decides when it is the only thing there is.
test("a re-run in flight never masks the completed verdict of the run it replaces", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const red = sentinelRun("failure", 60, "10");

  const rerunning = await sentinelStatus(dir, [red, sentinelRun(null, 61, "40", "in_progress")], SENTINEL);
  assert.equal(rerunning.state, "red", "a red main stays red while the re-run is in flight");
  assert.deepEqual(rerunning.failing, SENTINEL);
  assert.deepEqual(rerunning.stalled, [], "the completed run answered, so nothing is stalled");

  const queued = await sentinelStatus(dir, [red, sentinelRun(null, 62, "40", "queued")], SENTINEL);
  assert.equal(queued.state, "red", "a queued re-run is no different from an in-progress one");

  // A queued run GitHub has not started yet carries neither timestamp, so it ranks 0 and
  // would lose on rank alone. Status, not rank, is what must keep it out of the verdict.
  const unstarted = await sentinelStatus(dir, [
    { name: SENTINEL[0], status: "queued", conclusion: null, id: 63, completed_at: null, started_at: null },
    red,
  ], SENTINEL);
  assert.equal(unstarted.state, "red", "a not-yet-started re-run does not erase the verdict either");

  const greenRerun = await sentinelStatus(dir, [sentinelRun("success", 64, "10"), sentinelRun(null, 65, "40", "in_progress")], SENTINEL);
  assert.equal(greenRerun.state, "green", "and a green main is not downgraded by its own re-run");
});

test("a later Actions run attempt outranks the superseded attempt", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const first = { ...sentinelRun("failure", 999, "59"), run_id: 77, run_attempt: 1 };
  const second = { ...sentinelRun("success", 1, "01"), run_id: 77, run_attempt: 2 };

  const green = await sentinelStatus(dir, [first, second], SENTINEL);
  assert.equal(green.state, "green", "attempt number outranks an adversarially newer timestamp and higher job id");

  const regressed = await sentinelStatus(dir, [first, { ...second, conclusion: "failure" }], SENTINEL);
  assert.equal(regressed.state, "red", "the later attempt still decides when it fails");
});

// A job that never ran has no verdict. `skipped` (an `if:` that was false, a needed job
// that failed) and `neutral` are `completed` conclusions that decide nothing. The RED set
// excluded them, so a sentinel whose only run was skipped read GREEN (#21 review, NB1) —
// kj-brain carried a duplicate SKIPPED sentinel on one head. The deciding run per name is
// the top-ranked completed run whose conclusion is not skipped/neutral; a name with only
// those is undecided, which is never green. Same rule as the control plane's merge window
// ("deciding run per required check"), so the two brakes agree.
test("a skipped or neutral sentinel never reads green and never outranks a real conclusion", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  for (const conclusion of ["skipped", "neutral"]) {
    const only = await sentinelStatus(dir, [sentinelRun(conclusion, 100, "10")], SENTINEL);
    assert.equal(only.state, "pending", `a ${conclusion}-only sentinel is not green`);
    assert.deepEqual(only.undecided, SENTINEL, "and the untested check is named for pre-push");
    assert.deepEqual(only.stalled, [], "it is not the same thing as a run still in flight");

    // Newer, higher id: on rank alone the skipped run wins every tie-break. It must not.
    const afterSuccess = await sentinelStatus(dir, [sentinelRun("success", 1, "05"), sentinelRun(conclusion, 200, "40")], SENTINEL);
    assert.equal(afterSuccess.state, "green", `success then ${conclusion} is still green`);
    assert.deepEqual(afterSuccess.undecided, []);
    const beforeSuccess = await sentinelStatus(dir, [sentinelRun(conclusion, 1, "05"), sentinelRun("success", 200, "40")], SENTINEL);
    assert.equal(beforeSuccess.state, "green", `${conclusion} then success is green`);
    const afterFailure = await sentinelStatus(dir, [sentinelRun("failure", 1, "05"), sentinelRun(conclusion, 200, "40")], SENTINEL);
    assert.equal(afterFailure.state, "red", `failure then ${conclusion} stays red`);
    assert.deepEqual(afterFailure.failing, SENTINEL);
    // A later attempt that skipped does not clear the attempt that failed either.
    const attempt = await sentinelStatus(dir, [
      { ...sentinelRun("failure", 1, "05"), run_id: 7, run_attempt: 1 },
      { ...sentinelRun(conclusion, 2, "40"), run_id: 7, run_attempt: 2 },
    ], SENTINEL);
    assert.equal(attempt.state, "red", `a ${conclusion} re-run attempt never outranks the failed one`);
  }

  // The kj-brain shape: two workflow runs publish the name, one skipped, one real.
  const duplicate = await sentinelStatus(dir, [{ ...sentinelRun("skipped", 300, "40"), run_id: 8 }, { ...sentinelRun("success", 301, "10"), run_id: 9 }], SENTINEL);
  assert.equal(duplicate.state, "green", "the run that actually tested the head decides");
  const duplicateRed = await sentinelStatus(dir, [{ ...sentinelRun("skipped", 300, "40"), run_id: 8 }, { ...sentinelRun("failure", 301, "10"), run_id: 9 }], SENTINEL);
  assert.equal(duplicateRed.state, "red");

  // Truncated plus skipped is still never green, and skipped plus a re-run in flight is
  // undecided rather than merely stalled: nothing has judged this head yet.
  const cut = await sentinelStatus(dir, [sentinelRun("skipped", 100, "10")], SENTINEL, undefined, { total_count: 140 });
  assert.deepEqual([cut.state, cut.truncated], ["pending", true]);
  const inFlight = await sentinelStatus(dir, [sentinelRun("skipped", 100, "10"), sentinelRun(null, 101, "40", "in_progress")], SENTINEL);
  assert.equal(inFlight.state, "pending");
  assert.deepEqual(inFlight.undecided, SENTINEL);
});

test("legacy mode never lets a skipped run outrank a failure", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const green = { state: "success", statuses: [{ state: "success" }] };
  const masked = await sentinelStatus(dir, [sentinelRun("failure", 1, "05"), sentinelRun("skipped", 200, "40")], undefined, green);
  assert.equal(masked.state, "red", "a newer skipped run is not a newer verdict");
  assert.deepEqual(masked.failing, SENTINEL);
});

test("a truncated Actions result can never read green", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const runs = [sentinelRun("success", 70, "10")];

  const whole = await sentinelStatus(dir, runs, SENTINEL, undefined, { total_count: 1 });
  assert.equal(whole.state, "green");

  // A run we never fetched could outrank this one, so the sentinel's own success is not
  // evidence the head is green. Pending still proceeds; green would have been a claim.
  const cut = await sentinelStatus(dir, runs, SENTINEL, undefined, { total_count: 140 });
  assert.equal(cut.state, "pending", "a partial page downgrades the verdict, never upgrades it");
  assert.equal(cut.truncated, true, "and pre-push warns that the page was cut");

  const legacy = await sentinelStatus(dir, runs, undefined, { state: "success", statuses: [{ state: "success" }] }, { total_count: 140 });
  assert.equal(legacy.state, "pending", "legacy mode cannot claim green from the same partial evidence");
  assert.equal(legacy.truncated, true);
});

// A busy sha returns more than 100 workflow runs, and a sentinel whose run falls past
// page 1 would read `missing`. Paging is bounded; past it the gap is reported, not hidden.
test("Actions workflow runs are paged up to the bound before truncation is declared", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  seenUrls.length = 0;

  // The sentinel is on page 2. Without paging this is `missing`; with it, a real verdict.
  const found = await sentinelStatus(dir, POLLUTION, SENTINEL, undefined, { total_count: 2 }, [[sentinelRun("failure", 71, "10")]]);
  assert.equal(found.state, "red", "a sentinel on a later page is found, not reported missing");
  assert.deepEqual(found.missing, [], "and it is not warned as absent");
  assert.equal(found.truncated, false, "everything total_count promised was fetched");
  const pageParams = seenUrls.filter((url) => url.includes("/actions/runs?")).map((url) => /[?&]page=(\d+)/.exec(url)[1]);
  assert.deepEqual(pageParams, ["1", "2"], "paging stops as soon as total_count is satisfied");

  // Beyond the bound the sentinel is still unseen. Pushes proceed (pending proceeds), but
  // pre-push records `truncated-missing` rather than implying the head was inspected.
  seenUrls.length = 0;
  const beyond = await sentinelStatus(dir, POLLUTION, SENTINEL, undefined, { total_count: 900 }, [POLLUTION, POLLUTION, POLLUTION]);
  assert.equal(beyond.state, "pending");
  assert.equal(beyond.truncated, true);
  assert.deepEqual(beyond.missing, SENTINEL, "the unseen sentinel is what makes this reportable");
  assert.equal(seenUrls.filter((url) => url.includes("/actions/runs?")).length, 3, "paging is bounded at 3 pages");
});

// `build`, `test` and `lint` are ordinary job names; two workflows may each publish one.
// Keying the dedupe on the name alone let a passing run from one workflow supersede a
// failing run of the same name from another, so a real red read green.
test("same-named checks from different suites do not collapse into one verdict", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const green = { state: "success", statuses: [{ state: "success" }] };
  const suiteRun = (suite, conclusion, id, minute) => ({
    name: "test", status: "completed", conclusion, id, check_suite: { id: suite },
    completed_at: `2026-09-01T10:${minute}:00Z`, started_at: `2026-09-01T10:${minute}:00Z`,
  });

  // The passing run is strictly newer and has the higher id, so it wins on rank outright.
  // Only the suite key keeps the older failure in the verdict.
  const legacy = await sentinelStatus(dir, [suiteRun(1, "failure", 10, "05"), suiteRun(2, "success", 99, "40")], undefined, green);
  assert.equal(legacy.state, "red", "a failing `test` in one suite is not cleared by a passing `test` in another");
  assert.deepEqual(legacy.failing, ["test"]);

  // Within ONE suite the newer run still supersedes the older, which is the whole point of
  // the rank rule; the suite key must not disable it.
  const superseded = await sentinelStatus(dir, [suiteRun(1, "failure", 10, "05"), suiteRun(1, "success", 99, "40")], undefined, green);
  assert.equal(superseded.state, "green", "within a suite the later run still wins");

  // Sentinel mode has the same exposure: two workflows publishing the configured name.
  const sentinel = await sentinelStatus(dir, [
    { ...suiteRun(1, "failure", 10, "05"), name: SENTINEL[0] },
    { ...suiteRun(2, "success", 99, "40"), name: SENTINEL[0] },
  ], SENTINEL, green);
  assert.equal(sentinel.state, "red", "either suite going red is a red for the configured name");
});

test("Actions runs and jobs use the reviewed endpoints and never request check-runs", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  seenUrls.length = 0;
  const runs = [sentinelRun("success", 30, "10")];

  const complete = await sentinelStatus(dir, runs, SENTINEL, undefined, { total_count: 1 });
  assert.equal(complete.truncated, false);
  const runsUrl = seenUrls.find((url) => url.includes("/actions/runs?"));
  const jobsUrl = seenUrls.find((url) => /\/actions\/runs\/\d+\/jobs/.test(url));
  assert.match(runsUrl, /[?&]head_sha=d{40}(&|$)/);
  assert.match(runsUrl, /[?&]per_page=100(&|$)/);
  assert.match(runsUrl, /[?&]page=1(&|$)/);
  assert.match(jobsUrl, /[?&]filter=all(&|$)/, "all attempts must remain visible to the rank rule");
  assert.match(jobsUrl, /[?&]per_page=100(&|$)/);
  assert.equal(seenUrls.some((url) => url.includes("/check-runs")), false, "fine-grained PATs cannot read the Checks API");

  // total_count above the returned page means a run we never saw could outrank this one.
  const truncated = await sentinelStatus(dir, runs, SENTINEL, undefined, { total_count: 140 });
  assert.equal(truncated.truncated, true);

  const partialJobs = await sentinelStatus(dir, runs, SENTINEL, undefined, { total_count: 1, job_total_count: 140 });
  assert.equal(partialJobs.state, "pending", "a partial jobs list cannot claim green");
  assert.equal(partialJobs.truncated, true);
});

test("Actions job reads use bounded concurrency", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const sha = "a".repeat(40);
  const workflows = Array.from({ length: 12 }, (_, index) => ({ id: index + 1, run_attempt: 1 }));
  let active = 0;
  let peak = 0;
  const response = (value) => ({ ok: true, status: 200, json: async () => value });
  const result = await githubMainStatus(dir, async (url) => {
    if (url.endsWith(`/commits/${sha}/status`)) return response({ state: "success", statuses: [] });
    if (url.includes("/actions/runs?")) return response({ workflow_runs: workflows, total_count: workflows.length });
    const match = /\/actions\/runs\/(\d+)\/jobs/.exec(url);
    if (!match) throw new Error(`unexpected GitHub URL: ${url}`);
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((resolve) => setTimeout(resolve, 10));
    active -= 1;
    const id = Number(match[1]);
    return response({ jobs: [{ ...sentinelRun("success", id, "10"), run_id: id, run_attempt: 1 }], total_count: 1 });
  }, sha, 1500, SENTINEL);
  assert.equal(result.state, "green");
  assert.equal(peak, 4, "the reader uses the reviewed four-request concurrency bound");
});

test("the API base is an env-var seam and only the real API receives the token", () => {
  assert.equal(apiBaseUrl(undefined), "https://api.github.com");
  assert.equal(apiBaseUrl("https://api.github.com/"), "https://api.github.com", "a trailing slash must not silently drop auth");
  assert.equal(apiBaseUrl("http://127.0.0.1:8080///"), "http://127.0.0.1:8080");
  const committed = JSON.parse(fs.readFileSync(path.join(root, "flywheel.guard.json"), "utf8"));
  assert.equal("githubApiBase" in committed, false, "the API base must never become a committed config key");
});

test("omitting the sentinel key keeps the legacy all-checks behavior", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const runs = [...POLLUTION, sentinelRun("success", 11, "14")];
  for (const checkNames of [undefined, []]) {
    const legacy = await sentinelStatus(dir, runs, checkNames, { state: "success", statuses: [{ state: "success" }] });
    assert.equal(legacy.state, "red", "without the key any failing check still reds main");
    assert.ok(legacy.failing.includes("credential_failure"));
  }
});

// Legacy mode is what a vendoring repository gets if it forgets the key, and `filter=all`
// now hands it the superseded runs that `filter=latest` used to hide. Scanning every run
// for a red conclusion would make one cancelled run a permanent red for that repository,
// with no way to clear it. Each name is judged on its latest completed run instead.
test("legacy mode judges each check on its latest completed run", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const green = { state: "success", statuses: [{ state: "success" }] };

  const superseded = await sentinelStatus(dir, [sentinelRun("cancelled", 80, "05"), sentinelRun("success", 81, "20")], undefined, green);
  assert.equal(superseded.state, "green", "a cancelled run replaced by a later success no longer reds main forever");

  const regressed = await sentinelStatus(dir, [sentinelRun("success", 82, "05"), sentinelRun("failure", 83, "20")], undefined, green);
  assert.equal(regressed.state, "red", "but the latest completed run still decides");
  assert.deepEqual(regressed.failing, SENTINEL);

  // The legacy contract itself is untouched: with no sentinel key, a foreign job's failure
  // is still main's failure. That is exactly why this repository configures the key.
  const foreign = await sentinelStatus(dir, [...POLLUTION, sentinelRun("success", 84, "20")], undefined, green);
  assert.equal(foreign.state, "red");
  assert.deepEqual(foreign.failing.sort(), ["Weekly drill", "credential_failure"], "every foreign name still counts in legacy mode");
});

test("human push onto red main proceeds and leaves audit evidence", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-red-human-"));
  const ci = { state: "red", sha: "e".repeat(40), failing: SENTINEL };
  const gate = redMainGate(dir, ci, identity("human:Kevin"));
  assert.equal(gate.blocked, false);
  const row = JSON.parse(fs.readFileSync(path.join(dir, "flywheel-guard-audit.jsonl"), "utf8").trim());
  assert.equal(row.kind, "ci-status");
  assert.equal(row.value, "red");
  assert.equal(row.class, "human");
  assert.equal(row.identity, "human:Kevin");
  assert.equal(row.sha, ci.sha, "the red sha is recorded because pre-push cannot rewrite the commit");
  assert.deepEqual(row.failing, SENTINEL);
});

test("unset identity on red main proceeds but records class unknown", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-red-unset-"));
  const gate = redMainGate(dir, { state: "red", sha: "f".repeat(40), failing: [] }, null);
  assert.equal(gate.blocked, false);
  const row = JSON.parse(fs.readFileSync(path.join(dir, "flywheel-guard-audit.jsonl"), "utf8").trim());
  assert.equal(row.class, "unknown", "an unset identity is not on the human ratification list");
  assert.equal(row.identity, "unset");
});

test("an unwritable audit never fail-closes a human push onto red main", () => {
  const missing = path.join(os.tmpdir(), "flywheel-red-no-such-dir", "gitdir");
  const gate = redMainGate(missing, { state: "red", sha: "b".repeat(40), failing: SENTINEL }, identity("human:Kevin"));
  assert.equal(gate.blocked, false, "the audit write is evidence, not an additional gate");
});

test("the sentinel key must be an array of names, never a bare string", () => {
  assert.deepEqual(sentinelNames(undefined), []);
  assert.deepEqual(sentinelNames(["  Offline contract suite  "]), SENTINEL);
  for (const bad of ["Offline contract suite", 7, {}, [""], ["ok", 3]]) {
    assert.throws(() => sentinelNames(bad), /array of non-empty Actions job names/);
  }
});

// Every Actions job GitHub could publish, across every workflow. A job is named by its
// job-level `name:` when it has one and by its job id when it
// does not, so BOTH are matchable — fliff's sentinel is `ci.yml`'s `changes` job, which
// carries no `name:` at all. Scanning the whole directory rather than a hard-coded
// `main-status.yml` is what makes this test portable: komplex's sentinel workflow lives
// on an unmerged branch, and a vendoring repo is free to name the file anything.
// A top-level YAML key's body: every following line that is blank or indented, stopping at
// the next column-0 line. Enough for the shapes GitHub workflows actually use, and it
// fails loudly (empty body -> a named assertion below) rather than guessing.
function yamlBlock(text, key, indent = 0) {
  const lines = text.split("\n");
  const head = new RegExp(`^ {${indent}}${key}:`);
  const start = lines.findIndex((line) => head.test(line));
  if (start < 0) return null;
  const body = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim() && !new RegExp(`^ {${indent + 1},}`).test(line)) break;
    body.push(line);
  }
  return body.join("\n");
}

function workflowJobs(workflowsDir) {
  // ENOENT here means the repository has no workflows directory at all, which is the same
  // dead-halt condition as an empty one — report it, do not throw a stack trace.
  let entries;
  try { entries = fs.readdirSync(workflowsDir); }
  catch { entries = []; }
  const files = entries.filter((file) => /\.ya?ml$/.test(file));
  const jobs = [];
  for (const file of files) {
    const text = fs.readFileSync(path.join(workflowsDir, file), "utf8");
    const start = text.search(/^jobs:\s*$/m);
    if (start < 0) continue;
    const on = yamlBlock(text, "on") ?? "";
    const push = yamlBlock(on, "push", 2);
    for (const block of text.slice(start).split(/^ {2}(?=[\w.-]+:\s*$)/m).slice(1)) {
      const id = /^([\w.-]+):\s*$/m.exec(block)?.[1];
      if (!id) continue;
      const name = /^ {4}name:\s*(.+?)\s*$/m.exec(block)?.[1].replace(/^["']|["']$/g, "");
      jobs.push({ file, id, name, block, push });
    }
  }
  return { files, jobs };
}

// A job that matches by name is not enough: the workflow has to actually RUN on every
// `main` head. A schedule-only workflow, or one with a `paths`/`paths-ignore` filter,
// produces no Actions job for an ordinary commit, so the sentinel reads `pending` and the
// halt is dead — the same silent failure as a rename, from a different direction.
function triggerProblem(job) {
  if (job.push === null || job.push === undefined) return `${job.file} has no \`push:\` trigger, so it produces no Actions job on a main head`;
  if (/^\s*paths(-ignore)?:/m.test(job.push)) return `${job.file} filters its push trigger by \`paths\`/\`paths-ignore\`, so a commit outside those paths leaves main with no status`;
  const branches = yamlBlock(job.push, "branches", 4) ?? "";
  const inline = /^ {4}branches:\s*\[(.+)\]\s*$/m.exec(job.push)?.[1] ?? "";
  const listed = [...branches.matchAll(/-\s*["']?([\w.*/-]+)["']?/g)].map((match) => match[1])
    .concat(inline.split(",").map((entry) => entry.trim().replace(/^["']|["']$/g, "")));
  if (listed.length && !listed.includes("main")) return `${job.file} has a push trigger, but not on \`main\` (found: ${listed.join(", ")})`;
  return null;
}

function assertSentinelCoupling(configured, workflowsDir) {
  const { files, jobs } = workflowJobs(workflowsDir);
  // Not a skip: no workflows means no Actions job on any head, so main reads permanently
  // `pending` and the halt is dead code. That is the failure, not an absent precondition.
  assert.ok(files.length, `no workflow files under ${workflowsDir}: every configured red-main check would be permanently pending`);
  const candidates = jobs.map((job) => job.name || job.id);
  for (const name of configured) {
    // An Actions job is named by the job-level `name:` if present, otherwise by the job id.
    const job = jobs.find((candidate) => candidate.name === name) || jobs.find((candidate) => !candidate.name && candidate.id === name);
    assert.ok(job, `redMainCheckNames "${name}" matches no job name or job id under ${workflowsDir} (found: ${candidates.join(", ")})`);
    // GitHub names a matrixed Actions job `<name> (<matrix values>)`. That never equals
    // the configured name, so main would read permanently `pending` and the halt would be
    // dead code — the same silent failure a rename causes, with no rename to notice.
    // `[ \t]`, not `\s`: `\s` spans newlines, so `^\s+` could match across a line break and
    // find a `matrix:` that is not indented under this job at all.
    assert.doesNotMatch(job.block, /^[ \t]+(strategy|matrix):/m, `the "${name}" job in ${job.file} must not be matrixed: its Actions job name would gain a suffix and never match redMainCheckNames`);
    assert.equal(triggerProblem(job), null, `the "${name}" job cannot decide red-main: ${triggerProblem(job)}`);
  }
}

test("configured red-main check names match a real job in some workflow", () => {
  const configured = JSON.parse(fs.readFileSync(path.join(root, "flywheel.guard.json"), "utf8")).redMainCheckNames;
  assert.deepEqual(sentinelNames(configured), configured, "the committed key must satisfy the guard's own validator");
  assert.ok(configured.length, "the canary pins the sentinel; an empty list silently restores all-checks behavior");
  assertSentinelCoupling(configured, path.join(root, ".github", "workflows"));
});

// The same coupling has to hold in the repositories that vendor this guard, whose
// sentinels do not look like this one's. Fixtures, so the canary's own tree does not have
// to grow a workflow it never runs.
test("the sentinel coupling is portable across vendoring layouts", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-workflows-"));
  const write = (file, body) => fs.writeFileSync(path.join(dir, file), body);
  const PUSH_MAIN = "on:\n  push:\n    branches:\n      - main\n";

  // fliff: the sentinel job has no job-level `name:`, so GitHub names the Actions job after
  // the job id. Matching only `name:` would reject a correctly configured repository.
  write("ci.yml", `name: CI\n${PUSH_MAIN}jobs:\n  changes:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n`);
  assertSentinelCoupling(["changes"], dir);

  // A named job in a differently-named file still matches: nothing here is coupled to the
  // filename `main-status.yml`. Inline branch lists are the same trigger.
  write("status.yaml", "on:\n  push:\n    branches: [main, release]\njobs:\n  offline:\n    name: Offline contract suite\n    runs-on: ubuntu-latest\n");
  assertSentinelCoupling(["Offline contract suite", "changes"], dir);

  // A job id is matchable only when the job has no name of its own; once GitHub is
  // publishing `Offline contract suite`, nothing is ever published as `offline`.
  assert.throws(() => assertSentinelCoupling(["offline"], dir), /matches no job name or job id/);
  assert.throws(() => assertSentinelCoupling(["Nonexistent suite"], dir), /matches no job name or job id/);

  write("matrixed.yml", `${PUSH_MAIN}jobs:\n  spread:\n    strategy:\n      matrix:\n        node: [22, 24]\n    runs-on: ubuntu-latest\n`);
  assert.throws(() => assertSentinelCoupling(["spread"], dir), /must not be matrixed/);

  // A job can match by name and still be unable to decide red-main. Each of these leaves
  // an ordinary `main` commit with no Actions job, so the sentinel reads pending forever.
  write("scheduled.yml", "on:\n  schedule:\n    - cron: \"0 3 * * *\"\njobs:\n  nightly:\n    runs-on: ubuntu-latest\n");
  assert.throws(() => assertSentinelCoupling(["nightly"], dir), /has no `push:` trigger/);

  write("filtered.yml", `on:\n  push:\n    branches:\n      - main\n    paths-ignore:\n      - "**.md"\njobs:\n  filtered:\n    runs-on: ubuntu-latest\n`);
  assert.throws(() => assertSentinelCoupling(["filtered"], dir), /paths-ignore/, "a docs-only commit would clear a standing red-main halt");

  write("wrongbranch.yml", "on:\n  push:\n    branches:\n      - develop\njobs:\n  elsewhere:\n    runs-on: ubuntu-latest\n");
  assert.throws(() => assertSentinelCoupling(["elsewhere"], dir), /not on `main`/);

  const empty = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-workflows-empty-"));
  fs.writeFileSync(path.join(empty, "README.md"), "not a workflow\n");
  assert.throws(() => assertSentinelCoupling(["Offline contract suite"], empty), /no workflow files under/, "an empty workflows directory fails loudly rather than skipping");

  // Absent entirely, not merely empty: the same dead halt, and it must not surface as a
  // raw ENOENT stack trace from readdirSync.
  assert.throws(() => assertSentinelCoupling(["Offline contract suite"], path.join(empty, "no-such-dir")), /no workflow files under/);
});

test("worker push onto red main is blocked and writes no audit row", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-red-worker-"));
  const gate = redMainGate(dir, { state: "red", sha: "a".repeat(40), failing: SENTINEL }, identity("worker:codex-o01"));
  assert.equal(gate.blocked, true);
  assert.match(gate.reason, /red GitHub checks: Offline contract suite/);
  assert.equal(fs.existsSync(path.join(dir, "flywheel-guard-audit.jsonl")), false);
});

// An origin path ending in `github.com/<owner>/<repo>.git` satisfies the guard's remote
// parser while `git ls-remote` still resolves locally, so the whole pre-push leg — real
// hooks entry point, real stdin, real ls-remote — runs with no network at all.
function prePushFixture() {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-prepush-"));
  const origin = path.join(fixture, "github.com", "kjgryboski", "canary.git");
  fs.mkdirSync(origin, { recursive: true });
  git(origin, "init", "--bare", "-b", "main");
  const dir = path.join(fixture, "clone");
  fs.mkdirSync(dir);
  git(dir, "init", "-b", "main");
  git(dir, "config", "user.name", "Flywheel Test");
  git(dir, "config", "user.email", "flywheel-test@example.invalid");
  fs.writeFileSync(path.join(dir, "file.txt"), "guard test\n");
  git(dir, "add", "file.txt");
  git(dir, "commit", "-m", "seed");
  git(dir, "remote", "add", "origin", origin.replaceAll("\\", "/"));
  git(dir, "push", "--quiet", "origin", "main");
  // What `ls-remote` will resolve as origin/main HEAD, and therefore the sha the guard
  // judges and records — distinct from the local head now that there is a commit to push.
  const remoteHead = git(dir, "rev-parse", "HEAD").trim();
  // A SECOND commit, deliberately. `outgoing()` runs `git diff-tree ... -r <sha>` without
  // `--root`, which emits NOTHING for a root commit — so a fixture that pushed only the
  // seed made every pre-push test short-circuit on an empty path list, and the whole
  // reservation leg (conflicts, fail-open, the fail-open audit row) was never executed.
  fs.mkdirSync(path.join(dir, "src"), { recursive: true });
  fs.writeFileSync(path.join(dir, "src", "outgoing.mjs"), "export const outgoing = true;\n");
  git(dir, "add", "src/outgoing.mjs");
  git(dir, "commit", "-m", "outgoing change");
  const head = git(dir, "rev-parse", "HEAD").trim();
  return { dir, head, remoteHead, stdin: `refs/heads/main ${head} refs/heads/main ${"0".repeat(40)}\n` };
}

// Proves the fixture actually feeds paths to the reservation leg, so the assertions in the
// pre-push tests below are exercising it rather than an empty-list short circuit.
test("the pre-push fixture produces real outgoing paths", () => {
  const fixture = prePushFixture();
  const named = git(fixture.dir, "diff-tree", "--no-commit-id", "--name-only", "-r", fixture.head).trim();
  assert.equal(named, "src/outgoing.mjs", "a root-commit fixture would make this empty and silently skip the leg");
});

async function listen(handler) {
  const server = http.createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => handler(request, body, response));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

async function redMainServers(checkRuns, checksBody = {}) {
  const mail = await listen((request, body, response) => {
    const parsed = JSON.parse(body);
    const isResource = parsed.method === "resources/read";
    response.writeHead(200, { "content-type": "application/json" });
    response.end(rpc(parsed.id, isResource ? [] : { conflict_free: true, conflicts: [] }, isResource));
  });
  const api = await listen((request, _body, response) => {
    let value;
    if (request.url.includes("/commits/") && request.url.endsWith("/status")) {
      value = { state: "pending", statuses: [] };
    } else if (request.url.includes("/actions/runs?")) {
      value = { workflow_runs: [{ id: 1, run_attempt: Math.max(1, ...checkRuns.map((run) => Number(run.run_attempt) || 1)) }], total_count: checksBody.total_count ?? 1 };
    } else if (request.url.includes("/actions/runs/1/jobs")) {
      value = { jobs: checkRuns, total_count: checksBody.job_total_count ?? checkRuns.length };
    } else {
      response.writeHead(500, { "content-type": "application/json" });
      response.end(JSON.stringify({ message: `unexpected URL ${request.url}` }));
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(value));
  });
  return { mail, api, close: () => { mail.server.close(); api.server.close(); } };
}

test("Actions stub server supplies jobs, ranks attempts, and never receives a check-runs request", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const urls = [];
  const sha = "f".repeat(40);
  const api = await listen((request, _body, response) => {
    urls.push(request.url);
    let value;
    if (request.url.endsWith(`/commits/${sha}/status`)) value = { state: "success", statuses: [] };
    else if (request.url.includes("/actions/runs?")) value = { workflow_runs: [{ id: 41, run_attempt: 2 }], total_count: 1 };
    else if (request.url.includes("/actions/runs/41/jobs")) value = { jobs: [
      { ...sentinelRun("failure", 999, "59"), run_id: 41, run_attempt: 1 },
      { ...sentinelRun("success", 1, "01"), run_id: 41, run_attempt: 2 },
    ], total_count: 2 };
    else { response.writeHead(500); response.end(); return; }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(value));
  });
  try {
    const result = await githubMainStatus(dir, fetch, sha, 1500, SENTINEL, api.url);
    assert.equal(result.state, "green");
    assert.equal(urls.some((url) => url.includes("/check-runs")), false);
    assert.ok(urls.some((url) => url.includes(`/actions/runs?head_sha=${sha}&per_page=100&page=1`)));
    assert.ok(urls.some((url) => url.includes("/actions/runs/41/jobs?filter=all&per_page=100")));
  } finally {
    api.server.close();
  }
});

test("a non-rate-limited 403 on the Actions runs read is unauthenticated", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const sha = "e".repeat(40);
  const api = await listen((request, _body, response) => {
    if (request.url.endsWith(`/commits/${sha}/status`)) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ state: "success", statuses: [] }));
      return;
    }
    response.writeHead(403, { "content-type": "application/json", "x-ratelimit-remaining": "4999" });
    response.end(JSON.stringify({ message: "Resource not accessible by personal access token" }));
  });
  try {
    const result = await githubMainStatus(dir, fetch, sha, 1500, SENTINEL, api.url);
    assert.deepEqual([result.state, result.cause], ["unknown", "unauthenticated"]);
  } finally {
    api.server.close();
  }
});

test("pre-push on a red main: human proceeds with exactly one audit row, worker is blocked", async () => {
  const failed = [{ name: SENTINEL[0], status: "completed", conclusion: "failure", id: 1, completed_at: "2026-09-01T10:00:00Z" }];

  const human = prePushFixture();
  let servers = await redMainServers(failed);
  let configFile = config(human.dir, {
    agentMailUrl: `${servers.mail.url}/mcp/`,
    redMainCheckNames: SENTINEL,
  });
  const humanRun = await run(human.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: "human:Kevin",
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_API_BASE: servers.api.url,
  }, human.stdin);
  servers.close();
  assert.equal(humanRun.code, 0, humanRun.stderr);
  assert.match(humanRun.stderr, /is RED \(Offline contract suite\)/);
  const rows = fs.readFileSync(path.join(human.dir, ".git", "flywheel-guard-audit.jsonl"), "utf8").split("\n").filter(Boolean);
  assert.equal(rows.length, 1, `expected exactly one audit row, got: ${rows.join(" | ")}`);
  const row = JSON.parse(rows[0]);
  // The RED sha is origin/main's head, not the local head being pushed: the guard judges
  // the head you are pushing ONTO. Those are now different commits in the fixture.
  assert.deepEqual([row.kind, row.value, row.class, row.sha], ["ci-status", "red", "human", human.remoteHead]);
  assert.notEqual(human.remoteHead, human.head, "the fixture has real outgoing work, so the two shas must differ");

  const worker = prePushFixture();
  servers = await redMainServers(failed);
  configFile = config(worker.dir, {
    agentMailUrl: `${servers.mail.url}/mcp/`,
    redMainCheckNames: SENTINEL,
    workerClones: [{ alias: "codex-o01", path: worker.dir, mailAgent: "CalmRiver" }],
  });
  const workerRun = await run(worker.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: "worker:codex-o01",
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_API_BASE: servers.api.url,
  }, worker.stdin);
  servers.close();
  assert.equal(workerRun.code, 1);
  assert.match(workerRun.stderr, /BLOCKED: origin\/main .* red GitHub checks: Offline contract suite/);
  assert.equal(fs.existsSync(path.join(worker.dir, ".git", "flywheel-guard-audit.jsonl")), false);
});

// Pending proceeds — but a sentinel that only ever skipped never tested the head at all, and
// that is not the same as "the answer is not in yet". A worker does not push onto a head no
// check has judged; a human is warned, by name, and proceeds.
test("pre-push on a skipped-only sentinel blocks a worker naming the check and warns a human", async () => {
  const skipped = [{ name: SENTINEL[0], status: "completed", conclusion: "skipped", id: 1, completed_at: "2026-09-01T10:00:00Z" }];

  const worker = prePushFixture();
  let servers = await redMainServers(skipped);
  let configFile = config(worker.dir, {
    agentMailUrl: `${servers.mail.url}/mcp/`,
    redMainCheckNames: SENTINEL,
    workerClones: [{ alias: "codex-o01", path: worker.dir, mailAgent: "CalmRiver" }],
  });
  const workerRun = await run(worker.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: "worker:codex-o01",
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_API_BASE: servers.api.url,
  }, worker.stdin);
  servers.close();
  assert.equal(workerRun.code, 1, `a skipped-only sentinel must not read green for a worker:\n${workerRun.stderr}`);
  assert.match(workerRun.stderr, /BLOCKED: .*never tested.*Offline contract suite.*skipped\/neutral/);
  // Recorded before the block, like the unauthenticated row (#22 review, N2): a grey skip is
  // not a red main, so this row is the only trace of a worker wedged on it.
  const rows = fs.readFileSync(path.join(worker.dir, ".git", "flywheel-guard-audit.jsonl"), "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
  assert.equal(rows.length, 1, `expected exactly one audit row, got ${rows.length}`);
  assert.deepEqual([rows[0].kind, rows[0].value, rows[0].blocked, rows[0].class, rows[0].identity, rows[0].undecided], ["ci-status", "undecided", true, "worker", "worker:codex-o01", SENTINEL]);
  assert.equal(typeof rows[0].sha, "string", "the origin/main head the guard judged");

  const human = prePushFixture();
  servers = await redMainServers(skipped);
  configFile = config(human.dir, { agentMailUrl: `${servers.mail.url}/mcp/`, redMainCheckNames: SENTINEL });
  const humanRun = await run(human.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: "human:Kevin",
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_API_BASE: servers.api.url,
  }, human.stdin);
  servers.close();
  assert.equal(humanRun.code, 0, humanRun.stderr);
  assert.match(humanRun.stderr, /configured red-main check "Offline contract suite" has only skipped\/neutral runs/);
  assert.doesNotMatch(humanRun.stderr, /BLOCKED|is RED/, "undecided is pending for a human, not red");
  assert.equal(fs.existsSync(path.join(human.dir, ".git", "flywheel-guard-audit.jsonl")), false, "pending for a human leaves no row, like stalled and missing");
});

// A directory where the JSONL belongs: `appendFileSync` fails with EISDIR on every
// platform, with no chmod and no root-versus-user asymmetry.
function unwritableAudit(dir) {
  fs.mkdirSync(path.join(dir, ".git", "flywheel-guard-audit.jsonl"));
}

// Every fail-open path writes an audit row, and every one of those writes was capable of
// throwing. AGENTS.md §11 says Mail unreachable + human class fails open and "the commit
// proceeds"; §7 says the same for an unreachable GitHub. An unwritable audit file turned
// all three into hard blocks on a human — the outage became the gate.
test("an unwritable audit never fail-closes a human push on any fail-open path", async () => {
  const mailStub = (request, body, response) => {
    const parsed = JSON.parse(body);
    const isResource = parsed.method === "resources/read";
    response.writeHead(200, { "content-type": "application/json" });
    response.end(rpc(parsed.id, isResource ? [] : { conflict_free: true, conflicts: [] }, isResource));
  };

  // 1. pre-push, GitHub unreachable: the `ci-status: unknown` row.
  const unknown = prePushFixture();
  const mail = await listen(mailStub);
  const api = await listen((_request, _body, response) => {
    response.writeHead(503, { "content-type": "application/json" });
    response.end("{}");
  });
  unwritableAudit(unknown.dir);
  let configFile = config(unknown.dir, { agentMailUrl: `${mail.url}/mcp/`, redMainCheckNames: SENTINEL });
  const unknownRun = await run(unknown.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: "human:Kevin",
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_API_BASE: api.url,
  }, unknown.stdin);
  mail.server.close();
  api.server.close();
  assert.equal(unknownRun.code, 0, unknownRun.stderr);
  assert.match(unknownRun.stderr, /CI-Status: unknown/);
  assert.match(unknownRun.stderr, /could not record the unknown-status audit row/, "the lost evidence is reported, not swallowed");

  // 2. pre-push, Mail unreachable: the reservation `fail-open` row. Port 1 is closed, so
  // the reservation check throws and a human fails open — with real outgoing paths, which
  // is what makes this leg reachable at all.
  const failOpen = prePushFixture();
  unwritableAudit(failOpen.dir);
  configFile = config(failOpen.dir, { agentMailUrl: "http://127.0.0.1:1/mcp/", redMainCheckNames: SENTINEL });
  const pushRun = await run(failOpen.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: "human:Kevin",
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_API_BASE: "http://127.0.0.1:1",
  }, failOpen.stdin);
  assert.equal(pushRun.code, 0, pushRun.stderr);
  assert.match(pushRun.stderr, /could not record the fail-open audit row/, "the pre-push fail-open row is wrapped too");
  assert.doesNotMatch(pushRun.stderr, /BLOCKED/, "an unreachable Mail plus an unwritable audit is still a fail-open for a human");

  // 3. pre-commit, Mail unreachable: the same row on the commit leg.
  const commit = prePushFixture();
  unwritableAudit(commit.dir);
  fs.writeFileSync(path.join(commit.dir, "staged.txt"), "staged\n");
  git(commit.dir, "add", "staged.txt");
  configFile = config(commit.dir, { agentMailUrl: "http://127.0.0.1:1/mcp/", redMainCheckNames: SENTINEL });
  const commitRun = await run(commit.dir, ["--phase", "pre-commit"], {
    FLYWHEEL_AGENT_ID: "human:Kevin",
    FLYWHEEL_GUARD_CONFIG: configFile,
  });
  assert.equal(commitRun.code, 0, commitRun.stderr);
  assert.match(commitRun.stderr, /could not record the fail-open audit row/);
  assert.doesNotMatch(commitRun.stderr, /BLOCKED/, "AGENTS.md 11: Mail unreachable, human class, the commit proceeds");
});

// The mirror image: a WORKER bypass whose row cannot be written leaves no durable
// evidence anywhere, which §5 does not allow. Evidence is the price of the escape hatch.
test("a worker bypass fails closed when it cannot leave durable evidence", async () => {
  const worker = prePushFixture();
  unwritableAudit(worker.dir);
  const configFile = config(worker.dir, {
    redMainCheckNames: SENTINEL,
    workerClones: [{ alias: "codex-o01", path: worker.dir, mailAgent: "CalmRiver" }],
  });
  const blocked = await run(worker.dir, ["--phase", "pre-commit"], {
    FLYWHEEL_AGENT_ID: "worker:codex-o01",
    FLYWHEEL_GUARD_BYPASS: "no evidence possible",
    FLYWHEEL_GUARD_CONFIG: configFile,
  });
  assert.equal(blocked.code, 1);
  assert.match(blocked.stderr, /BLOCKED: bypass refused/);

  // A human bypass on the same unwritable file still proceeds: the warning is the record,
  // and a human is answerable for it.
  const human = prePushFixture();
  unwritableAudit(human.dir);
  const humanConfig = config(human.dir, { redMainCheckNames: SENTINEL });
  const allowed = await run(human.dir, ["--phase", "pre-commit"], {
    FLYWHEEL_AGENT_ID: "human:Kevin",
    FLYWHEEL_GUARD_BYPASS: "bounded test",
    FLYWHEEL_GUARD_CONFIG: humanConfig,
  });
  assert.equal(allowed.code, 0, allowed.stderr);
  assert.match(allowed.stderr, /could not record the bypass audit row/);
});

test("an explicitly empty sentinel list is a config error, not silent legacy mode", async () => {
  const fixture = prePushFixture();
  const configFile = config(fixture.dir, { redMainCheckNames: [] });
  const result = await run(fixture.dir, ["--phase", "pre-commit"], {
    FLYWHEEL_AGENT_ID: "human:Kevin",
    FLYWHEEL_GUARD_CONFIG: configFile,
  });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /redMainCheckNames is an empty array; omit the key/);
});

// "Pending" normally means the guard looked and the answer is not in yet. Truncated PLUS
// an absent sentinel means the guard may simply never have reached the run — the same
// verdict for a materially different reason. Pushes still proceed, but the gap is
// recorded, so a later audit can tell the two apart.
test("a truncated list hiding the sentinel is recorded as truncated-missing and still proceeds", async () => {
  const fixture = prePushFixture();
  // total_count far above what any page returns, and the sentinel in none of them.
  const servers = await redMainServers(POLLUTION, { total_count: 900 });
  const configFile = config(fixture.dir, {
    agentMailUrl: `${servers.mail.url}/mcp/`,
    redMainCheckNames: SENTINEL,
    workerClones: [{ alias: "codex-o01", path: fixture.dir, mailAgent: "CalmRiver" }],
  });
  const result = await run(fixture.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: "worker:codex-o01",
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_API_BASE: servers.api.url,
  }, fixture.stdin);
  servers.close();
  assert.equal(result.code, 0, result.stderr);
  assert.doesNotMatch(result.stderr, /BLOCKED/, "pending proceeds, even for a worker");
  assert.match(result.stderr, /recorded as truncated-missing/);
  const rows = fs.readFileSync(path.join(fixture.dir, ".git", "flywheel-guard-audit.jsonl"), "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const row = rows.find((candidate) => candidate.kind === "truncated-missing");
  assert.ok(row, `no truncated-missing row; got: ${rows.map((r) => r.kind).join(", ") || "(none)"}`);
  assert.deepEqual(row.missing, SENTINEL);
  assert.equal(row.sha, fixture.remoteHead);
  assert.equal(row.pages, 3, "the row says how hard the guard looked before giving up");
});

test("pre-push warns when a configured sentinel check has no run on the head", async () => {
  const fixture = prePushFixture();
  const servers = await redMainServers([{ name: "credential_failure", status: "completed", conclusion: "failure", id: 4, completed_at: "2026-09-01T10:00:00Z" }]);
  const configFile = config(fixture.dir, {
    agentMailUrl: `${servers.mail.url}/mcp/`,
    redMainCheckNames: SENTINEL,
    workerClones: [{ alias: "codex-o01", path: fixture.dir, mailAgent: "CalmRiver" }],
  });
  const result = await run(fixture.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: "worker:codex-o01",
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_API_BASE: servers.api.url,
  }, fixture.stdin);
  servers.close();
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stderr, /configured red-main check "Offline contract suite" has no run/);
  assert.doesNotMatch(result.stderr, /BLOCKED/, "a missing sentinel is pending, and pending proceeds");
});

test("an invalid sentinel key blocks loudly at commit time, naming the config file", async () => {
  const fixture = prePushFixture();
  const configFile = config(fixture.dir, { redMainCheckNames: "Offline contract suite" });
  // pre-commit, not pre-push: a worker must learn the halt is misconfigured before doing
  // an hour of work, and the message has to say which file to fix.
  for (const [phase, stdin] of [["pre-commit", ""], ["pre-push", fixture.stdin]]) {
    const result = await run(fixture.dir, ["--phase", phase], {
      FLYWHEEL_AGENT_ID: "human:Kevin",
      FLYWHEEL_GUARD_CONFIG: configFile,
    }, stdin);
    assert.equal(result.code, 1, `${phase} should have blocked`);
    assert.match(result.stderr, /BLOCKED: .*flywheel\.guard\.json: redMainCheckNames must be an array/);
  }
});

test("live main status returns unknown on a bounded API timeout", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const started = performance.now();
  const result = await githubMainStatus(dir, () => new Promise(() => {}), "c".repeat(40), 25);
  assert.equal(result.state, "unknown");
  assert.match(result.reason, /timeout/);
  assert.ok(performance.now() - started < 500);
});

test("human Mail outage proceeds and commit-msg adds a fail-open trailer", async () => {
  const dir = repo();
  const configFile = config(dir);
  const message = path.join(dir, "message.txt");
  fs.writeFileSync(message, "docs: exercise guard\n");
  const result = await run(dir, ["--phase", "commit-msg", message], {
    FLYWHEEL_AGENT_ID: "human:Kevin",
    FLYWHEEL_GUARD_CONFIG: configFile,
  });
  assert.equal(result.code, 0, result.stderr);
  assert.match(fs.readFileSync(message, "utf8"), /^Flywheel-Guard: fail-open /m);
  assert.match(fs.readFileSync(message, "utf8"), /^Flywheel-Identity: human:Kevin$/m);
});

test("worker Mail outage fails closed", async () => {
  const dir = repo();
  const configFile = config(dir, {
    workerClones: [{ alias: "codex-o01", path: dir, mailAgent: "CalmRiver" }],
  });
  const result = await run(dir, ["--phase", "pre-commit"], {
    FLYWHEEL_AGENT_ID: "worker:codex-o01",
    FLYWHEEL_GUARD_CONFIG: configFile,
  });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /BLOCKED:.*(fetch failed|Agent Mail)/s);
});

test("registered worker clone blocks missing worker identity", async () => {
  const dir = repo();
  const configFile = config(dir, {
    workerClones: [{ alias: "codex-o01", path: dir, mailAgent: "CalmRiver" }],
  });
  const result = await run(dir, ["--phase", "pre-commit"], { FLYWHEEL_GUARD_CONFIG: configFile });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /requires FLYWHEEL_AGENT_ID=worker:codex-o01/);
});

test("active reservation conflict blocks with holder and thread attribution", async () => {
  const server = http.createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const parsed = JSON.parse(body);
      const isResource = parsed.method === "resources/read";
      const value = isResource
        ? [{ agent: "StoneOwl", path_pattern: "src/**", reason: "canary-drill-2", expires_ts: "2099-01-01T00:00:00Z", released_ts: null }]
        : { conflict_free: false, conflicts: [{ path: "src/file.mjs", holders: [{ agent: "StoneOwl", path_pattern: "src/**", exclusive: true, expires_ts: "2099-01-01T00:00:00Z" }] }] };
      response.writeHead(200, { "content-type": "application/json" });
      response.end(rpc(parsed.id, value, isResource));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const dir = repo();
  fs.mkdirSync(path.join(dir, "src"));
  fs.writeFileSync(path.join(dir, "src", "file.mjs"), "export {};\n");
  git(dir, "add", "src/file.mjs");
  const { port } = server.address();
  const configFile = config(dir, { agentMailUrl: `http://127.0.0.1:${port}/mcp/` });
  const result = await run(dir, ["--phase", "pre-commit"], {
    FLYWHEEL_AGENT_ID: "human:Kevin",
    FLYWHEEL_GUARD_CONFIG: configFile,
  });
  server.close();
  assert.equal(result.code, 1);
  assert.match(result.stderr, /StoneOwl \(thread canary-drill-2\)/);
});

test("expired reservation is reported but not enforced", async () => {
  const server = http.createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const parsed = JSON.parse(body);
      const isResource = parsed.method === "resources/read";
      const value = isResource
        ? [{ agent: "StoneOwl", path_pattern: "file.txt", reason: "old-drill", expires_ts: "2000-01-01T00:00:00Z", released_ts: null }]
        : { conflict_free: true, conflicts: [] };
      response.writeHead(200, { "content-type": "application/json" });
      response.end(rpc(parsed.id, value, isResource));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const dir = repo();
  const { port } = server.address();
  const configFile = config(dir, { agentMailUrl: `http://127.0.0.1:${port}/mcp/` });
  const result = await run(dir, ["--phase", "pre-commit"], {
    FLYWHEEL_AGENT_ID: "human:Kevin",
    FLYWHEEL_GUARD_CONFIG: configFile,
  });
  server.close();
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stderr, /expired reservation ignored/);
});

test("bypass is recorded and sent to Agent Mail when configured", async () => {
  const calls = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const parsed = JSON.parse(body);
      calls.push(parsed);
      response.writeHead(200, { "content-type": "application/json" });
      response.end(rpc(parsed.id, { id: 99 }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const dir = repo();
  const { port } = server.address();
  const configFile = config(dir, {
    agentMailUrl: `http://127.0.0.1:${port}/mcp/`,
    audit: { sender: "CreamCompass", recipient: "CreamCompass" },
  });
  const result = await run(dir, ["--phase", "pre-commit"], {
    FLYWHEEL_AGENT_ID: "human:Kevin",
    FLYWHEEL_GUARD_BYPASS: "bounded test",
    FLYWHEEL_GUARD_CONFIG: configFile,
  });
  server.close();
  assert.equal(result.code, 0, result.stderr);
  assert.equal(calls[0].params.name, "send_message");
  assert.match(fs.readFileSync(path.join(dir, ".git", "flywheel-guard-audit.jsonl"), "utf8"), /"kind":"bypass"/);
});

test("CI mode is a sub-second no-op without a Git repository", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-guard-ci-"));
  const started = performance.now();
  const result = await run(dir, ["--phase", "pre-commit"], { CI: "1" });
  assert.equal(result.code, 0, result.stderr);
  assert.ok(performance.now() - started < 1000);
});

test("worker Bead validation fails before br when the shared database is missing", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-bead-missing-"));
  const missing = path.join(dir, "beads.db");
  let called = false;
  assert.throws(() => validateBead({
    br: { binary: nativeBrFixture(dir), database: missing },
  }, root, "codex-o01", "test\n\nBead: afc-1\n", () => {
    called = true;
    return { status: 0, stdout: "{}" };
  }), /shared Beads database is missing/);
  assert.equal(called, false);
});

test("worker Bead validation uses global flags and enforces assignee", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-bead-validation-"));
  const database = path.join(dir, "beads.db");
  fs.writeFileSync(database, "test fixture");
  const binary = nativeBrFixture(dir);
  const argsSeen = [];
  const runner = (_binary, args) => {
    argsSeen.push(args);
    return { status: 0, stdout: JSON.stringify({ id: "afc-1", status: "in_progress", assignee: "codex-o01" }) };
  };
  assert.equal(validateBead({ br: { binary, database } }, root, "codex-o01", "test\n\nBead: afc-1\n", runner), "afc-1");
  assert.deepEqual(argsSeen[0].slice(0, 2), ["--db", database]);
  assert.ok(argsSeen[0].indexOf("show") > argsSeen[0].indexOf("--actor"));

  assert.throws(() => validateBead({ br: { binary, database } }, root, "codex-o02", "test\n\nBead: afc-1\n", runner), /not codex-o02/);
  const missing = () => ({ status: 1, stdout: "" });
  assert.throws(() => validateBead({ br: { binary, database } }, root, "codex-o01", "test\n\nBead: afc-404\n", missing), /does not exist/);
  const terminal = () => ({ status: 0, stdout: JSON.stringify({ id: "afc-1", status: "closed", assignee: "codex-o01" }) });
  assert.throws(() => validateBead({ br: { binary, database } }, root, "codex-o01", "test\n\nBead: afc-1\n", terminal), /terminal/);
});

test("cold Linux repository install pins executable hooks and native Node", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-cold-install-"));
  git(dir, "init", "-b", "main");
  fs.cpSync(path.join(root, ".githooks"), path.join(dir, ".githooks"), { recursive: true });
  fs.mkdirSync(path.join(dir, "scripts"));
  fs.copyFileSync(path.join(root, "scripts", "install-flywheel-hooks.mjs"), path.join(dir, "scripts", "install-flywheel-hooks.mjs"));
  execFileSync(process.execPath, [path.join(dir, "scripts", "install-flywheel-hooks.mjs")], { cwd: dir });
  assert.equal(git(dir, "config", "--get", "core.hooksPath").trim(), ".githooks");
  assert.equal(git(dir, "config", "--get", "flywheel.nodePath").trim(), process.execPath);
  for (const hook of ["pre-commit", "commit-msg", "pre-push"]) {
    assert.notEqual(fs.statSync(path.join(dir, ".githooks", hook)).mode & 0o111, 0);
  }
});

// Every fleet repository is private, so an uncredentialed read answers 404 and the halt
// returns no verdict at all. These cover the credential, the two causes of `unknown`, and
// the rule that the token never reaches any output the operator or the audit ever sees.
// The fake token is assembled at runtime so no PAT-shaped literal exists in this source:
// this file is vendored into consuming repositories, where secret scanners (React Doctor's
// `no-secrets-in-client-code`, budget 0 in the Security category) fire on the prefix and
// red the owner exact-commit run. The runtime value keeps the realistic fine-grained-PAT
// prefix and length the redaction tests rely on.
const SECRET = ["github", "pat", "FAKEFIXTURE", "0123456789abcdef"].join("_");

test("the read token has a fixed precedence and a dedicated name wins", () => {
  assert.equal(githubReadToken({}), null);
  assert.equal(githubReadToken({ GH_TOKEN: "c" }).name, "GH_TOKEN");
  assert.equal(githubReadToken({ GITHUB_TOKEN: "b", GH_TOKEN: "c" }).name, "GITHUB_TOKEN");
  const all = githubReadToken({ FLYWHEEL_GITHUB_READ_TOKEN: "a", GITHUB_TOKEN: "b", GH_TOKEN: "c" });
  assert.deepEqual([all.name, all.value], ["FLYWHEEL_GITHUB_READ_TOKEN", "a"], "a write-scoped ambient token must never outrank the read token");
  assert.equal(githubReadToken({ FLYWHEEL_GITHUB_READ_TOKEN: "  \n " }), null, "whitespace is not a credential");
  assert.equal(githubReadToken({ FLYWHEEL_GITHUB_READ_TOKEN: " a " }).value, "a");
});

test("redaction removes the token from any text and tolerates no token", () => {
  assert.equal(redact(`Bearer ${SECRET} rejected`, SECRET), "Bearer [redacted] rejected");
  assert.equal(redact("plain outage", undefined), "plain outage");
  assert.equal(redact("plain outage", "short"), "plain outage", "a too-short value must not turn every message into confetti");
});

test("the token reaches only the real API, and an echoed token is redacted from the reason", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const previous = process.env.FLYWHEEL_GITHUB_READ_TOKEN;
  process.env.FLYWHEEL_GITHUB_READ_TOKEN = SECRET;
  try {
    const seen = [];
    const capture = async (_url, options) => { seen.push(options.headers.authorization); return { ok: true, status: 200, json: async () => ({ state: "success", statuses: [], workflow_runs: [], total_count: 0 }) }; };
    await githubMainStatus(dir, capture, "a".repeat(40));
    assert.deepEqual(seen, [`Bearer ${SECRET}`, `Bearer ${SECRET}`], "the real API must receive the credential or the halt cannot read a private repo");

    seen.length = 0;
    await githubMainStatus(dir, capture, "a".repeat(40), 1500, [], "http://127.0.0.1:1");
    assert.deepEqual(seen, [undefined, undefined], "an overridden base must never see the credential");

    const echoed = await githubMainStatus(dir, async () => { throw new Error(`upstream rejected Bearer ${SECRET}`); }, "a".repeat(40));
    assert.equal(echoed.cause, "unavailable");
    assert.doesNotMatch(echoed.reason, new RegExp(SECRET), "an echoed credential must not survive into the reason");
    assert.match(echoed.reason, /\[redacted\]/);
  } finally {
    if (previous === undefined) delete process.env.FLYWHEEL_GITHUB_READ_TOKEN;
    else process.env.FLYWHEEL_GITHUB_READ_TOKEN = previous;
  }
});

test("unknown carries a cause: a credential HTTP code is not an outage", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const at = (status) => githubMainStatus(dir, async () => ({ ok: false, status, json: async () => ({}) }), "a".repeat(40));
  for (const status of [401, 403, 404]) {
    const result = await at(status);
    assert.deepEqual([result.state, result.cause], ["unknown", "unauthenticated"], `HTTP ${status} means no usable credential`);
  }
  for (const status of [500, 502, 503, 429]) {
    const result = await at(status);
    assert.deepEqual([result.state, result.cause], ["unknown", "unavailable"], `HTTP ${status} is a transient outage`);
  }
  const timeout = await githubMainStatus(dir, () => new Promise(() => {}), "a".repeat(40), 25);
  assert.equal(timeout.cause, "unavailable");
});

test("an unauthenticated unknown blocks a worker and records the cause for a human", () => {
  const worker = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-unauth-worker-"));
  const gate = unknownMainGate(worker, { state: "unknown", sha: "a".repeat(40), cause: "unauthenticated", reason: "GitHub HTTP 404" }, identity("worker:codex-o01"));
  assert.equal(gate.blocked, true);
  assert.match(gate.reason, /red-main read is unauthenticated; set FLYWHEEL_GITHUB_READ_TOKEN/);
  assert.match(gate.reason, /or the repository is not visible to it/, "a 404 is equally what a repository the token cannot see returns");
  // Written BEFORE the block, unlike the red path: a worker wedged on an unreadable halt
  // leaves no other trace anywhere, so the fleet only learns about it from this row.
  const blockedRow = JSON.parse(fs.readFileSync(path.join(worker, "flywheel-guard-audit.jsonl"), "utf8").trim());
  assert.deepEqual([blockedRow.kind, blockedRow.cause, blockedRow.class, blockedRow.blocked], ["ci-status", "unauthenticated", "worker", true]);

  const human = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-unauth-human-"));
  const proceed = unknownMainGate(human, { state: "unknown", sha: "b".repeat(40), cause: "unauthenticated", reason: "GitHub HTTP 404" }, identity("human:Kevin"));
  assert.equal(proceed.blocked, false);
  const row = JSON.parse(fs.readFileSync(path.join(human, "flywheel-guard-audit.jsonl"), "utf8").trim());
  assert.deepEqual([row.kind, row.value, row.cause, row.class], ["ci-status", "unknown", "unauthenticated", "human"]);
});

test("an unavailable unknown blocks a worker and lets every other class proceed", () => {
  const worker = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-unavail-worker-"));
  const blocked = unknownMainGate(worker, { state: "unknown", sha: "c".repeat(40), cause: "unavailable", reason: "GitHub API timeout" }, identity("worker:codex-o01"));
  assert.equal(blocked.blocked, true, "an unreadable halt is not a green halt: the worker stops");
  assert.match(blocked.reason, /red-main read is unavailable/);
  // The remedy follows the LEG the reason names: an API-leg outage is not fixed by fetching.
  assert.match(blocked.reason, /GitHub's API did not answer/, "the block has to name the remedy for the leg that failed");
  assert.doesNotMatch(blocked.reason, /git fetch origin main/, "an API outage is not an ls-remote problem");
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(worker, "flywheel-guard-audit.jsonl"), "utf8").trim()).blocked, true);

  const lsRemote = unknownMainGate(fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-unavail-lsremote-")), {
    state: "unknown", cause: "unavailable", reason: "origin/main HEAD is unavailable (git ls-remote origin refs/heads/main exit 128)",
  }, identity("worker:codex-o01"));
  assert.equal(lsRemote.blocked, true);
  assert.match(lsRemote.reason, /git fetch origin main/, "the ls-remote leg is fixed by making the remote readable");

  const foreignOrigin = unknownMainGate(fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-unavail-origin-")), {
    state: "unknown", cause: "unavailable", reason: "origin is not a GitHub repository",
  }, identity("worker:codex-o01"));
  assert.equal(foreignOrigin.blocked, true);
  assert.match(foreignOrigin.reason, /needs a GitHub origin/, "no retry can turn a non-GitHub origin into a readable halt");

  for (const who of [identity("human:Kevin"), null]) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-unavail-"));
    const gate = unknownMainGate(dir, { state: "unknown", sha: "c".repeat(40), cause: "unavailable", reason: "GitHub API timeout" }, who);
    assert.equal(gate.blocked, false, "a non-worker push proceeds on the record");
    const row = JSON.parse(fs.readFileSync(path.join(dir, "flywheel-guard-audit.jsonl"), "utf8").trim());
    assert.deepEqual([row.cause, row.blocked, row.class], ["unavailable", false, who?.class || "unknown"]);
  }
  // A row with no cause at all (a pre-upgrade guard) is an unavailable one, and stops a worker.
  const legacy = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-unavail-legacy-"));
  assert.equal(unknownMainGate(legacy, { state: "unknown", sha: "" }, identity("worker:codex-o01")).blocked, true);
});

// An unwritable audit must not fail-close a push that the contract says proceeds.
test("an unwritable audit never fail-closes an unknown-main push", () => {
  const missing = path.join(os.tmpdir(), "flywheel-unknown-no-such-dir", "gitdir");
  assert.equal(unknownMainGate(missing, { state: "unknown", sha: "d".repeat(40), cause: "unavailable" }, identity("human:Kevin")).blocked, false);
});

async function statusServers(apiStatus) {
  const mail = await listen((request, body, response) => {
    const parsed = JSON.parse(body);
    const isResource = parsed.method === "resources/read";
    response.writeHead(200, { "content-type": "application/json" });
    response.end(rpc(parsed.id, isResource ? [] : { conflict_free: true, conflicts: [] }, isResource));
  });
  const api = await listen((_request, _body, response) => {
    response.writeHead(apiStatus, { "content-type": "application/json" });
    response.end(JSON.stringify({ message: "Not Found" }));
  });
  return { mail, api, close: () => { mail.server.close(); api.server.close(); } };
}

async function prePushAgainst(apiStatus, agentId, worker = false) {
  const fixture = prePushFixture();
  const servers = await statusServers(apiStatus);
  const configFile = config(fixture.dir, {
    agentMailUrl: `${servers.mail.url}/mcp/`,
    redMainCheckNames: SENTINEL,
    ...(worker ? { workerClones: [{ alias: "codex-o01", path: fixture.dir, mailAgent: "CalmRiver" }] } : {}),
  });
  const result = await run(fixture.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: agentId,
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_API_BASE: servers.api.url,
    FLYWHEEL_GITHUB_READ_TOKEN: SECRET,
  }, fixture.stdin);
  servers.close();
  const auditFile = path.join(fixture.dir, ".git", "flywheel-guard-audit.jsonl");
  const rows = fs.existsSync(auditFile) ? fs.readFileSync(auditFile, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
  return { ...fixture, result, rows };
}

test("pre-push on a private repo with no accepted credential blocks a worker", async () => {
  const { result, rows } = await prePushAgainst(404, "worker:codex-o01", true);
  assert.equal(result.code, 1, result.stderr);
  assert.match(result.stderr, /BLOCKED: red-main read is unauthenticated; set FLYWHEEL_GITHUB_READ_TOKEN/);
  assert.deepEqual([rows.length, rows[0].cause, rows[0].class, rows[0].blocked], [1, "unauthenticated", "worker", true], "the block itself must reach the audit");
  for (const stream of [result.stderr, result.stdout]) assert.doesNotMatch(stream, new RegExp(SECRET), "the token must never reach the operator's terminal");
});

// A failing response with a chosen status, headers, and body. `headers` is a real
// get()-style bag so the guard's optional-chaining path is the one under test.
function failingResponse(status, headers = {}, body = "{}") {
  return async () => ({
    ok: false, status, headers: { get: (name) => headers[name.toLowerCase()] ?? null },
    text: async () => body, json: async () => ({}),
  });
}

// All three names, not just the dedicated one: an ambient GH_TOKEN in the developer's
// shell would otherwise make "no credential" quietly mean "some credential".
const TOKEN_ENV = ["FLYWHEEL_GITHUB_READ_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"];

async function withToken(value, run) {
  const previous = TOKEN_ENV.map((name) => [name, process.env[name]]);
  for (const name of TOKEN_ENV) delete process.env[name];
  if (value !== null) process.env.FLYWHEEL_GITHUB_READ_TOKEN = value;
  try { return await run(); } finally {
    for (const [name, was] of previous) {
      if (was === undefined) delete process.env[name];
      else process.env[name] = was;
    }
  }
}

// A 403 is GitHub's answer to a rate limit as well as to a missing credential. Blocking
// the fleet's workers because the API was busy would be the wrong failure entirely — but
// the carve-out only applies when a credential was actually sent, and only to a 403.
test("a rate-limited 403 is an outage, but only when a credential was sent", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  await withToken(SECRET, async () => {
    const exhausted = await githubMainStatus(dir, failingResponse(403, { "x-ratelimit-remaining": "0" }), "a".repeat(40));
    assert.equal(exhausted.cause, "unavailable", "x-ratelimit-remaining: 0 on a sent credential is an outage");
    const backoff = await githubMainStatus(dir, failingResponse(403, { "retry-after": "60" }), "a".repeat(40));
    assert.equal(backoff.cause, "unavailable", "a Retry-After is an outage");
    const secondary = await githubMainStatus(dir, failingResponse(403, {}, '{"message":"You have exceeded a secondary rate limit"}'), "a".repeat(40));
    assert.equal(secondary.cause, "unavailable", "the secondary-rate-limit body is an outage");
    const denied = await githubMainStatus(dir, failingResponse(403, { "x-ratelimit-remaining": "4999" }, '{"message":"Resource not accessible"}'), "a".repeat(40));
    assert.equal(denied.cause, "unauthenticated", "a 403 with quota left and no rate-limit body is a credential problem");
  });
});

// The bug this test exists for: `limited` used to be computed from the rate-limit headers
// on EVERY status, so a private-repo 404 that merely arrived during an exhausted quota
// read as an outage and the worker proceeded past a halt that had never run. Six lanes
// share one IP and each pre-push makes at least two calls, so the unauthenticated 60/hr
// budget runs out in an ordinary busy hour — this was an hourly free pass, not a corner.
test("rate-limit headers never excuse a 401 or a 404", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  await withToken(SECRET, async () => {
    for (const status of [401, 404]) {
      for (const headers of [{ "x-ratelimit-remaining": "0" }, { "retry-after": "60" }]) {
        const result = await githubMainStatus(dir, failingResponse(status, headers), "a".repeat(40));
        assert.equal(result.cause, "unauthenticated", `HTTP ${status} with ${JSON.stringify(headers)} is still a credential failure`);
      }
    }
    // Nor may a rate-limit BODY on a non-403 status excuse it.
    const body = await githubMainStatus(dir, failingResponse(404, {}, '{"message":"API rate limit exceeded"}'), "a".repeat(40));
    assert.equal(body.cause, "unauthenticated", "a 404 body claiming a rate limit is not a rate limit");
  });
});

// The guard knows whether it attached a credential, and that fact outranks any header the
// response carries: an unsent token cannot have been rate limited.
test("with no credential at all, 401/403/404 is unauthenticated whatever the headers say", async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  await withToken(null, async () => {
    for (const status of [401, 403, 404]) {
      const exhausted = await githubMainStatus(dir, failingResponse(status, { "x-ratelimit-remaining": "0" }), "a".repeat(40));
      assert.equal(exhausted.cause, "unauthenticated", `HTTP ${status} with no token sent is a misconfiguration, not an outage`);
      const secondary = await githubMainStatus(dir, failingResponse(status, {}, '{"message":"You have exceeded a secondary rate limit"}'), "a".repeat(40));
      assert.equal(secondary.cause, "unauthenticated", `HTTP ${status} with no token sent cannot be excused by a body`);
    }
    // A 5xx is still an outage: no-credential does not turn every failure into a block.
    const outage = await githubMainStatus(dir, failingResponse(503), "a".repeat(40));
    assert.equal(outage.cause, "unavailable", "an unauthenticated guard still treats a 5xx as transient");
  });
});

// pre-push, end to end: the exact reviewer scenario — no token, private repo 404, quota
// exhausted — must BLOCK the worker rather than wave it through.
test("a worker is blocked by a 404 that arrives with an exhausted rate-limit quota", async () => {
  const fixture = prePushFixture();
  const mail = await listen((request, body, response) => {
    const parsed = JSON.parse(body);
    const isResource = parsed.method === "resources/read";
    response.writeHead(200, { "content-type": "application/json" });
    response.end(rpc(parsed.id, isResource ? [] : { conflict_free: true, conflicts: [] }, isResource));
  });
  const api = await listen((_request, _body, response) => {
    response.writeHead(404, { "content-type": "application/json", "x-ratelimit-remaining": "0", "retry-after": "60" });
    response.end(JSON.stringify({ message: "Not Found" }));
  });
  const configFile = config(fixture.dir, {
    agentMailUrl: `${mail.url}/mcp/`,
    redMainCheckNames: SENTINEL,
    workerClones: [{ alias: "codex-o01", path: fixture.dir, mailAgent: "CalmRiver" }],
  });
  const result = await run(fixture.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: "worker:codex-o01",
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_API_BASE: api.url,
  }, fixture.stdin);
  mail.server.close();
  api.server.close();
  assert.equal(result.code, 1, `a quota-exhausted 404 must not become a free pass:\n${result.stderr}`);
  assert.match(result.stderr, /BLOCKED: red-main read is unauthenticated/);
  const rows = fs.readFileSync(path.join(fixture.dir, ".git", "flywheel-guard-audit.jsonl"), "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
  assert.deepEqual([rows.length, rows[0].cause, rows[0].blocked], [1, "unauthenticated", true]);
});

// boundedFetch has already cleared its abort timer by the time the body is read, so an
// unbounded read here would hang pre-push on a response that never finishes its body.
// The explicit timeout is the assertion: without the deadline the body read never
// settles, and a hang has to be a deterministic failure rather than a stuck run.
test("a stalled 403 body cannot hang pre-push", { timeout: 5000 }, async () => {
  const dir = repo();
  git(dir, "remote", "add", "origin", "https://github.com/kjgryboski/agent-flywheel-live-canary.git");
  const stalled = async () => ({
    ok: false, status: 403, headers: { get: () => null },
    text: () => new Promise(() => {}), json: async () => ({}),
  });
  await withToken(SECRET, async () => {
    const started = performance.now();
    const result = await githubMainStatus(dir, stalled, "a".repeat(40));
    const elapsed = performance.now() - started;
    // The body never resolves, so `limited` stays false and the 403 reads as a credential
    // failure — the safe direction — and it does so promptly.
    assert.equal(result.cause, "unauthenticated");
    assert.ok(elapsed < 4000, `the body read must be bounded, took ${Math.round(elapsed)}ms`);
  });
});

// The packet ceiling: 500 → 600 → 750 → 800. Two deliberate raises merged on 2026-09-02: the `lane:`
// class and the `Bead: none` declaration (~32 lines, PR #23), and fail-closed `unavailable` for workers —
// per-leg block remedy, timeout diagnostics, the two 5 s budgets (~16 lines, PR #24). Enforced here so it
// cannot drift silently again.
test("the guard stays under the packet's line ceiling", () => {
  const lines = fs.readFileSync(path.join(root, "scripts", "flywheel-guard.mjs"), "utf8").split("\n").length - 1;
  // 800 → 1010 for the C14a janitor exception (spec §2.4): eight conditions, each with the
  // reasoning that makes it fail-closed, do not compress below this. The ceiling has moved
  // with the packet before (500 → 750 → 770 → 800) and it is a policy call recorded in
  // docs/agent-runs/claude-c14/audit-c14a-canary.md, not a silent relaxation.
  assert.ok(lines <= 1010, `scripts/flywheel-guard.mjs is ${lines} lines, over the 1010-line ceiling`);
});

test("pre-push on an unauthenticated read lets a human through, on the record", async () => {
  const { result, rows, remoteHead } = await prePushAgainst(403, "human:Kevin");
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stderr, /CI-Status: unknown \(unauthenticated\); proceeding/);
  assert.equal(rows.length, 1, `expected exactly one audit row, got ${rows.length}`);
  // The recorded sha is the origin/main head the guard judged, which is what makes the
  // row reconcilable against the remote — not the local head being pushed.
  assert.deepEqual([rows[0].kind, rows[0].value, rows[0].cause, rows[0].class, rows[0].sha], ["ci-status", "unknown", "unauthenticated", "human", remoteHead]);
  assert.doesNotMatch(JSON.stringify(rows), new RegExp(SECRET), "the token must never reach the clone-local audit");
  for (const stream of [result.stderr, result.stdout]) assert.doesNotMatch(stream, new RegExp(SECRET));
});

test("pre-push on a 5xx read blocks a worker and records unavailable", async () => {
  const { result, rows } = await prePushAgainst(503, "worker:codex-o01", true);
  assert.equal(result.code, 1, result.stderr);
  assert.match(result.stderr, /BLOCKED: red-main read is unavailable/, "an unread halt cannot clear a worker");
  // The API leg: ls-remote resolved the head fine, so the remedy is to wait, not to fetch.
  assert.match(result.stderr, /GitHub's API did not answer/);
  assert.doesNotMatch(result.stderr, /git fetch origin main/, "the remedy must not send the worker after the leg that worked");
  assert.deepEqual([rows.length, rows[0].cause, rows[0].class, rows[0].blocked], [1, "unavailable", "worker", true]);
});

// The other half of `unavailable`: the API is never reached at all because `git ls-remote`
// cannot resolve origin/main HEAD. Deleting the bare origin is the cheapest honest way to
// get that offline, and it exercises the real ls-remote path rather than a stubbed fetch.
async function prePushWithBrokenOrigin(agentId, worker) {
  const fixture = prePushFixture();
  fs.rmSync(git(fixture.dir, "remote", "get-url", "origin").trim(), { recursive: true, force: true });
  const mail = await listen((request, body, response) => {
    const parsed = JSON.parse(body);
    const isResource = parsed.method === "resources/read";
    response.writeHead(200, { "content-type": "application/json" });
    response.end(rpc(parsed.id, isResource ? [] : { conflict_free: true, conflicts: [] }, isResource));
  });
  const configFile = config(fixture.dir, {
    agentMailUrl: `${mail.url}/mcp/`,
    redMainCheckNames: SENTINEL,
    workerClones: worker ? [{ alias: "codex-o01", path: fixture.dir, mailAgent: "CalmRiver" }] : [],
  });
  const result = await run(fixture.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: agentId,
    FLYWHEEL_GUARD_CONFIG: configFile,
  }, fixture.stdin);
  mail.server.close();
  const auditFile = path.join(fixture.dir, ".git", "flywheel-guard-audit.jsonl");
  const rows = fs.existsSync(auditFile) ? fs.readFileSync(auditFile, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
  return { result, rows };
}

test("pre-push blocks a worker when origin/main HEAD cannot be read", async () => {
  const { result, rows } = await prePushWithBrokenOrigin("worker:codex-o01", true);
  assert.equal(result.code, 1, result.stderr);
  assert.match(result.stderr, /BLOCKED: red-main read is unavailable \(origin\/main HEAD is unavailable/);
  // The ls-remote leg, so the remedy is the one that makes the remote readable again.
  assert.match(result.stderr, /git fetch origin main/);
  const row = rows.at(-1);
  assert.deepEqual([row.kind, row.value, row.cause, row.blocked, row.class, row.sha], ["ci-status", "unknown", "unavailable", true, "worker", null]);
  assert.ok(row.reason.startsWith("origin/main HEAD is unavailable"), `unexpected reason: ${row.reason}`);
  // A missing origin is a failing exit, not a timeout and not a missing ref: the diagnostic
  // has to say which, or the next investigator cannot tell an outage from a broken remote.
  assert.match(row.reason, /^origin\/main HEAD is unavailable \(git ls-remote origin refs\/heads\/main exit \d+\)$/);
});

test("pre-push with origin/main unreadable lets a human proceed and records the row", async () => {
  const { result, rows } = await prePushWithBrokenOrigin("human:Kevin", false);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stderr, /CI-Status: unknown \(origin\/main HEAD is unavailable/);
  const row = rows.at(-1);
  assert.deepEqual([row.cause, row.blocked, row.class, row.sha], ["unavailable", false, "human", null]);
});

// An extensionless `#!/bin/sh` shim on PATH is a POSIX-only technique: Windows resolves
// `git` through PATHEXT and would never run it, so these skip there rather than fail.
const POSIX_SHIM = { skip: process.platform === "win32" ? "POSIX shim" : false };

// A `git` shim that sleeps before delegating, so ls-remote takes at least `seconds`.
// PATH is mutated in place and restored in a finally by each caller. node:test runs this
// file's tests sequentially, so no concurrent test can see the shim.
function slowGitShim(seconds) {
  const realGit = execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim();
  const shimDir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-slow-git-"));
  fs.writeFileSync(path.join(shimDir, "git"), `#!/bin/sh\nif [ "$1" = "ls-remote" ]; then sleep ${seconds}; fi\nexec ${realGit} "$@"\n`);
  fs.chmodSync(path.join(shimDir, "git"), 0o755);
  return shimDir;
}

test("an ls-remote that exceeds its budget is unavailable, not green", POSIX_SHIM, async () => {
  const fixture = prePushFixture();
  const shimDir = slowGitShim(1);
  const previousPath = process.env.PATH;
  let fetches = 0;
  try {
    process.env.PATH = `${shimDir}${path.delimiter}${previousPath}`;
    const result = await githubMainStatus(fixture.dir, async () => { fetches += 1; throw new Error("unreachable"); }, "", 1500, [], apiBaseUrl(), 100);
    assert.deepEqual([result.state, result.cause], ["unknown", "unavailable"]);
    assert.match(result.reason, /exceeded 100ms/);
  } finally {
    process.env.PATH = previousPath;
  }
  assert.equal(fetches, 0, "a head the guard could not read is never worth an API call");
});

// The default itself, not a value the caller passed: `gh` as a credential helper is measured
// at 0.8-1.2s on the fleet host, and a slow one must not become a worker block now that
// `unavailable` fails closed. Two seconds of shim would blow a 1500ms default; the sha comes
// back, so the run reaches the API leg and fails there instead — which is the proof.
test("the default ls-remote budget outlasts a slow credential helper", POSIX_SHIM, async () => {
  const fixture = prePushFixture();
  const shimDir = slowGitShim(2);
  const previousPath = process.env.PATH;
  try {
    process.env.PATH = `${shimDir}${path.delimiter}${previousPath}`;
    const result = await githubMainStatus(fixture.dir, async () => { throw new Error("stub"); }, "", 1500, [], apiBaseUrl());
    assert.equal(result.sha, fixture.remoteHead, "a 1500ms default would have timed the helper out and resolved no sha");
    assert.equal(result.cause, "unavailable");
    assert.equal(result.reason, "stub", "the failure is the stubbed API leg, not the ls-remote leg");
  } finally {
    process.env.PATH = previousPath;
  }
});

// Which leg failed, and how, is the whole value of the parenthetical: a remote that answers
// with no `main` is a different repair from a remote that is not there at all.
test("an unreadable origin/main says which leg failed", async () => {
  const fixture = prePushFixture();
  const origin = git(fixture.dir, "remote", "get-url", "origin").trim();
  let fetches = 0;
  const fetchImpl = async () => { fetches += 1; throw new Error("never reached"); };

  git(origin, "update-ref", "-d", "refs/heads/main");
  const noRef = await githubMainStatus(fixture.dir, fetchImpl, "", 1500, [], apiBaseUrl());
  assert.ok(noRef.reason.endsWith("returned no ref)"), `unexpected reason: ${noRef.reason}`);

  fs.rmSync(origin, { recursive: true, force: true });
  const gone = await githubMainStatus(fixture.dir, fetchImpl, "", 1500, [], apiBaseUrl());
  assert.match(gone.reason, /exit \d+\)$/, `unexpected reason: ${gone.reason}`);
  assert.equal(fetches, 0, "neither leg is worth an API call once the head is unreadable");
});

test("trailer insertion is idempotent", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-guard-message-"));
  const message = path.join(dir, "message.txt");
  fs.writeFileSync(message, "test\n");
  appendTrailer(message, "Flywheel-Guard", "fail-open timeout");
  appendTrailer(message, "Flywheel-Guard", "fail-open timeout");
  assert.equal((fs.readFileSync(message, "utf8").match(/Flywheel-Guard:/g) || []).length, 1);
});

// git's own reading of a message file: the independent oracle for what a trailer is.
// `--no-divider`: a commit message has no `---` patch divider, and a markdown rule in a
// body must not truncate the oracle's view of it.
function gitTrailers(file) {
  return execFileSync("git", ["interpret-trailers", "--parse", "--no-divider", file], { encoding: "utf8" }).trim();
}

function messageFile(body) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-guard-trailer-")), "COMMIT_EDITMSG");
  fs.writeFileSync(file, body);
  return file;
}

// The live instance: canary d8d8fd4's body has a prose line that begins `Flywheel-Identity:`,
// and the guard's any-line scan returned early, so a commit made under a human identity
// through the commit-msg hook landed with no identity trailer at all (recorded in 17ad2d8f).
// A trailer is a `Key: value` line in the trailing paragraph(s) made only of such lines —
// the block git reads — never a line anywhere in the prose.
const PROSE_MENTION = [
  "review-sweep: head-only skip-ci, trailer blocks",
  "",
  "Trailer folding across merged commits stays, but Bead: /",
  "Flywheel-Identity: / Flywheel-Guard: / CI-Status: are parsed as a trailer",
  "block (trailing trailer-only paragraphs), not as any line anywhere, so a",
  "prose-quoted Bead: id no longer spawns a real br show.",
  "",
].join("\n");

test("a prose line that starts with the key is not the trailer: appendTrailer still appends", () => {
  const file = messageFile(PROSE_MENTION);
  assert.equal(gitTrailers(file), "", "git sees no trailer in the prose, and neither may the guard");
  appendTrailer(file, "Flywheel-Identity", "human:Kevin");
  const written = fs.readFileSync(file, "utf8");
  assert.equal(gitTrailers(file), "Flywheel-Identity: human:Kevin", "the real trailer now exists and is the only one");
  assert.ok(written.startsWith(PROSE_MENTION.trimEnd()), "the prose is untouched");
  assert.match(written, /show\.\n\nFlywheel-Identity: human:Kevin\n$/, "the trailer is its own block after the last prose paragraph");
  // Idempotent on the real trailer, still — and the key match is case-insensitive, as in git.
  appendTrailer(file, "flywheel-identity", "human:Someone");
  assert.equal(gitTrailers(file), "Flywheel-Identity: human:Kevin");
});

test("appendTrailer joins the existing trailer block and never writes the same trailer twice", () => {
  // The worker shape at HEAD (137ac43, de9b985): a `Bead:` paragraph, the guard's
  // `Flywheel-Identity:` paragraph — and `Bead:` a second time. The block is written back
  // deduplicated, and a new key joins it rather than opening yet another paragraph, so
  // git's strict last-paragraph parser sees every trailer.
  const file = messageFile("docs: record L0 fire drill\n\nBead: afc-u2o\n\nFlywheel-Identity: worker:codex-o03\nBead: afc-u2o\n");
  appendTrailer(file, "Flywheel-Identity", "worker:codex-o03");
  assert.equal(fs.readFileSync(file, "utf8"), "docs: record L0 fire drill\n\nBead: afc-u2o\nFlywheel-Identity: worker:codex-o03\n");
  appendTrailer(file, "Flywheel-Guard", "fail-open Agent Mail timeout");
  assert.equal(gitTrailers(file), "Bead: afc-u2o\nFlywheel-Identity: worker:codex-o03\nFlywheel-Guard: fail-open Agent Mail timeout");
  // Different values under one key are two trailers, not a duplicate: git keeps both.
  const two = messageFile("subject\n\nBead: afc-1\nBead: afc-2\n");
  appendTrailer(two, "Flywheel-Identity", "worker:codex-o01");
  assert.equal(gitTrailers(two), "Bead: afc-1\nBead: afc-2\nFlywheel-Identity: worker:codex-o01");
});

test("comment lines, a scissors cut, and CRLF neither hide nor lose a trailer", () => {
  // The editor template: comment lines after the body. git strips them AFTER commit-msg
  // runs, so they are transparent to the block, not prose that ends it — and the hook carries
  // them through untouched (only the editor flow strips them; `-m`/`-F` record them),
  // inserting above them, where `git interpret-trailers --trailer` inserts too.
  const templated = messageFile("subject\r\n\r\nBead: afc-1\r\n# Please enter the commit message for your changes.\r\n# Lines starting with '#' will be ignored.\r\n");
  appendTrailer(templated, "Flywheel-Identity", "human:Kevin");
  assert.equal(fs.readFileSync(templated, "utf8"), "subject\n\nBead: afc-1\nFlywheel-Identity: human:Kevin\n# Please enter the commit message for your changes.\n# Lines starting with '#' will be ignored.\n");
  assert.equal(gitTrailers(templated), "Bead: afc-1\nFlywheel-Identity: human:Kevin");

  // `commit -v`: everything below the scissors line is the diff, and git discards it after
  // the hook. A trailer appended at the end of the file would be discarded with it — and
  // the diff itself, which may quote a trailer line, is never read as the block.
  const cut = "# ------------------------ >8 ------------------------\n# Do not modify or remove the line above.\ndiff --git a/x b/x\n+Flywheel-Identity: not-a-trailer\n";
  const verbose = messageFile(`subject\n\nbody\n\n${cut}`);
  appendTrailer(verbose, "Flywheel-Identity", "human:Kevin");
  assert.equal(fs.readFileSync(verbose, "utf8"), `subject\n\nbody\n\nFlywheel-Identity: human:Kevin\n${cut}`);
});

// B1 from the #22 review: the block is edited as raw lines. git's parser classifies a bare URL,
// a drive-letter path or a clock time as a trailer line (`token:` + value); re-serialising from
// parsed pairs turned `https://x` into `https: //x`, unfolded continuations, and dropped `#`
// lines that `commit -m`/`-F` record. (`git interpret-trailers --trailer` normalises its own
// last paragraph the same way, but the guard on main only ever appended, and this block spans
// every trailing paragraph — a URL paragraph above `Bead:` is prose to git and must stay so.)
// Every line the hook did not add comes through byte-identical, and git reads the block whole.
test("appendTrailer carries every existing line through verbatim: what it did not write, it does not rewrite", () => {
  const url = "https://github.com/kjgryboski/agent-flywheel-live-canary/pull/22";
  const parsedUrl = "https: //github.com/kjgryboski/agent-flywheel-live-canary/pull/22";
  assert.equal(gitTrailers(messageFile(`subject\n\nbody\n\n${url}\n`)), parsedUrl, "git's parser reads the bare URL as a trailer line; the hook must carry it through untouched");
  const cases = [
    // [message, the file after appendTrailer(Flywheel-Identity, human:Kevin), git's parse of it]
    [`subject\n\nbody\n\n${url}\n`, `subject\n\nbody\n\n${url}\nFlywheel-Identity: human:Kevin\n`, `${parsedUrl}\nFlywheel-Identity: human:Kevin`],
    // The worker shape: the URL as its own paragraph directly above `Bead:` joins the block.
    [`subject\n\n${url}\n\nBead: afc-1\n`, `subject\n\n${url}\nBead: afc-1\nFlywheel-Identity: human:Kevin\n`, `${parsedUrl}\nBead: afc-1\nFlywheel-Identity: human:Kevin`],
    ["subject\n\nC:\\Users\\Kevin\\x.txt\n", "subject\n\nC:\\Users\\Kevin\\x.txt\nFlywheel-Identity: human:Kevin\n", "C: \\Users\\Kevin\\x.txt\nFlywheel-Identity: human:Kevin"],
    ["subject\n\n10:30 standup notes\n", "subject\n\n10:30 standup notes\nFlywheel-Identity: human:Kevin\n", "10: 30 standup notes\nFlywheel-Identity: human:Kevin"],
    // A folded continuation stays folded in the file; `--parse` unfolds it for the oracle.
    ["subject\n\nCI-Status: unknown (origin/main HEAD\n  is unavailable)\n", "subject\n\nCI-Status: unknown (origin/main HEAD\n  is unavailable)\nFlywheel-Identity: human:Kevin\n", "CI-Status: unknown (origin/main HEAD is unavailable)\nFlywheel-Identity: human:Kevin"],
    // `#` lines inside the block and as a trailing paragraph: kept in place, transparent to git.
    ["subject\n\nBead: afc-1\n#42 closes\nFlywheel-Guard: fail-open x\n", "subject\n\nBead: afc-1\n#42 closes\nFlywheel-Guard: fail-open x\nFlywheel-Identity: human:Kevin\n", "Bead: afc-1\nFlywheel-Guard: fail-open x\nFlywheel-Identity: human:Kevin"],
    ["subject\n\nBead: afc-1\n#42 closes the regression\n", "subject\n\nBead: afc-1\nFlywheel-Identity: human:Kevin\n#42 closes the regression\n", "Bead: afc-1\nFlywheel-Identity: human:Kevin"],
    ["fix: w\n\nbody\n\n#42 reported the regression\n", "fix: w\n\nbody\n\nFlywheel-Identity: human:Kevin\n#42 reported the regression\n", "Flywheel-Identity: human:Kevin"],
    // Dedupe compares the folded (key, value) pair and drops the repeat with its continuation.
    ["subject\n\nCI-Status: unknown (a\n  b)\n\nCI-Status: unknown (a\n  b)\n", "subject\n\nCI-Status: unknown (a\n  b)\nFlywheel-Identity: human:Kevin\n", "CI-Status: unknown (a b)\nFlywheel-Identity: human:Kevin"],
  ];
  for (const [message, expected, parsed] of cases) {
    const file = messageFile(message);
    appendTrailer(file, "Flywheel-Identity", "human:Kevin");
    assert.equal(fs.readFileSync(file, "utf8"), expected, JSON.stringify(message));
    assert.equal(gitTrailers(file), parsed, JSON.stringify(message));
  }
});

test("commit-msg appends the identity trailer to a message whose prose starts a line with the key", async () => {
  const dir = repo();
  const configFile = config(dir);
  const message = path.join(dir, "message.txt");
  fs.writeFileSync(message, PROSE_MENTION);
  const result = await run(dir, ["--phase", "commit-msg", message], {
    FLYWHEEL_AGENT_ID: "human:Kevin",
    FLYWHEEL_GUARD_CONFIG: configFile,
  });
  assert.equal(result.code, 0, result.stderr);
  // Mail is unreachable here, so the fail-open trailer lands too; both are in one block.
  assert.match(gitTrailers(message), /^Flywheel-Guard: fail-open .*\nFlywheel-Identity: human:Kevin$/);
});

// The guard and review-sweep must read one message the same way, or a commit the guard
// trailered is a `missing-identity` finding for the sweep — and vice versa. Both accept
// every trailing trailer-only paragraph; only the guard also reads through comment lines.
test("the guard and review-sweep parse the same trailer block from the same message", () => {
  const messages = [
    "docs: record L0 fire drill\n\nBead: afc-u2o\n\nFlywheel-Identity: worker:codex-o03\n",
    "docs: one block\n\nBead: afc-u2o\nFlywheel-Identity: worker:codex-o03\n",
    "subject\n\nsome prose\nFlywheel-Identity: human:Kevin\n",
    "Bead: not-a-trailer\n",
    "subject\n\nCI-Status: unknown (origin/main HEAD\n  is unavailable)\n",
    "subject\n\nBead: afc-1\n\nprose after the block\n",
    PROSE_MENTION,
    "",
  ];
  for (const message of messages) {
    assert.deepEqual(trailerBlock(message), sweepTrailerBlock(message), JSON.stringify(message));
  }
  assert.deepEqual(trailerBlock(messages[0]), [{ key: "Bead", value: "afc-u2o" }, { key: "Flywheel-Identity", value: "worker:codex-o03" }], "the pre-fix worker shape still parses whole");
  assert.deepEqual(trailerBlock(messages[4]), [{ key: "CI-Status", value: "unknown (origin/main HEAD is unavailable)" }], "continuation lines fold");
  assert.deepEqual(trailerBlock(messages[5]), []);
});

test("worker Bead validation reads the trailer block, not any line that starts with Bead:", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-bead-block-"));
  const database = path.join(dir, "beads.db");
  fs.writeFileSync(database, "test fixture");
  const cfg = { br: { binary: nativeBrFixture(dir), database } };
  const shown = [];
  const runner = (_binary, args) => {
    shown.push(args[args.indexOf("show") + 1]);
    return { status: 0, stdout: JSON.stringify({ id: shown.at(-1), status: "in_progress", assignee: "codex-o01" }) };
  };
  // A prose mention is not a trailer, and br is never consulted for an id nobody cited —
  // even when the mention is a whole line, which the old any-line scan accepted as the id.
  const prose = "docs: talk about a bead\n\nEarlier work used\nBead: afc-old\nfor this; see the ledger. That line is prose and must not reach br.\n";
  assert.throws(() => validateBead(cfg, root, "codex-o01", prose, runner), /require a Bead: <id> trailer/);
  assert.deepEqual(shown, []);
  // The real trailer wins over a prose line that starts with the key, in the shape the
  // guard wrote before this fix (two trailing trailer-only paragraphs) as well as after.
  const both = "docs: both\n\nBead: afc-old was the previous id, superseded below by\nthe real one.\n\nBead: afc-1\n\nFlywheel-Identity: worker:codex-o01\n";
  assert.equal(validateBead(cfg, root, "codex-o01", both, runner), "afc-1");
  assert.deepEqual(shown, ["afc-1"]);
  // A multi-word value is not an id.
  assert.throws(() => validateBead(cfg, root, "codex-o01", "docs: x\n\nBead: afc-1 and afc-2\n", runner), /require a Bead: <id> trailer/);
  assert.deepEqual(shown, ["afc-1"]);
});

// The trailer grammar after the fleet's first sweep (control plane, fleet-review-sweep-run):
// `Bead: none (<reason>)` is an explicit no-bead declaration that human and lane class may
// write; `lane:<slug>` is a recognised class. Neither loosens the worker contract, and a lane
// that lands commits on main is held to it.
test("`Bead: none` is a declaration, never an id: a worker commit with it is still denied and br is never consulted", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-bead-none-"));
  const database = path.join(dir, "beads.db");
  fs.writeFileSync(database, "test fixture");
  const cfg = { br: { binary: nativeBrFixture(dir), database } };
  const shown = [];
  const runner = (_binary, args) => {
    shown.push(args[args.indexOf("show") + 1]);
    return { status: 0, stdout: JSON.stringify({ id: shown.at(-1), status: "in_progress", assignee: "codex-o01" }) };
  };
  for (const value of ["none", "none (grammar fix; no bead exists)", "NONE (case is not an escape)", "none(no space)"]) {
    assert.throws(() => validateBead(cfg, root, "codex-o01", `docs: x\n\nBead: ${value}\nFlywheel-Identity: worker:codex-o01\n`, runner), /worker commits require a Bead: <id> trailer; `Bead: none` declares no bead and is not an id/, value);
  }
  assert.deepEqual(shown, [], "a declaration is never looked up");
  // A real id beside a declaration is still the id; the declaration is ignored, not fatal.
  assert.equal(validateBead(cfg, root, "codex-o01", "docs: x\n\nBead: none (superseded)\nBead: afc-1\n", runner), "afc-1");
  assert.deepEqual(shown, ["afc-1"]);
  // A value that is neither an id nor a declaration is still not an id (unchanged rule).
  assert.throws(() => validateBead(cfg, root, "codex-o01", "docs: x\n\nBead: afc-1 [kxl-d03]\n", runner), /worker commits require a Bead: <id> trailer$/);
});

test("lane class validates a bead under its own assignee form, and is refused inside a registered worker clone", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-lane-bead-"));
  const database = path.join(dir, "beads.db");
  fs.writeFileSync(database, "test fixture");
  const cfg = { br: { binary: nativeBrFixture(dir), database } };
  const assigned = (assignee) => () => ({ status: 0, stdout: JSON.stringify({ id: "afc-7", status: "open", assignee }) });
  assert.equal(validateBead(cfg, root, "grammar-fix", "docs: x\n\nBead: afc-7\n", assigned("lane:grammar-fix"), "lane"), "afc-7");
  assert.equal(validateBead(cfg, root, "grammar-fix", "docs: x\n\nBead: afc-7\n", assigned("grammar-fix"), "lane"), "afc-7");
  assert.throws(() => validateBead(cfg, root, "grammar-fix", "docs: x\n\nBead: afc-7\n", assigned("codex-o01"), "lane"), /assigned to codex-o01, not grammar-fix/);
  assert.throws(() => validateBead(cfg, root, "grammar-fix", "docs: x\n\nBead: none (no bead)\n", assigned("lane:grammar-fix"), "lane"), /lane commits require a Bead: <id> trailer; `Bead: none` declares no bead/);
  // The clone-path anchor is unchanged: only the matching worker may commit in a worker clone.
  const config_ = { workerClones: [{ alias: "codex-o01", path: dir, mailAgent: "CalmRiver" }] };
  assert.throws(() => cloneIdentity(config_, dir, identity("lane:grammar-fix")), /requires FLYWHEEL_AGENT_ID=worker:codex-o01/);
  assert.equal(cloneIdentity({ workerClones: [] }, dir, identity("lane:grammar-fix")), null, "a lane outside every worker clone is not anchored and needs no anchor");
});

test("commit-msg: a lane with `Bead: none (reason)` proceeds and is trailered; a worker with it is BLOCKED before br", async () => {
  const laneDir = repo();
  const laneMessage = path.join(laneDir, "message.txt");
  fs.writeFileSync(laneMessage, "docs: grammar fix\n\nBead: none (grammar fix; no bead exists)\n");
  const lane = await run(laneDir, ["--phase", "commit-msg", laneMessage], {
    FLYWHEEL_AGENT_ID: "lane:guard-sweep-grammar-fix",
    FLYWHEEL_GUARD_CONFIG: config(laneDir),
  });
  assert.equal(lane.code, 0, lane.stderr);
  // Mail is unreachable here: human semantics at commit time, so the fail-open trailer lands too.
  assert.match(gitTrailers(laneMessage), /^Bead: none \(grammar fix; no bead exists\)\nFlywheel-Guard: fail-open .*\nFlywheel-Identity: lane:guard-sweep-grammar-fix$/);

  // The worker: Mail answers conflict-free so the reservation leg passes and the bead rule
  // is the thing that decides. The fixture br is four magic bytes, so it must never be spawned.
  const mail = await listen((request, body, response) => {
    const parsed = JSON.parse(body);
    const isResource = parsed.method === "resources/read";
    response.writeHead(200, { "content-type": "application/json" });
    response.end(rpc(parsed.id, isResource ? [] : { conflict_free: true, conflicts: [] }, isResource));
  });
  try {
    const workerDir = repo();
    const database = path.join(workerDir, "beads.db");
    fs.writeFileSync(database, "test fixture");
    const workerMessage = path.join(workerDir, "message.txt");
    fs.writeFileSync(workerMessage, "docs: grammar fix\n\nBead: none (a worker may not say this)\n");
    const worker = await run(workerDir, ["--phase", "commit-msg", workerMessage], {
      FLYWHEEL_AGENT_ID: "worker:codex-o01",
      FLYWHEEL_GUARD_CONFIG: config(workerDir, {
        agentMailUrl: `${mail.url}/mcp/`,
        workerClones: [{ alias: "codex-o01", path: workerDir, mailAgent: "CalmRiver" }],
        br: { binary: nativeBrFixture(workerDir), database },
      }),
    });
    assert.equal(worker.code, 1, worker.stderr);
    assert.match(worker.stderr, /BLOCKED: worker commits require a Bead: <id> trailer; `Bead: none` declares no bead and is not an id/);
  } finally {
    mail.server.close();
  }
});

test("mainCommits reads only the updates that land on refs/heads/main", () => {
  const fixture = prePushFixture();
  const seed = git(fixture.dir, "rev-parse", "HEAD~1").trim();
  // The fixture's stdin says the remote main is being created, so every reachable commit lands.
  assert.deepEqual(mainCommits(fixture.stdin, fixture.dir), [fixture.head, seed]);
  assert.deepEqual(mainCommits(`refs/heads/main ${fixture.head} refs/heads/main ${seed}\n`, fixture.dir), [fixture.head], "with a known remote sha only the new commits are landing");
  assert.deepEqual(mainCommits(`refs/heads/main ${fixture.head} refs/heads/feature ${"0".repeat(40)}\n`, fixture.dir), [], "a branch push is the pull-request route");
  assert.deepEqual(mainCommits(`(delete) ${"0".repeat(40)} refs/heads/main ${seed}\n`, fixture.dir), [], "a deletion lands nothing");
  assert.deepEqual(mainCommits("", fixture.dir), []);
});

test("pre-push: a lane landing commits on main without a resolvable bead is BLOCKED; the same lane pushing a branch proceeds as human class", async () => {
  const green = [{ name: SENTINEL[0], status: "completed", conclusion: "success", id: 1, completed_at: "2026-09-01T10:00:00Z" }];
  const fixture = prePushFixture();
  // The outgoing commit declares no bead, the shape every orchestrator lane writes.
  git(fixture.dir, "commit", "--amend", "-q", "-m", "outgoing change\n\nBead: none (grammar fix; no bead exists)\nFlywheel-Identity: lane:guard-sweep-grammar-fix");
  const head = git(fixture.dir, "rev-parse", "HEAD").trim();
  const servers = await redMainServers(green);
  try {
    const configFile = config(fixture.dir, { agentMailUrl: `${servers.mail.url}/mcp/`, redMainCheckNames: SENTINEL });
    const env = { FLYWHEEL_AGENT_ID: "lane:guard-sweep-grammar-fix", FLYWHEEL_GUARD_CONFIG: configFile, FLYWHEEL_GUARD_API_BASE: servers.api.url };
    const direct = await run(fixture.dir, ["--phase", "pre-push"], env, `refs/heads/main ${head} refs/heads/main ${fixture.remoteHead}\n`);
    assert.equal(direct.code, 1, direct.stderr);
    assert.match(direct.stderr, new RegExp(`BLOCKED: lane:guard-sweep-grammar-fix is pushing ${head.slice(0, 12)} to main on the direct route: lane commits require a Bead: <id> trailer; \`Bead: none\` declares no bead and is not an id; open a pull request instead`));
    assert.equal(fs.existsSync(path.join(fixture.dir, ".git", "flywheel-guard-audit.jsonl")), false, "denied before any gate wrote a row");

    // A bead-less commit that says nothing at all is denied the same way.
    const seedOnly = await run(fixture.dir, ["--phase", "pre-push"], env, `refs/heads/main ${fixture.remoteHead} refs/heads/main ${"0".repeat(40)}\n`);
    assert.equal(seedOnly.code, 1, seedOnly.stderr);
    assert.match(seedOnly.stderr, /BLOCKED: lane:guard-sweep-grammar-fix is pushing .* to main on the direct route: lane commits require a Bead: <id> trailer; open a pull request instead/);

    // The pull-request route: the branch push proceeds on a green main, no bead needed.
    const branch = await run(fixture.dir, ["--phase", "pre-push"], env, `refs/heads/fix/grammar ${head} refs/heads/fix/grammar ${"0".repeat(40)}\n`);
    assert.equal(branch.code, 0, branch.stderr);
    assert.doesNotMatch(branch.stderr, /BLOCKED/);
  } finally {
    servers.close();
  }
});

test("the fail-closed gates hold for a lane on the direct route and keep human semantics otherwise", () => {
  const red = { state: "red", sha: "b".repeat(40), failing: SENTINEL };
  const unauth = { state: "unknown", sha: "b".repeat(40), cause: "unauthenticated", reason: "GitHub HTTP 404" };
  const landing = { ...identity("lane:grammar-fix"), strict: true };
  const strictDir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-lane-strict-"));
  assert.equal(redMainGate(strictDir, red, landing).blocked, true);
  assert.equal(fs.existsSync(path.join(strictDir, "flywheel-guard-audit.jsonl")), false, "a block writes no red-main row, as for a worker");
  const gate = unknownMainGate(strictDir, unauth, landing);
  assert.equal(gate.blocked, true);
  const rows = fs.readFileSync(path.join(strictDir, "flywheel-guard-audit.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual([rows.length, rows[0].class, rows[0].identity, rows[0].blocked], [1, "lane", "lane:grammar-fix", true], "the row names the lane, not a worker");

  const openDir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-lane-open-"));
  assert.equal(redMainGate(openDir, red, identity("lane:grammar-fix")).blocked, false);
  assert.equal(unknownMainGate(openDir, unauth, identity("lane:grammar-fix")).blocked, false);
  const openRows = fs.readFileSync(path.join(openDir, "flywheel-guard-audit.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual(openRows.map((row) => [row.kind, row.value, row.class]), [["ci-status", "red", "lane"], ["ci-status", "unknown", "lane"]]);

  // Merged semantics (#23 + #24): an `unavailable` read — network, timeout, 5xx, unreadable origin/main HEAD —
  // stops a lane landing on main exactly as it stops a worker; a lane on a branch and a human proceed on the
  // record. A gate of `who?.class === "worker" || (unauth && strict(who))` passes every other test yet fails here.
  const unavail = { state: "unknown", sha: "c".repeat(40), cause: "unavailable", reason: "GitHub API timeout" };
  assert.equal(unknownMainGate(fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-lane-unavail-strict-")), unavail, landing).blocked, true, "lane landing on main + unavailable must fail closed");
  assert.equal(unknownMainGate(fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-lane-unavail-open-")), unavail, identity("lane:grammar-fix")).blocked, false);
  assert.equal(unknownMainGate(fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-lane-unavail-worker-")), unavail, identity("worker:codex-o01")).blocked, true);
  assert.equal(unknownMainGate(fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-lane-unavail-human-")), unavail, identity("human:Kevin")).blocked, false);
});

// ---------------------------------------------------------------------------------------
// C14a — the janitor exception (spec §2.4). Every fixture below builds REAL commits, so the
// tree-equality test, the parent test and the fence test run against git rather than a mock.
// The `br` reads go through the injected `runner` seam, which is how this suite already
// tests `validateBead` (`worker Bead validation uses global flags and enforces assignee`):
// `requireNativeBr` demands a real ELF binary, so a hermetic fixture cannot answer a live
// `br show`, and the guard must not grow an env seam that would let one.
// ---------------------------------------------------------------------------------------

const JANITOR_BEAD = "afc-j1";
const JANITOR_WHO = identity("worker:codex-o01");

function janitorRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-janitor-"));
  git(dir, "init", "-b", "main");
  git(dir, "config", "user.name", "Flywheel Test");
  git(dir, "config", "user.email", "flywheel-test@example.invalid");
  fs.writeFileSync(path.join(dir, "file.txt"), "seed\n");
  git(dir, "add", "file.txt");
  git(dir, "commit", "-m", "seed");
  return dir;
}

function writeAll(dir, files) {
  for (const [name, body] of Object.entries(files)) {
    const target = path.join(dir, name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, body);
    git(dir, "add", "--", name);
  }
}

// The red head: one commit, with a trailer block of its own so conditions 5b and 8 have
// something real to read.
function landRed(dir, files, { bead = JANITOR_BEAD, agent = "worker:codex-o01", markers = [] } = {}) {
  writeAll(dir, files);
  const message = ["the breaking change", "", ...markers.map((sha) => `Janitor-Revert-Of: ${sha}`), `Bead: ${bead}`, `Flywheel-Identity: ${agent}`].join("\n");
  git(dir, "commit", "-m", message);
  return git(dir, "rev-parse", "HEAD").trim();
}

// The Step 3.4 recipe as P3 rewrites it: `Janitor-Revert-Of:` then `Bead:` then
// `Flywheel-Identity:`, one trailer paragraph.
function revertMessage(shas, { bead = JANITOR_BEAD, agent = "worker:codex-o01" } = {}) {
  return ['Revert "the breaking change"', "", ...shas.map((sha) => `Janitor-Revert-Of: ${sha}`), `Bead: ${bead}`, `Flywheel-Identity: ${agent}`].join("\n");
}

function landRevert(dir, redSha, message) {
  git(dir, "revert", "--no-edit", "-n", redSha);
  git(dir, "commit", "-m", message);
  return git(dir, "rev-parse", "HEAD").trim();
}

const janitorStdin = (local, remote) => `refs/heads/main ${local} refs/heads/main ${remote}\n`;

function janitorConfig(dir) {
  const database = path.join(dir, ".fixture-beads.db");
  fs.writeFileSync(database, "");
  return { br: { binary: nativeBrFixture(dir), database } };
}

// One record answers both reads: `validateBead`'s status/assignee check and the janitor
// path's `description` marker check. `calls` proves the self-revert path adds no second read.
function brStub(record, { status = 0 } = {}) {
  const calls = [];
  const runner = (binary, args) => {
    calls.push(args);
    return { status, stdout: status === 0 ? JSON.stringify(record) : "", stderr: status === 0 ? "" : "br failed" };
  };
  return { runner, calls };
}

const janitorRecord = (redSha, extra = {}) => ({
  id: JANITOR_BEAD,
  status: "open",
  assignee: "worker:codex-o01",
  description: `revert the red head\n\nJanitor-Revert-Of: ${redSha}`,
  ...extra,
});

function attempt(dir, { stdin, ci, record, runner, who = JANITOR_WHO, status } = {}) {
  const stub = runner ? { runner, calls: [] } : brStub(record ?? janitorRecord(ci.sha), { status });
  const result = janitorException(janitorConfig(dir), { root: dir, gitDir: path.join(dir, ".git") }, stdin, ci, who, stub.runner);
  return { result, calls: stub.calls };
}

const redCi = (sha) => ({ state: "red", sha, failing: SENTINEL });

test("mainRefUpdates reports the ref updates in a push, and mainCommits is untouched", () => {
  const dir = janitorRepo();
  const red = landRed(dir, { "src/feature.mjs": "export const broken = true;\n" });
  const local = landRevert(dir, red, revertMessage([red]));
  const stdin = `${janitorStdin(local, red)}refs/heads/topic ${local} refs/heads/topic ${"0".repeat(40)}\nrefs/heads/dead ${"0".repeat(40)} refs/heads/dead ${red}\n`;
  const updates = mainRefUpdates(stdin);
  // The deletion line is not an update; the two live ones are, in push order.
  assert.deepEqual(updates.map(([, , remoteRef]) => remoteRef), ["refs/heads/main", "refs/heads/topic"]);
  assert.deepEqual(updates.map(([, localSha]) => localSha), [local, local]);
  // The exported helper the lane direct-route check uses still answers only about main.
  assert.deepEqual(mainCommits(stdin, dir), [local]);
});

test("the janitor exception admits the exact inverse of the judged red head, carried by a marker bead", () => {
  const dir = janitorRepo();
  // A DIFFERENT worker broke main, so the self-revert branch cannot match and the janitor
  // path — the bead's own `Janitor-Revert-Of:` marker — is the thing under test.
  const red = landRed(dir, { "src/feature.mjs": "export const broken = true;\n" }, { bead: "afc-red", agent: "worker:codex-o04" });
  const local = landRevert(dir, red, revertMessage([red]));
  const { result, calls } = attempt(dir, { stdin: janitorStdin(local, red), ci: redCi(red) });
  assert.deepEqual([result.ok, result.bead, result.sha, result.revertsSha, result.path], [true, JANITOR_BEAD, local, red, "janitor"]);
  // Two reads: validateBead's, then the marker read, with the identical argv.
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0], calls[1]);
  assert.deepEqual(calls[1].slice(0, 8), ["--db", path.join(dir, ".fixture-beads.db"), "--no-auto-import", "--no-auto-flush", "--lock-timeout", "5000", "--actor", "codex-o01"]);
  assert.deepEqual(calls[1].slice(8), ["show", JANITOR_BEAD, "--json"]);
});

test("the self-revert path is live under the P3 recipe and adds no second br read", () => {
  const dir = janitorRepo();
  const red = landRed(dir, { "src/feature.mjs": "export const broken = true;\n" }, { bead: JANITOR_BEAD, agent: "worker:codex-o01" });
  const local = landRevert(dir, red, revertMessage([red]));
  // The bead record deliberately carries NO marker: the self-revert path must not need one.
  const { result, calls } = attempt(dir, { stdin: janitorStdin(local, red), ci: redCi(red), record: janitorRecord(red, { description: "ordinary work bead" }) });
  assert.deepEqual([result.ok, result.path], [true, "self-revert"]);
  assert.equal(calls.length, 1, "the self-revert path reads br exactly once, through validateBead");
});

test("a resolvable bead without the marker, and no identity match, is refused", () => {
  const dir = janitorRepo();
  const red = landRed(dir, { "src/feature.mjs": "export const broken = true;\n" }, { bead: "afc-other", agent: "worker:codex-o04" });
  const local = landRevert(dir, red, revertMessage([red]));
  const { result } = attempt(dir, { stdin: janitorStdin(local, red), ci: redCi(red), record: janitorRecord(red, { description: "ordinary work bead" }) });
  assert.deepEqual([result.ok, result.attempted], [false, true]);
  assert.match(result.reason, /does not carry Janitor-Revert-Of/);
});

test("an unreadable or unparseable br record refuses the exception rather than throwing", () => {
  const dir = janitorRepo();
  // Another worker's breakage again, so every case below is on the janitor path.
  const red = landRed(dir, { "src/feature.mjs": "export const broken = true;\n" }, { bead: "afc-red", agent: "worker:codex-o04" });
  const local = landRevert(dir, red, revertMessage([red]));
  const stdin = janitorStdin(local, red);
  // validateBead THROWS; an uncaught throw would reach main().catch and block with a
  // confusing reason instead of the red-main one.
  const missing = attempt(dir, { stdin, ci: redCi(red), status: 1 });
  assert.deepEqual([missing.result.ok, missing.result.attempted], [false, true]);
  assert.match(missing.result.reason, /does not exist in the shared database/);
  const terminal = attempt(dir, { stdin, ci: redCi(red), record: janitorRecord(red, { status: "closed" }) });
  assert.match(terminal.result.reason, /is terminal \(closed\)/);
  const foreign = attempt(dir, { stdin, ci: redCi(red), record: janitorRecord(red, { assignee: "worker:codex-o04" }) });
  assert.match(foreign.result.reason, /assigned to worker:codex-o04, not codex-o01/);
  // A record that parses as JSON but is not a record at all.
  let call = 0;
  const runner = () => (call++ === 0 ? { status: 0, stdout: JSON.stringify(janitorRecord(red)) } : { status: 0, stdout: "not json" });
  const unparseable = attempt(dir, { stdin, ci: redCi(red), runner });
  assert.match(unparseable.result.reason, /did not return a readable record/);
});

test("the exception is derived from pre-push stdin, so pushing another sha while HEAD is a genuine inverse is refused", () => {
  const dir = janitorRepo();
  const red = landRed(dir, { "src/feature.mjs": "export const broken = true;\n" });
  // HEAD is a real one-commit exact inverse carrying the marker — revision 1's predicate
  // said yes to this push. What git is actually pushing is a different commit entirely.
  const genuine = landRevert(dir, red, revertMessage([red]));
  git(dir, "checkout", "--quiet", "-b", "smuggle", red);
  writeAll(dir, { "src/payload.mjs": "export const payload = true;\n" });
  git(dir, "commit", "-m", revertMessage([red]));
  const smuggled = git(dir, "rev-parse", "HEAD").trim();
  git(dir, "checkout", "--quiet", "main");
  assert.notEqual(smuggled, genuine);
  assert.equal(git(dir, "rev-parse", "HEAD").trim(), genuine, "HEAD really is the honest inverse");
  const { result } = attempt(dir, { stdin: janitorStdin(smuggled, red), ci: redCi(red) });
  assert.equal(result.ok, false);
  assert.match(result.reason, /not the exact inverse of the red head/);
});

test("tree equality, not patch-id: a whitespace-only or binary-only difference from the true inverse is refused", () => {
  const whitespace = janitorRepo();
  writeAll(whitespace, { "src/feature.mjs": "export const value = {\n  a: 1,\n};\n" });
  git(whitespace, "commit", "-m", "seed the module");
  const redWhitespace = landRed(whitespace, { "src/feature.mjs": "export const value = {\n  a: 2,\n};\n" });
  // A "revert" that restores the VALUE but re-indents the line. `git patch-id --stable`
  // hashes the diff after whitespace normalisation, so this compares EQUAL under patch-id
  // and unequal under tree equality. That is the whole point of the test.
  writeAll(whitespace, { "src/feature.mjs": "export const value = {\n\ta: 1,\n};\n" });
  git(whitespace, "commit", "-m", revertMessage([redWhitespace]));
  const nearly = git(whitespace, "rev-parse", "HEAD").trim();
  const whitespaceRun = attempt(whitespace, { stdin: janitorStdin(nearly, redWhitespace), ci: redCi(redWhitespace) });
  assert.equal(whitespaceRun.result.ok, false);
  assert.match(whitespaceRun.result.reason, /not the exact inverse of the red head/);

  // `git diff` renders any changed binary as the constant "Binary files a/x and b/x differ",
  // so a different blob is invisible to a patch-id comparator and visible to a tree one.
  const binary = janitorRepo();
  writeAll(binary, { "assets/blob.bin": Buffer.from([0, 1, 2, 3]) });
  git(binary, "commit", "-m", "seed the blob");
  const redBinary = landRed(binary, { "assets/blob.bin": Buffer.from([9, 9, 9, 9]) });
  writeAll(binary, { "assets/blob.bin": Buffer.from([7, 7, 7, 7]) });
  git(binary, "commit", "-m", revertMessage([redBinary]));
  const swapped = git(binary, "rev-parse", "HEAD").trim();
  const binaryRun = attempt(binary, { stdin: janitorStdin(swapped, redBinary), ci: redCi(redBinary) });
  assert.equal(binaryRun.result.ok, false);
  assert.match(binaryRun.result.reason, /not the exact inverse of the red head/);
});

test("the exception refuses any push that is not one commit onto the judged red head", () => {
  const dir = janitorRepo();
  const red = landRed(dir, { "src/feature.mjs": "export const broken = true;\n" });
  const local = landRevert(dir, red, revertMessage([red]));
  const ci = redCi(red);

  // A second ref update in the same push.
  const twoRefs = attempt(dir, { stdin: `${janitorStdin(local, red)}refs/heads/topic ${local} refs/heads/topic ${"0".repeat(40)}\n`, ci });
  assert.match(twoRefs.result.reason, /updates 2 refs/);

  // Not refs/heads/main at all.
  const branch = attempt(dir, { stdin: `refs/heads/topic ${local} refs/heads/topic ${red}\n`, ci });
  assert.match(branch.result.reason, /not refs\/heads\/main/);

  // The remote side is not the head GitHub judged.
  const elsewhere = attempt(dir, { stdin: janitorStdin(local, "b".repeat(40)), ci });
  assert.match(elsewhere.result.reason, /not the judged red head/);

  // A create of refs/heads/main.
  const created = attempt(dir, { stdin: janitorStdin(local, "0".repeat(40)), ci });
  assert.match(created.result.reason, /creates refs\/heads\/main/);

  // Two commits landing at once.
  writeAll(dir, { "src/extra.mjs": "export const extra = true;\n" });
  git(dir, "commit", "-m", revertMessage([red]));
  const second = git(dir, "rev-parse", "HEAD").trim();
  const twoCommits = attempt(dir, { stdin: janitorStdin(second, red), ci });
  assert.match(twoCommits.result.reason, /lands 2 commits on main/);
});

test("a merge commit is refused even when its first parent is the red head", () => {
  const dir = janitorRepo();
  const red = landRed(dir, { "src/feature.mjs": "export const broken = true;\n" });
  // A merge whose second parent is ALREADY upstream: it lands exactly one commit and its
  // tree is the red head's parent's tree, so conditions 3's count and 4 both pass. Only the
  // parent-count half of condition 3 catches it, which is why that half exists.
  const tree = git(dir, "rev-parse", `${red}~1^{tree}`).trim();
  const merge = git(dir, "commit-tree", tree, "-p", red, "-p", `${red}~1`, "-m", revertMessage([red])).trim();
  git(dir, "update-ref", "refs/heads/main", merge);
  assert.deepEqual(mainCommits(janitorStdin(merge, red), dir), [merge], "the merge must land exactly one commit for this case to bite");
  const { result } = attempt(dir, { stdin: janitorStdin(merge, red), ci: redCi(red) });
  assert.equal(result.ok, false);
  assert.match(result.reason, /has 2 parents/);
});

test("a root red head has nothing to revert to and is refused", () => {
  const dir = janitorRepo();
  const root = git(dir, "rev-parse", "HEAD").trim();
  writeAll(dir, { "src/anything.mjs": "export const anything = true;\n" });
  git(dir, "commit", "-m", revertMessage([root]));
  const local = git(dir, "rev-parse", "HEAD").trim();
  const { result } = attempt(dir, { stdin: janitorStdin(local, root), ci: redCi(root) });
  assert.equal(result.ok, false);
  assert.match(result.reason, /no first parent \(root commit\)/);
});

// The condition-6 fixtures are DERIVED from FENCE_GLOBS rather than naming canary fence
// members, so a vendoring repo's suite exercises its own fence and cannot pass or fail on the
// canary's (RULING-fence-globs.md revision 3's filed follow-up, settled in revision 5 item 4).
// One concrete path per glob, matching it under the guard's own `globRegex`; `{a,b}` and a
// mid-pattern `**/` are banned from the fence, so a wildcard is always a whole path segment.
function fenceFixture(pattern) {
  return pattern.replaceAll("**", "fenced-fixture").replaceAll("*", "fenced-fixture").replaceAll("?", "x");
}

test("reverting a commit that touched a critical path is itself a fenced change and is refused", () => {
  assert.ok(FENCE_GLOBS.length > 0, "FENCE_GLOBS must be non-empty; the derived condition-6 cases would otherwise pass vacuously");
  for (const fenced of FENCE_GLOBS.map(fenceFixture)) {
    assert.equal(FENCE_GLOBS.some((pattern) => overlaps(fenced, pattern)), true, `${fenced} must be a live fence fixture`);
    const dir = janitorRepo();
    const red = landRed(dir, { [fenced]: "fenced content\n" });
    const local = landRevert(dir, red, revertMessage([red]));
    const { result } = attempt(dir, { stdin: janitorStdin(local, red), ci: redCi(red) });
    assert.equal(result.ok, false, `${fenced} must not be auto-revertible`);
    assert.match(result.reason, new RegExp(`touches critical-path ${fenced.replaceAll(".", "\\.")}`));
  }
});

// A MERGE red head: the shape condition 4 deliberately admits (`git revert -m 1 <merge>`
// produces exactly the first parent's tree) and the shape every canary window landing has
// (manifest method `merge`). One-argument `git diff-tree <merge>` prints NOTHING, so a
// condition 6 written that way is vacuous for exactly this shape; the two-tree form against
// condition 4's `revertedParent` sees the whole first-parent diff.
function landMergedRed(dir, files) {
  const base = git(dir, "rev-parse", "HEAD").trim();
  git(dir, "checkout", "--quiet", "-b", "topic", base);
  writeAll(dir, files);
  git(dir, "commit", "-m", "the breaking change, on a topic branch");
  git(dir, "checkout", "--quiet", "main");
  git(dir, "merge", "--no-ff", "--no-edit", "-m", "Merge the breaking change", "topic");
  return git(dir, "rev-parse", "HEAD").trim();
}

function landMergeRevert(dir, redSha, message) {
  git(dir, "revert", "--no-edit", "-n", "-m", "1", redSha);
  git(dir, "commit", "-m", message);
  return git(dir, "rev-parse", "HEAD").trim();
}

test("a merge red head whose first-parent diff touches a fenced path is refused", () => {
  const dir = janitorRepo();
  assert.ok(FENCE_GLOBS.length > 0, "FENCE_GLOBS must be non-empty; the derived condition-6 cases would otherwise pass vacuously");
  const fenced = fenceFixture(FENCE_GLOBS[0]);
  const red = landMergedRed(dir, { [fenced]: "a fenced path, edited on a topic branch\n" });
  assert.equal(git(dir, "rev-list", "--parents", "-n", "1", red).trim().split(/\s+/).length, 3, "the red head must really be a merge for this case to bite");
  // The premise of the defect this case pins: the one-argument form sees nothing here.
  assert.equal(git(dir, "diff-tree", "--no-commit-id", "--name-only", "-r", red).trim(), "", "one-argument diff-tree really is blind to a merge commit");
  const local = landMergeRevert(dir, red, revertMessage([red]));
  const { result } = attempt(dir, { stdin: janitorStdin(local, red), ci: redCi(red) });
  assert.equal(result.ok, false, "reverting a merge that carried a fenced edit must not be mechanically admitted");
  assert.match(result.reason, new RegExp(`touches critical-path ${fenced.replaceAll(".", "\\.")}`));
});

test("a merge red head whose first-parent diff touches only src/ is admitted", () => {
  const dir = janitorRepo();
  const red = landMergedRed(dir, { "src/feature.mjs": "export const broken = true;\n" });
  const local = landMergeRevert(dir, red, revertMessage([red]));
  const { result } = attempt(dir, { stdin: janitorStdin(local, red), ci: redCi(red) });
  assert.deepEqual([result.ok, result.sha, result.revertsSha, result.path], [true, local, red, "janitor"], "condition 4 admits a merge red head by design; condition 6 must not turn that into a blanket refusal");
});

// The fence list is stated in scripts/flywheel-fence.mjs as a constant and re-exported by the
// guard (an exception that admits a push onto a RED main must not depend on a key a clone
// could soften) and mirrored in flywheel.guard.json, which test/review-sweep.test.mjs already
// pins to AGENTS.md §9. This couples the copy the guard actually enforces.
test("FENCE_GLOBS is byte-identical to the flywheel.guard.json criticalPathGlobs mirror", () => {
  assert.deepEqual(FENCE_GLOBS, JSON.parse(fs.readFileSync(path.join(root, "flywheel.guard.json"), "utf8")).criticalPathGlobs.globs);
});

test("the Janitor-Revert-Of marker is required, quantified, and must name the judged head", () => {
  const dir = janitorRepo();
  const red = landRed(dir, { "src/feature.mjs": "export const broken = true;\n" });
  const older = git(dir, "rev-parse", `${red}~1`).trim();

  // No marker at all: not even reported, because the push never claimed to be one.
  const bare = landRevert(dir, red, ['Revert "the breaking change"', "", `Bead: ${JANITOR_BEAD}`, "Flywheel-Identity: worker:codex-o01"].join("\n"));
  const noMarker = attempt(dir, { stdin: janitorStdin(bare, red), ci: redCi(red) });
  assert.deepEqual([noMarker.result.ok, noMarker.result.attempted], [false, false]);
  assert.match(noMarker.result.reason, /carries no Janitor-Revert-Of/);
  git(dir, "reset", "--quiet", "--hard", red);

  // A marker naming an older commit: older breakage is the human path.
  const stale = landRevert(dir, red, revertMessage([older]));
  const staleRun = attempt(dir, { stdin: janitorStdin(stale, red), ci: redCi(red) });
  assert.deepEqual([staleRun.result.ok, staleRun.result.attempted], [false, true]);
  assert.match(staleRun.result.reason, /names a commit other than the red head/);
  git(dir, "reset", "--quiet", "--hard", red);

  // Two markers, one of them right: the fail-closed reading is the only one that cannot be
  // gamed by appending a second marker to a commit that reverts something else.
  const disagreeing = landRevert(dir, red, revertMessage([red, older]));
  const disagreeingRun = attempt(dir, { stdin: janitorStdin(disagreeing, red), ci: redCi(red) });
  assert.equal(disagreeingRun.result.ok, false);
  assert.match(disagreeingRun.result.reason, /names a commit other than the red head/);
  // The same commit with both markers naming the head is fine: the rule is "at least one and
  // all of them", not "exactly one".
  git(dir, "reset", "--quiet", "--hard", red);
  const doubled = landRevert(dir, red, revertMessage([red, red]));
  assert.equal(attempt(dir, { stdin: janitorStdin(doubled, red), ci: redCi(red) }).result.ok, true);
});

test("condition 8: a revert of a janitor revert is refused, and the identical push without the marker is admitted", () => {
  const dir = janitorRepo();
  const first = landRed(dir, { "src/feature.mjs": "export const broken = true;\n" });
  // The janitor revert that landed. `main` is still red, so a second revert is attempted —
  // it would re-land the tree already judged to have broken main, every 30-45 minutes.
  const janitorRevert = landRevert(dir, first, revertMessage([first]));
  const oscillation = landRevert(dir, janitorRevert, revertMessage([janitorRevert]));
  const blocked = attempt(dir, { stdin: janitorStdin(oscillation, janitorRevert), ci: redCi(janitorRevert), record: janitorRecord(janitorRevert) });
  assert.deepEqual([blocked.result.ok, blocked.result.attempted], [false, true]);
  assert.match(blocked.result.reason, /itself a janitor revert/);

  // The pair: the same shape with the marker absent from the reverted commit's own trailer
  // block. Conditions 1-7 are identical, so this pass/fail difference is condition 8 alone.
  const clean = janitorRepo();
  const ordinary = landRed(clean, { "src/feature.mjs": "export const broken = true;\n" });
  const revert = landRevert(clean, ordinary, revertMessage([ordinary]));
  const admitted = attempt(clean, { stdin: janitorStdin(revert, ordinary), ci: redCi(ordinary) });
  assert.equal(admitted.result.ok, true, admitted.result.reason);
});

test("pre-push wiring: a worker's ordinary push onto red main is blocked exactly as before, with no janitor trace", async () => {
  const failed = [{ name: SENTINEL[0], status: "completed", conclusion: "failure", id: 1, completed_at: "2026-09-01T10:00:00Z" }];
  const worker = prePushFixture();
  const servers = await redMainServers(failed);
  const configFile = config(worker.dir, {
    agentMailUrl: `${servers.mail.url}/mcp/`,
    redMainCheckNames: SENTINEL,
    workerClones: [{ alias: "codex-o01", path: worker.dir, mailAgent: "CalmRiver" }],
  });
  const result = await run(worker.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: "worker:codex-o01",
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_API_BASE: servers.api.url,
  }, worker.stdin);
  servers.close();
  assert.equal(result.code, 1);
  assert.match(result.stderr, /BLOCKED: origin\/main .* red GitHub checks: Offline contract suite/);
  // A push that never claimed to be a janitor revert says nothing about the janitor: the
  // stderr of an ordinary red block is byte-for-byte what it was before C14a.
  assert.doesNotMatch(result.stderr, /janitor/i);
  assert.equal(fs.existsSync(path.join(worker.dir, ".git", "flywheel-guard-audit.jsonl")), false);
});

test("pre-push wiring: a real janitor revert reaches the exception, and a refusal still blocks on the red-main reason", async () => {
  const failed = [{ name: SENTINEL[0], status: "completed", conclusion: "failure", id: 1, completed_at: "2026-09-01T10:00:00Z" }];
  const fixture = prePushFixture();
  // Make the local head a genuine exact inverse of the remote head, carrying the marker, so
  // conditions 1-4 and 6-8 all hold and only condition 5's `br` read can fail — which it
  // must, because the fixture's `br` is four bytes of ELF magic and cannot answer.
  git(fixture.dir, "reset", "--quiet", "--hard", fixture.remoteHead);
  writeAll(fixture.dir, { "src/broken.mjs": "export const broken = true;\n" });
  git(fixture.dir, "commit", "-m", "the breaking change");
  const red = git(fixture.dir, "rev-parse", "HEAD").trim();
  git(fixture.dir, "push", "--quiet", "origin", "main");
  const local = landRevert(fixture.dir, red, revertMessage([red]));
  const servers = await redMainServers(failed);
  const configFile = config(fixture.dir, {
    agentMailUrl: `${servers.mail.url}/mcp/`,
    redMainCheckNames: SENTINEL,
    workerClones: [{ alias: "codex-o01", path: fixture.dir, mailAgent: "CalmRiver" }],
  });
  const result = await run(fixture.dir, ["--phase", "pre-push"], {
    FLYWHEEL_AGENT_ID: "worker:codex-o01",
    FLYWHEEL_GUARD_CONFIG: configFile,
    FLYWHEEL_GUARD_API_BASE: servers.api.url,
  }, janitorStdin(local, red));
  servers.close();
  // The exception was reached and reported, and the push is still blocked on the red-main
  // reason — a refusal never invents a new block, it falls through to redMainGate.
  assert.match(result.stderr, /janitor exception refused:/);
  assert.equal(result.code, 1, result.stderr);
  assert.match(result.stderr, /BLOCKED: origin\/main .* red GitHub checks: Offline contract suite/);
  assert.equal(fs.existsSync(path.join(fixture.dir, ".git", "flywheel-guard-audit.jsonl")), false, "a refused exception writes no janitor-revert row");
});
