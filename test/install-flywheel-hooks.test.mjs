// Contract tests for scripts/install-flywheel-hooks.mjs and the .githooks wrappers.
//
// The wrappers are exercised against a stub guard rather than the real one: what is under test
// here is the wrapper contract (guard first, chain only on success, stdin replayed byte for
// byte), not the guard's own logic, which test/flywheel-guard.test.mjs covers.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installer = path.join("scripts", "install-flywheel-hooks.mjs");

function git(cwd, ...args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" });
}

function configValue(dir, key) {
  const result = spawnSync("git", ["config", "--get", key], { cwd: dir, encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : null;
}

// A stand-in for scripts/flywheel-guard.mjs. Records the phase, the trailing arguments and the
// exact stdin bytes it was given, then exits with the code in `.guard-exit` (default 0).
const STUB_GUARD = `import fs from "node:fs";
const at = process.argv.indexOf("--phase");
const phase = process.argv[at + 1];
let stdin = "";
try { stdin = fs.readFileSync(0, "utf8"); } catch { stdin = ""; }
fs.writeFileSync(\`.guard-\${phase}.json\`, JSON.stringify({ args: process.argv.slice(at + 2), stdin }));
const code = fs.existsSync(".guard-exit") ? Number(fs.readFileSync(".guard-exit", "utf8").trim()) : 0;
process.exit(code);
`;

// A stand-in for a husky user hook: plain sh, no executable bit unless a test adds one.
function chainedHook(name) {
  return `#!/bin/sh
printf '%s\\n' "$@" > .chain-${name}-args
if [ "${name}" = "pre-push" ]; then cat > .chain-${name}-stdin; fi
if [ -f .chain-exit ]; then exit "$(cat .chain-exit)"; fi
exit 0
`;
}

// The executable-bit branch of the wrappers is only observable with a hook that is NOT a shell
// script: `sh -e` happily runs an executable sh file, so a sh fixture cannot tell the two
// branches apart. This one is Node with a shebang — running it through `sh -e` fails.
function executableChainedHook(name) {
  return `#!${process.execPath}
const fs = require("node:fs");
fs.writeFileSync(".chain-${name}-args", process.argv.slice(2).join("\\n") + "\\n");
if ("${name}" === "pre-push") fs.writeFileSync(".chain-${name}-stdin", fs.readFileSync(0));
process.exit(fs.existsSync(".chain-exit") ? Number(fs.readFileSync(".chain-exit", "utf8").trim()) : 0);
`;
}

function fixture({ chainHooksDir, chainedHooksIn, chainedHooks = [], executable = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "flywheel-install-test-"));
  git(dir, "init", "-b", "main");
  // Without an author identity git exits 128 on commit; that is not a guard block.
  git(dir, "config", "user.name", "Flywheel Test");
  git(dir, "config", "user.email", "flywheel-test@example.invalid");
  fs.cpSync(path.join(root, ".githooks"), path.join(dir, ".githooks"), { recursive: true });
  fs.mkdirSync(path.join(dir, "scripts"));
  fs.copyFileSync(path.join(root, "scripts", "install-flywheel-hooks.mjs"), path.join(dir, installer));
  fs.writeFileSync(path.join(dir, "scripts", "flywheel-guard.mjs"), STUB_GUARD);
  writeConfig(dir, chainHooksDir);
  for (const hook of chainedHooks) {
    const target = path.join(dir, chainedHooksIn ?? chainHooksDir, hook);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, executable ? executableChainedHook(hook) : chainedHook(hook));
    if (executable) fs.chmodSync(target, 0o755);
  }
  fs.writeFileSync(path.join(dir, "file.txt"), "install test\n");
  git(dir, "add", "file.txt");
  return dir;
}

function writeConfig(dir, chainHooksDir) {
  const value = { version: 1 };
  if (chainHooksDir !== undefined) value.chainHooksDir = chainHooksDir;
  fs.writeFileSync(path.join(dir, "flywheel.guard.json"), `${JSON.stringify(value, null, 2)}\n`);
}

function install(dir, env = {}) {
  return spawnSync(process.execPath, [installer], { cwd: dir, encoding: "utf8", env: { ...process.env, CI: "", VERCEL: "", ...env } });
}

function runHook(dir, hook, args = [], input = "") {
  return spawnSync(path.join(dir, ".githooks", hook), args, { cwd: dir, encoding: "utf8", input });
}

test("a non-Linux platform warns and exits 0 without touching git config", () => {
  const dir = fixture();
  const result = install(dir, { FLYWHEEL_HOOKS_PLATFORM_OVERRIDE: "win32" });
  assert.equal(result.status, 0);
  assert.match(result.stderr, /not installed/);
  assert.match(result.stderr, /win32/);
  assert.equal(configValue(dir, "core.hooksPath"), null);
  assert.equal(configValue(dir, "flywheel.nodePath"), null);
});

test("FLYWHEEL_HOOKS_STRICT restores the hard failure on a non-Linux platform", () => {
  const dir = fixture();
  const result = install(dir, { FLYWHEEL_HOOKS_PLATFORM_OVERRIDE: "win32", FLYWHEEL_HOOKS_STRICT: "1" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must be installed from WSL\/Linux/);
  assert.equal(configValue(dir, "core.hooksPath"), null);
});

test("FLYWHEEL_HOOKS_STRICT is reachable under CI and VERCEL", () => {
  for (const key of ["CI", "VERCEL"]) {
    const dir = fixture();
    const result = install(dir, { [key]: "1", FLYWHEEL_HOOKS_PLATFORM_OVERRIDE: "win32", FLYWHEEL_HOOKS_STRICT: "1" });
    assert.notEqual(result.status, 0, `${key}: strict must still fail`);
    assert.match(result.stderr, /must be installed from WSL\/Linux/);
  }
});

test("CI and VERCEL remain no-ops", () => {
  for (const key of ["CI", "VERCEL"]) {
    const dir = fixture();
    const result = install(dir, { [key]: "1" });
    assert.equal(result.status, 0);
    assert.equal(configValue(dir, "core.hooksPath"), null);
  }
});

test("FLYWHEEL_HOOKS_PLATFORM_OVERRIDE is ignored outside the test runner", () => {
  const dir = fixture();
  const env = { ...process.env, CI: "", VERCEL: "", FLYWHEEL_HOOKS_PLATFORM_OVERRIDE: "win32" };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, [installer], { cwd: dir, encoding: "utf8", env });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(configValue(dir, "core.hooksPath"), ".githooks", "production must not honor the override");
});

test("a Linux install pins hooks, node and no chain directory by default", () => {
  const dir = fixture();
  const result = install(dir);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(configValue(dir, "core.hooksPath"), ".githooks");
  assert.equal(configValue(dir, "flywheel.nodePath"), process.execPath);
  assert.equal(configValue(dir, "flywheel.chainHooksDir"), null);
});

test("chainHooksDir is mirrored into git config, trimmed, and unset again when the key goes away", () => {
  const dir = fixture({ chainHooksDir: "  .husky/_  ", chainedHooksIn: ".husky/_", chainedHooks: ["pre-commit"] });
  assert.equal(install(dir).status, 0);
  assert.equal(configValue(dir, "flywheel.chainHooksDir"), ".husky/_");
  writeConfig(dir, undefined);
  assert.equal(install(dir).status, 0);
  assert.equal(configValue(dir, "flywheel.chainHooksDir"), null);
});

test("a missing chain directory warns but does not fail the install", () => {
  const dir = fixture({ chainHooksDir: ".husky/_" });
  const result = install(dir);
  assert.equal(result.status, 0);
  assert.match(result.stderr, /not an existing directory/);
  assert.equal(configValue(dir, "flywheel.chainHooksDir"), ".husky/_");
});

test("a chainHooksDir that is a regular file warns like a missing directory", () => {
  const dir = fixture({ chainHooksDir: "hooks-file" });
  fs.writeFileSync(path.join(dir, "hooks-file"), "not a directory\n");
  const result = install(dir);
  assert.equal(result.status, 0);
  assert.match(result.stderr, /not an existing directory/);
});

// A rejected chainHooksDir must never leave the clone unguarded: the hooks go on first, the
// chain key is cleared, and only then does the install fail loudly.
test("a refused chainHooksDir still installs an enforcing guard, then fails the install", () => {
  const cases = [
    { name: "recursion", value: ".githooks", pattern: /chain into themselves/ },
    { name: "recursion, dotted", value: "./.githooks", pattern: /chain into themselves/ },
    { name: "recursion, trailing slash", value: ".githooks/", pattern: /chain into themselves/ },
    { name: "absolute", value: "/etc/hooks", pattern: /not absolute/ },
    { name: "escaping", value: "../outside-hooks", pattern: /stay inside the repository/ },
    { name: "empty", value: "   ", pattern: /non-empty string/ },
    { name: "wrong type", value: 42, pattern: /non-empty string/ },
  ];
  for (const { name, value, pattern } of cases) {
    const dir = fixture({ chainHooksDir: value });
    // A stale value from an earlier good install must be cleared, not left behind.
    git(dir, "config", "flywheel.chainHooksDir", ".stale");
    const result = install(dir);
    assert.equal(result.status, 1, `${name}: install must fail`);
    assert.match(result.stderr, pattern, name);
    assert.equal(configValue(dir, "core.hooksPath"), ".githooks", `${name}: clone must stay guarded`);
    assert.equal(configValue(dir, "flywheel.nodePath"), process.execPath, `${name}: node must stay pinned`);
    assert.equal(configValue(dir, "flywheel.chainHooksDir"), null, `${name}: chain key must be cleared`);
  }
});

test("a symlink pointing at .githooks is refused as recursion", () => {
  const dir = fixture({ chainHooksDir: ".husky-link" });
  fs.symlinkSync(path.join(dir, ".githooks"), path.join(dir, ".husky-link"), "dir");
  const result = install(dir);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /chain into themselves/);
  assert.equal(configValue(dir, "core.hooksPath"), ".githooks");
  assert.equal(configValue(dir, "flywheel.chainHooksDir"), null);
});

test("an unreadable flywheel.guard.json fails the install but leaves the guard enforcing", () => {
  const dir = fixture();
  fs.writeFileSync(path.join(dir, "flywheel.guard.json"), "{ not json\n");
  const result = install(dir);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /cannot resolve chainHooksDir/);
  assert.equal(configValue(dir, "core.hooksPath"), ".githooks");
  assert.equal(configValue(dir, "flywheel.chainHooksDir"), null);
});

test("a chained pre-commit runs after a passing guard and its non-zero exit blocks the commit", () => {
  const dir = fixture({ chainHooksDir: ".husky/_", chainedHooks: ["pre-commit"] });
  assert.equal(install(dir).status, 0);

  git(dir, "commit", "-m", "first");
  assert.ok(fs.existsSync(path.join(dir, ".guard-pre-commit.json")));
  assert.ok(fs.existsSync(path.join(dir, ".chain-pre-commit-args")));

  fs.writeFileSync(path.join(dir, "file.txt"), "second\n");
  git(dir, "add", "file.txt");
  fs.writeFileSync(path.join(dir, ".chain-exit"), "3\n");
  const blocked = spawnSync("git", ["commit", "-m", "second"], { cwd: dir, encoding: "utf8" });
  assert.notEqual(blocked.status, 0);
  assert.equal(git(dir, "rev-list", "--count", "HEAD").trim(), "1");
});

test("an executable chained pre-commit is run directly and its non-zero exit blocks the commit", () => {
  const dir = fixture({ chainHooksDir: ".husky/_", chainedHooks: ["pre-commit"], executable: true });
  assert.equal(install(dir).status, 0);
  assert.notEqual(fs.statSync(path.join(dir, ".husky", "_", "pre-commit")).mode & 0o111, 0);
  git(dir, "commit", "-m", "first");
  assert.ok(fs.existsSync(path.join(dir, ".chain-pre-commit-args")));

  fs.writeFileSync(path.join(dir, "file.txt"), "second\n");
  git(dir, "add", "file.txt");
  fs.writeFileSync(path.join(dir, ".chain-exit"), "5\n");
  const blocked = spawnSync("git", ["commit", "-m", "second"], { cwd: dir, encoding: "utf8" });
  assert.notEqual(blocked.status, 0);
  assert.equal(git(dir, "rev-list", "--count", "HEAD").trim(), "1");
});

test("a failing guard short-circuits: the chained hook never runs", () => {
  const dir = fixture({ chainHooksDir: ".husky/_", chainedHooks: ["pre-commit"] });
  assert.equal(install(dir).status, 0);
  fs.writeFileSync(path.join(dir, ".guard-exit"), "1\n");
  const blocked = spawnSync("git", ["commit", "-m", "blocked"], { cwd: dir, encoding: "utf8" });
  assert.notEqual(blocked.status, 0);
  assert.equal(fs.existsSync(path.join(dir, ".chain-pre-commit-args")), false);
  assert.equal(git(dir, "rev-list", "--count", "--all").trim(), "0");
});

test("a non-executable chained hook is still run, via sh -e", () => {
  const dir = fixture({ chainHooksDir: ".husky/_", chainedHooks: ["pre-commit"] });
  assert.equal(install(dir).status, 0);
  assert.equal(fs.statSync(path.join(dir, ".husky", "_", "pre-commit")).mode & 0o111, 0);
  const result = runHook(dir, "pre-commit");
  assert.equal(result.status, 0, result.stderr);
  assert.ok(fs.existsSync(path.join(dir, ".chain-pre-commit-args")));
});

test("pre-push replays the identical stdin bytes to the guard and the chained hook", () => {
  const dir = fixture({ chainHooksDir: ".husky/_", chainedHooks: ["pre-push"] });
  assert.equal(install(dir).status, 0);
  const refs = "refs/heads/main 1111111111111111111111111111111111111111 refs/heads/main 2222222222222222222222222222222222222222\nrefs/heads/topic 3333333333333333333333333333333333333333 refs/heads/topic 0000000000000000000000000000000000000000\n";
  const result = runHook(dir, "pre-push", ["origin", "git@github.com:example/repo.git"], refs);
  assert.equal(result.status, 0, result.stderr);
  const seenByGuard = JSON.parse(fs.readFileSync(path.join(dir, ".guard-pre-push.json"), "utf8")).stdin;
  const seenByChain = fs.readFileSync(path.join(dir, ".chain-pre-push-stdin"), "utf8");
  assert.equal(seenByGuard, refs);
  assert.equal(seenByChain, refs);
  assert.deepEqual(fs.readFileSync(path.join(dir, ".chain-pre-push-args"), "utf8").split("\n").filter(Boolean), ["origin", "git@github.com:example/repo.git"]);
});

test("pre-push replays stdin to an executable chained hook too", () => {
  const dir = fixture({ chainHooksDir: ".husky/_", chainedHooks: ["pre-push"], executable: true });
  assert.equal(install(dir).status, 0);
  assert.notEqual(fs.statSync(path.join(dir, ".husky", "_", "pre-push")).mode & 0o111, 0);
  const refs = "refs/heads/main 4444444444444444444444444444444444444444 refs/heads/main 5555555555555555555555555555555555555555\n";
  const result = runHook(dir, "pre-push", ["origin", "url"], refs);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir, ".guard-pre-push.json"), "utf8")).stdin, refs);
  assert.equal(fs.readFileSync(path.join(dir, ".chain-pre-push-stdin"), "utf8"), refs);
});

test("pre-push without a chained hook still feeds stdin to the guard", () => {
  const dir = fixture();
  assert.equal(install(dir).status, 0);
  const refs = "refs/heads/main aaaa refs/heads/main bbbb\n";
  const result = runHook(dir, "pre-push", ["origin", "url"], refs);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir, ".guard-pre-push.json"), "utf8")).stdin, refs);
});

test("commit-msg passes the message file path to the guard and to the chained hook", () => {
  const dir = fixture({ chainHooksDir: ".husky/_", chainedHooks: ["commit-msg"] });
  assert.equal(install(dir).status, 0);
  const message = path.join(dir, ".git", "COMMIT_EDITMSG_TEST");
  fs.writeFileSync(message, "subject\n");
  const result = runHook(dir, "commit-msg", [message]);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, ".guard-commit-msg.json"), "utf8")).args, [message]);
  assert.equal(fs.readFileSync(path.join(dir, ".chain-commit-msg-args"), "utf8").trim(), message);
});

test("a chained pre-push non-zero exit blocks the push", () => {
  const dir = fixture({ chainHooksDir: ".husky/_", chainedHooks: ["pre-push"] });
  assert.equal(install(dir).status, 0);
  fs.writeFileSync(path.join(dir, ".chain-exit"), "7\n");
  const result = runHook(dir, "pre-push", ["origin", "url"], "refs\n");
  assert.equal(result.status, 7);
});

// A multi-valued flywheel.chainHooksDir must resolve deterministically to the value the
// installer wrote first, not to whatever `git config --get` happens to return for a repeated
// key (git 2.43 answers with the LAST value; other versions exit 2, which would read as "no
// chaining" and silently drop the consumer's hooks). The wrappers use --get-all | head -n 1.
test("a multi-valued flywheel.chainHooksDir chains on the first value, not the last", () => {
  const dir = fixture({ chainHooksDir: ".husky/_", chainedHooks: ["pre-commit"] });
  assert.equal(install(dir).status, 0);
  const alt = path.join(dir, ".husky", "alt");
  fs.mkdirSync(alt, { recursive: true });
  fs.writeFileSync(path.join(alt, "pre-commit"), "#!/bin/sh\ntouch .chain-alt-ran\n");
  git(dir, "config", "--add", "flywheel.chainHooksDir", ".husky/alt");

  const lookup = spawnSync("git", ["config", "--get-all", "flywheel.chainHooksDir"], { cwd: dir, encoding: "utf8" });
  assert.deepEqual(lookup.stdout.trim().split("\n"), [".husky/_", ".husky/alt"]);

  const result = runHook(dir, "pre-commit");
  assert.equal(result.status, 0, result.stderr);
  assert.ok(fs.existsSync(path.join(dir, ".chain-pre-commit-args")), "the first value's hook must run");
  assert.equal(fs.existsSync(path.join(dir, ".chain-alt-ran")), false, "the last value's hook must not run");
});
