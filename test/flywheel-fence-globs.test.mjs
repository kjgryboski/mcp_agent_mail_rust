// The fence drift test (RULING-fence-globs.md revision 5). Four order-sensitive copies of the
// critical-path fence now move together, and this file is the tripwire that says so:
//
//   1. AGENTS.md §9, the fenced block — the AUTHORITY, parsed at runtime by
//      scripts/review-sweep.mjs;
//   2. flywheel.guard.json `criticalPathGlobs.globs`, the advisory mirror;
//   3. scripts/flywheel-fence.mjs, the enforced constant;
//   4. the guard's re-export of it, which condition 6 of the janitor exception reads.
//
// This file is itself a fence entry, with the module: a clone that can soften the tripwire can
// soften the fence.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { FENCE_GLOBS as MODULE_GLOBS } from "../scripts/flywheel-fence.mjs";
import { FENCE_GLOBS as GUARD_GLOBS, overlaps } from "../scripts/flywheel-guard.mjs";
import { criticalPathGlobs } from "../scripts/review-sweep.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const modulePath = path.join(root, "scripts", "flywheel-fence.mjs");

test("the fence agrees four ways: AGENTS.md, the mirror, the module, the guard re-export", () => {
  const manual = criticalPathGlobs(root);
  const mirror = JSON.parse(fs.readFileSync(path.join(root, "flywheel.guard.json"), "utf8")).criticalPathGlobs.globs;
  assert.deepEqual(mirror, manual, "flywheel.guard.json diverges from the AGENTS.md authority");
  assert.deepEqual(MODULE_GLOBS, manual, "scripts/flywheel-fence.mjs diverges from the AGENTS.md authority");
  assert.deepEqual(GUARD_GLOBS, MODULE_GLOBS, "the guard no longer re-exports the fence module's list");
});

test("the machinery quintet is fenced, so condition 6 cannot auto-revert the fence itself", () => {
  for (const entry of ["scripts/flywheel-guard.mjs", "scripts/flywheel-fence.mjs", "flywheel.guard.json", ".githooks/**", "test/flywheel-fence-globs.test.mjs"]) {
    assert.equal(MODULE_GLOBS.includes(entry), true, `${entry} must be a fence entry`);
  }
});

// The module must be a BARE literal, not a computed one. Test 1 pins the VALUE, but a value
// check cannot see `export const FENCE_GLOBS = process.env.X ? [] : [ ...entries... ]`, which is
// green in CI and empty in a clone that sets X -- the env-softenable predicate that candidate (a)
// was rejected for, re-entering through the file the split created. So this test reads the SOURCE
// and requires every non-blank line to be one of exactly four forms: a full-line comment, the
// opening `export const FENCE_GLOBS = [`, an entry line `  "<glob>",`, or the closing `];`. That
// admits no ternary, no spread, no call, no identifier, no template literal and no second
// statement -- and it is why the trailing comma on the LAST entry is REQUIRED, not optional.
test("the fence module is a bare literal, one entry per line, in order, with no row packing", () => {
  const lines = fs.readFileSync(modulePath, "utf8").split("\n");
  const COMMENT = /^\s*\/\//;
  const OPEN = /^export const FENCE_GLOBS = \[[ \t]*$/;
  const ENTRY = /^\s+"[^"\\]+",$/;
  const ENTRY_NO_COMMA = /^\s+"[^"\\]+"$/;
  const entries = [];
  const entryLines = [];
  let opens = 0;
  let closes = 0;
  let open = -1;
  let close = -1;
  for (const [index, line] of lines.entries()) {
    if (line.trim() === "") continue;
    if (COMMENT.test(line)) continue;
    if (OPEN.test(line)) { opens += 1; if (open < 0) open = index; continue; }
    if (line === "];") { closes += 1; if (close < 0) close = index; continue; }
    assert.equal(ENTRY_NO_COMMA.test(line), false, `scripts/flywheel-fence.mjs:${index + 1}: every FENCE_GLOBS entry line must be "  <double-quoted glob>," INCLUDING THE LAST -- the trailing comma is REQUIRED on the final entry too, and a generator that omits it fails this vendored test. Found: ${JSON.stringify(line)}`);
    assert.equal(ENTRY.test(line), true, `scripts/flywheel-fence.mjs:${index + 1} is none of the four permitted forms (a full-line comment, "export const FENCE_GLOBS = [", an entry line, or "];"): ${JSON.stringify(line)}. The module must be a bare literal: a ternary, a spread, a call, an identifier or a template literal would let a clone empty the fence without changing its value in CI.`);
    entries.push(line.trim());
    entryLines.push(index);
  }
  assert.equal(opens, 1, `expected exactly one "export const FENCE_GLOBS = [" line, found ${opens}`);
  assert.equal(closes, 1, `expected exactly one "];" line, found ${closes}`);
  assert.equal(open < close, true, "the fence literal must open before it closes");
  assert.ok(entryLines.length > 0, "the fence literal has no entry lines");
  assert.equal(entryLines.every((index) => index > open && index < close), true, "every entry line must sit between the opening bracket and the closing bracket");
  assert.equal(entries.length, MODULE_GLOBS.length, `expected ${MODULE_GLOBS.length} entry lines, found ${entries.length}`);
  for (const [index, glob] of MODULE_GLOBS.entries()) {
    assert.equal(entries[index], `${JSON.stringify(glob)},`, `every FENCE_GLOBS entry line must be "  <double-quoted glob>," INCLUDING THE LAST; entry ${index} is ${JSON.stringify(entries[index])}, expected ${JSON.stringify(`${JSON.stringify(glob)},`)}`);
  }
});

test("no entry is duplicated, uses the brace form, or uses a mid-pattern star-star slash", () => {
  assert.deepEqual([...new Set(MODULE_GLOBS)], MODULE_GLOBS, "the fence has a duplicate entry");
  for (const glob of MODULE_GLOBS) {
    // globRegex matches `{a,b}` literally and requires an intervening directory for `**/`,
    // unlike minimatch; either form silently fences nothing.
    assert.equal(/[{}]/.test(glob), false, `${glob} uses the brace form, which globRegex matches literally`);
    assert.equal(glob.includes("**/"), false, `${glob} uses a mid-pattern **/, which globRegex reads as a required directory`);
  }
});

test("every fence entry matches at least one tracked path under the guard's own matcher", () => {
  const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean);
  assert.ok(tracked.length > 0, "git ls-files returned nothing; the liveness check would pass vacuously");
  for (const glob of MODULE_GLOBS) {
    assert.equal(tracked.some((file) => overlaps(file, glob)), true, `${glob} is a dead fence entry: it matches no tracked path`);
  }
});
