#!/usr/bin/env node
// Flywheel guard hook installer. Runs from the package.json `prepare` script, which means it
// runs on every `npm install` / `pnpm install` in every repository that vendors the guard —
// including the ones that are developed from a Windows shell. It must therefore never make a
// plain `npm install` fail on a platform where the guard is not meant to be installed.
//
// Behavior:
//   - platform is not linux and
//     FLYWHEEL_HOOKS_STRICT=1       -> throw, as this installer used to do unconditionally.
//                                      Checked before the CI/VERCEL no-op so it is reachable
//                                      from CI, which is where a hard failure is most useful.
//   - `CI` or `VERCEL` set          -> no-op, exit 0. Production builds ride on this path.
//   - platform is not linux         -> one-line warning on stderr, no git config touched, exit 0.
//   - linux                         -> refuse a non-ELF (Windows/PE) Node, make the `.githooks`
//                                      shims executable, set `core.hooksPath=.githooks`, pin
//                                      `flywheel.nodePath` to this Node, and mirror the optional
//                                      `chainHooksDir` key of flywheel.guard.json into the
//                                      repo-local `flywheel.chainHooksDir` git config (unsetting
//                                      it when the key is absent, so a stale value never lingers).
//
// A rejected `chainHooksDir` still leaves a fully installed, enforcing guard: the hooks are wired
// and `flywheel.chainHooksDir` is unset before the error is reported. A config mistake must never
// downgrade a clone to unguarded — it fails the install loudly with the guard switched on.
//
// Environment variables:
//   CI, VERCEL                        install is a no-op (unchanged, long-standing behavior).
//   FLYWHEEL_HOOKS_STRICT=1           a non-Linux platform throws instead of warning, including
//                                     under CI/VERCEL.
//   FLYWHEEL_HOOKS_PLATFORM_OVERRIDE  TEST-ONLY. Substitutes for `process.platform` so the
//                                     non-Linux paths can be exercised from the Linux test
//                                     suite. Honored only when NODE_TEST_CONTEXT is set, i.e.
//                                     under `node --test`; in production it is ignored, so it
//                                     cannot become a one-variable opt-out of guard install.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HOOKS = ["pre-commit", "commit-msg", "pre-push"];
const GITHOOKS = ".githooks";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const platform = (process.env.NODE_TEST_CONTEXT && process.env.FLYWHEEL_HOOKS_PLATFORM_OVERRIDE) || process.platform;

if (platform !== "linux" && process.env.FLYWHEEL_HOOKS_STRICT === "1") {
  throw new Error("Flywheel hooks must be installed from WSL/Linux");
}

if (!process.env.CI && !process.env.VERCEL) {
  if (platform !== "linux") {
    console.error(`Flywheel guard hooks not installed: platform "${platform}" is not linux, and the guard is only installed in Linux worker clones (set FLYWHEEL_HOOKS_STRICT=1 to fail instead).`);
  } else {
    const magic = fs.readFileSync(process.execPath).subarray(0, 4);
    if (!magic.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) throw new Error(`refusing non-ELF Node runtime: ${process.execPath}`);
    const probe = spawnSync("git", ["rev-parse", "--git-dir"], { cwd: root, encoding: "utf8" });
    if (probe.status === 0) {
      let chain = null;
      let chainError = null;
      try { chain = chainHooksDir(root); } catch (error) { chainError = error; }

      // The guard goes on first, unconditionally. Only then is a bad chainHooksDir reported.
      for (const hook of HOOKS) fs.chmodSync(path.join(root, GITHOOKS, hook), 0o755);
      const install = spawnSync("git", ["config", "core.hooksPath", GITHOOKS], { cwd: root, encoding: "utf8" });
      const pin = spawnSync("git", ["config", "flywheel.nodePath", process.execPath], { cwd: root, encoding: "utf8" });
      // `git config --unset-all` exits 5 when the key was never set; that is a success here.
      const chained = chain === null
        ? spawnSync("git", ["config", "--unset-all", "flywheel.chainHooksDir"], { cwd: root, encoding: "utf8" })
        : spawnSync("git", ["config", "flywheel.chainHooksDir", chain], { cwd: root, encoding: "utf8" });
      const chainedOk = chain === null ? chained.status === 0 || chained.status === 5 : chained.status === 0;

      if (install.status !== 0 || pin.status !== 0 || !chainedOk) {
        console.error(install.stderr || pin.stderr || chained.stderr || "failed to install Flywheel hooks");
        process.exitCode = 1;
      } else {
        console.log(`Flywheel hooks installed at ${GITHOOKS}`);
        if (chainError) {
          console.error(chainError.message);
          console.error("Flywheel hooks: the guard is installed and enforcing; chaining is disabled until the config is fixed.");
          process.exitCode = 1;
        } else if (chain !== null && !isDirectory(path.resolve(root, chain))) {
          console.error(`Flywheel hooks: chainHooksDir "${chain}" is not an existing directory; chained hooks are skipped until it is.`);
        }
      }
    }
  }
}

// Optional `chainHooksDir` in flywheel.guard.json. Git allows exactly one core.hooksPath, so a
// repository that already uses husky loses its own hooks when the guard takes that slot. The
// wrappers chain into this directory after the guard passes. Returns the trimmed value, or null
// when unconfigured. Throws on anything the wrappers must not be handed.
function chainHooksDir(dir) {
  const file = path.join(dir, "flywheel.guard.json");
  if (!fs.existsSync(file)) return null;
  let raw;
  try { raw = JSON.parse(fs.readFileSync(file, "utf8")).chainHooksDir; }
  catch (error) { throw new Error(`${file}: unreadable, cannot resolve chainHooksDir (${error.message})`); }
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "string" || raw.trim() === "") throw new Error(`${file}: chainHooksDir must be a non-empty string`);
  const value = raw.trim();
  if (path.isAbsolute(value)) throw new Error(`${file}: chainHooksDir must be a repository-relative path, not absolute: "${value}"`);
  const resolved = path.resolve(dir, value);
  if (path.relative(dir, resolved).startsWith("..")) {
    throw new Error(`${file}: chainHooksDir must stay inside the repository: "${value}"`);
  }
  if (realpath(resolved) === realpath(path.resolve(dir, GITHOOKS))) {
    throw new Error(`${file}: chainHooksDir must not resolve to ${GITHOOKS} — the guard wrappers would chain into themselves: "${value}"`);
  }
  return value;
}

// Symlinks are resolved so that a link pointing at .githooks is caught by the recursion check;
// a path that does not exist yet falls back to its lexical form.
function realpath(target) {
  try { return fs.realpathSync(target); } catch { return target; }
}

function isDirectory(target) {
  try { return fs.statSync(target).isDirectory(); } catch { return false; }
}
