#!/usr/bin/env python3
"""Compare published PKCS #11 modules using one lifecycle client on a runner."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import zipfile


PASS_MARKER = "[LIFECYCLE] PASS: late C_CloseSession and C_Finalize after main"


def download_and_unpack(repo, tag, asset, destination):
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / asset
    subprocess.run(
        ["gh", "release", "download", tag, "--repo", repo,
         "--pattern", asset, "--dir", str(destination)],
        check=True,
    )
    with zipfile.ZipFile(archive) as package:
        package.extractall(destination)


def check_one(client, module, workdir, version, profile):
    store = workdir / "stores" / f"{version}-{profile}"
    tokens = store / "tokens"
    tokens.mkdir(parents=True)
    config = store / "softhsm.conf"
    config.write_text(
        f"directories.tokendir = {tokens.resolve().as_posix()}\n"
        f"objectstore.backend = file\nFAKE_RUTOKEN_ECP = {profile}\n",
        encoding="ascii",
    )
    environment = os.environ.copy()
    environment["SOFTHSM2_CONF"] = str(config.resolve())
    environment["P11_TEST_EXCLUDE_FUNCTIONS"] = ""
    try:
        result = subprocess.run(
            [str(client.resolve()), "lifecycle", str(module.resolve())],
            cwd=store,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=180,
            check=False,
        )
        output = result.stdout
        exit_code = result.returncode
    except subprocess.TimeoutExpired as error:
        output = str(error.stdout or b"") + "\nTIMEOUT\n"
        exit_code = "timeout"
    log_dir = workdir / "logs"
    log_dir.mkdir(exist_ok=True)
    (log_dir / f"{version}-{profile}.log").write_text(output, encoding="utf-8")
    passed = exit_code == 0 and PASS_MARKER in output
    print(f"[LIFECYCLE-A/B] {version} profile={profile}: "
          f"exit={exit_code}, marker={PASS_MARKER in output}, pass={passed}", flush=True)
    return passed, exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-module", type=Path)
    parser.add_argument("--fixed-module", type=Path)
    parser.add_argument("--client", type=Path)
    parser.add_argument("--workdir", type=Path)
    arguments = parser.parse_args()

    workdir = (arguments.workdir or Path(os.environ.get("RUNNER_TEMP", "/tmp")) /
               "lifecycle-compare").resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    supplied = [arguments.old_module, arguments.fixed_module, arguments.client]
    if any(supplied) and not all(supplied):
        parser.error("--old-module, --fixed-module and --client must be given together")

    if all(supplied):
        old_module, fixed_module, client = supplied
    else:
        repo = os.environ["GITHUB_REPOSITORY"]
        old_tag = os.environ.get("LIFECYCLE_OLD_TAG", "v2.7.0-portable.75")
        fixed_tag = os.environ["LIFECYCLE_FIXED_TAG"]
        platform = os.environ["LIFECYCLE_PLATFORM"]
        arch = os.environ["LIFECYCLE_ARCH"]
        product_asset = f"softhsm-portable-{platform}-{arch}.zip"
        kit_asset = f"softhsm-testkit-{platform}-{arch}.zip"
        old_dir, fixed_dir, kit_dir = (
            workdir / "old", workdir / "fixed", workdir / "kit")
        download_and_unpack(repo, old_tag, product_asset, old_dir)
        download_and_unpack(repo, fixed_tag, product_asset, fixed_dir)
        download_and_unpack(repo, fixed_tag, kit_asset, kit_dir)
        if platform == "windows":
            module_name, client_name = "softhsm2.dll", "portable-token-e2e.exe"
        elif platform == "macos":
            module_name, client_name = "libsofthsm2.dylib", "portable-token-e2e"
        else:
            parser.error("the release comparison supports macos and windows")
        old_module, fixed_module = old_dir / module_name, fixed_dir / module_name
        client = kit_dir / "bin" / client_name
        if platform == "macos":
            client.chmod(client.stat().st_mode | 0o111)

    for path in (old_module, fixed_module, client):
        if not path.is_file():
            parser.error(f"missing input file: {path}")

    rows = []
    for profile in ("false", "true"):
        old_ok, old_exit = check_one(client, old_module, workdir, "old", profile)
        fixed_ok, fixed_exit = check_one(client, fixed_module, workdir, "fixed", profile)
        rows.append((profile, old_ok, old_exit, fixed_ok, fixed_exit))

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as report:
            report.write("\n| Profile | .75 passes | Fixed passes |\n"
                         "| --- | --- | --- |\n")
            for profile, old_ok, _, fixed_ok, _ in rows:
                report.write(f"| {profile} | {old_ok} | {fixed_ok} |\n")

    if any(not fixed_ok for _, _, _, fixed_ok, _ in rows):
        print("[LIFECYCLE-A/B] FAIL: the fixed release failed; see logs", file=sys.stderr)
        return 1
    if any(old_ok for _, old_ok, _, _, _ in rows):
        print("[LIFECYCLE-A/B] NOT REPRODUCED: .75 also passed on this runner; "
              "the scenario does not prove a historical bug here", flush=True)
        # Windows unloads DLLs after executable atexit handlers, so the old
        # destructor-order bug may genuinely be absent there. A successful
        # fixed release is still required, and the old result stays visible.
        return 0 if os.environ.get("LIFECYCLE_PLATFORM") == "windows" else 2
    print("[LIFECYCLE-A/B] PASS: .75 failed and the fixed release passed "
          "with both profiles")
    return 0


if __name__ == "__main__":
    sys.exit(main())
