#!/usr/bin/env python3
"""Collect CDDE log archives through temporary private Azure Blob Storage."""
import argparse
import datetime as dt
import gzip
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import parse_qs, urlsplit
import uuid

from cdde_validation import digest, write_json

LOG_DIRECTORY = "Microsoft.Azure.Security.ConfidentialDiskEncryption.CDELinux"
CONTAINER = "diagnostic-logs"


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def redact(message):
    return re.sub(r"(?i)((?:sig|AccountKey)=)[^&\s\"';]+", r"\1<redacted>", str(message))


def upload_script(url):
    script = r"""
set -eu
umask 077
for tool in tar gzip curl sha256sum stat mktemp; do
  command -v "$tool" >/dev/null || { echo "Missing guest tool: $tool" >&2; exit 1; }
done
directory=Microsoft.Azure.Security.ConfidentialDiskEncryption.CDELinux
test "$(id -u)" -eq 0 || { echo "Guest collection requires root." >&2; exit 1; }
test -d "/var/log/azure/$directory" || { echo "Requested CDDE log directory not found." >&2; exit 1; }
tmpdir=$(mktemp -d /tmp/cdde-diagnostic-logs.XXXXXXXXXX)
archive="$tmpdir/cdde-logs.tar.gz"
trap 'rm -f "$tmpdir/cdde-logs.tar.gz" "$tmpdir/tar.stderr"; rmdir "$tmpdir"' EXIT
for attempt in 1 2 3; do
  if tar -C /var/log/azure -czf "$archive" -- "$directory" 2>"$tmpdir/tar.stderr"; then
    break
  else
    rc=$?
  fi
  tail -c 1000 "$tmpdir/tar.stderr" >&2
  if test "$rc" -ne 1 || test "$attempt" -eq 3; then exit "$rc"; fi
  echo "Logs changed during tar; retrying capture." >&2
  sleep 2
done
test -s "$archive"
curl --fail --silent --show-error --connect-timeout 30 --max-time 300 \
  --retry 2 --retry-delay 5 \
  --request PUT --header "x-ms-blob-type: BlockBlob" \
  --header "Content-Type: application/gzip" \
  --upload-file "$archive" __UPLOAD_URL__
hash=$(sha256sum "$archive")
bytes=$(stat -c %s "$archive")
rm -f "$archive" "$tmpdir/tar.stderr"
rmdir "$tmpdir"
trap - EXIT
printf 'CDDE_ARCHIVE_SHA256=%s\n' "${hash%% *}"
printf 'CDDE_ARCHIVE_BYTES=%s\n' "$bytes"
echo CDDE_LOG_EXPORT=PASS
"""
    return script.replace("__UPLOAD_URL__", shlex.quote(url))


def guest_output(value, marker):
    entries = value.get("value") if isinstance(value, dict) else None
    if (not isinstance(entries, list) or not entries or
            any(not isinstance(item, dict) or not isinstance(item.get("message", ""), str) for item in entries)):
        raise RuntimeError("Invalid Run Command response")
    if (not any(str(item.get("code", "")).lower().endswith("/succeeded") for item in entries) or
            any("/failed" in str(item.get("code", "")).lower() for item in entries)):
        raise RuntimeError("Run Command transport failed")
    text = "\n".join(item.get("message", "") for item in entries)
    if marker not in text.splitlines():
        raise RuntimeError("Guest command did not complete successfully: " + redact(text[-1600:]))
    return text


def archive_metadata(value):
    text = guest_output(value, "CDDE_LOG_EXPORT=PASS")
    hashes = re.findall(r"^CDDE_ARCHIVE_SHA256=([0-9a-f]{64})\r?$", text, re.MULTILINE)
    sizes = re.findall(r"^CDDE_ARCHIVE_BYTES=([0-9]+)\r?$", text, re.MULTILINE)
    if len(hashes) != 1 or len(sizes) != 1 or int(sizes[0]) <= 0:
        raise RuntimeError("Guest archive hash/size is missing or ambiguous")
    return hashes[0], int(sizes[0])


def verify_archive(file, expected_hash, expected_size):
    if file.stat().st_size != expected_size or digest(file) != expected_hash:
        raise RuntimeError("Downloaded archive size or SHA-256 differs from the guest archive")
    with gzip.open(file, "rb") as stream:
        while stream.read(1024 * 1024):
            pass
    with tarfile.open(file, "r:gz") as archive:
        members = archive.getmembers()
        if not members or not any(member.isfile() for member in members):
            raise RuntimeError("The log archive contains no regular files")
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or not name.parts or name.parts[0] != LOG_DIRECTORY:
                raise RuntimeError("Unexpected archive path: " + member.name)
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise RuntimeError("Unexpected archive member type: " + member.name)
            if member.issym() or member.islnk():
                target = posixpath.normpath(
                    posixpath.join(str(name.parent), member.linkname) if member.issym() else member.linkname)
                if target != LOG_DIRECTORY and not target.startswith(LOG_DIRECTORY + "/"):
                    raise RuntimeError("Archive link points outside the log directory: " + member.name)
    return len(members)


class Collector:
    def __init__(self, args):
        self.args = args
        self.directory = Path(args.output).resolve()
        self.directory.mkdir(parents=True, exist_ok=False)
        self.token = uuid.uuid4().hex
        self.account = "cddelogs" + self.token[:16]
        self.auth = None
        self.created = False
        self.uncertain = set()
        self.report = {"started_utc": utc(), "subscription": args.subscription,
            "resource_group": args.resource_group, "log_directory": "/var/log/azure/" + LOG_DIRECTORY,
            "temporary_storage_account": self.account, "storage_creation_attempted": False,
            "storage_deleted": False, "vms": {}, "errors": []}
        self.save()

    def save(self):
        temporary = self.directory / "collection.json.tmp"
        write_json(temporary, self.report)
        os.replace(temporary, self.directory / "collection.json")

    def az(self, *args, output="json", storage=False):
        command = ["az", *map(str, args), "--subscription", self.args.subscription,
                   "--only-show-errors", "--output", output]
        env = None
        if storage:
            if self.auth is None:
                raise RuntimeError("Temporary storage authentication is unavailable")
            env = os.environ.copy()
            for key in ("AZURE_STORAGE_CONNECTION_STRING", "AZURE_STORAGE_SAS_TOKEN"):
                env.pop(key, None)
            env.update(self.auth)
            command += ["--auth-mode", "key", "--account-name", self.account]
        print("Azure CLI:", " ".join(map(str, args[:3])), flush=True)
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=self.args.timeout, env=env)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Azure CLI operation timed out; its Azure operation may still be running") from None
        if result.returncode:
            raise RuntimeError("Azure CLI operation failed: " + redact(result.stderr.strip()))
        if output == "tsv":
            return result.stdout.strip()
        if not result.stdout.strip():
            return None
        try:
            return json.loads(result.stdout)
        except ValueError as error:
            raise RuntimeError("Azure CLI returned invalid JSON") from error

    def wait(self, description, query, ready):
        print("Waiting for " + description, flush=True)
        deadline = time.monotonic() + self.args.timeout
        while True:
            value = query()
            if ready(value):
                return value
            if time.monotonic() >= deadline:
                raise RuntimeError("Timed out waiting for " + description)
            time.sleep(15)

    def view(self, vm):
        value = self.az("vm", "get-instance-view", "-g", self.args.resource_group, "-n", vm)
        if not isinstance(value, dict) or not isinstance(value.get("instanceView"), dict):
            raise RuntimeError("Invalid VM instance-view response for " + vm)
        return value["instanceView"]

    def power(self, vm):
        statuses = self.view(vm).get("statuses", [])
        if not isinstance(statuses, list) or any(not isinstance(item, dict) for item in statuses):
            raise RuntimeError("Invalid VM power status response for " + vm)
        states = [item.get("code", "") for item in statuses
                  if isinstance(item, dict) and str(item.get("code", "")).startswith("PowerState/")]
        if len(states) != 1:
            raise RuntimeError("Cannot establish VM power state for " + vm)
        return states[0]

    def setup_storage(self, location):
        available = self.az("storage", "account", "check-name", "--name", self.account)
        if not isinstance(available, dict) or available.get("nameAvailable") is not True:
            raise RuntimeError("Temporary storage account name is unavailable")
        self.report["storage_creation_attempted"] = True
        self.save()
        account = self.az("storage", "account", "create", "-g", self.args.resource_group,
            "-n", self.account, "-l", location, "--sku", "Standard_LRS", "--kind", "StorageV2",
            "--https-only", "true", "--min-tls-version", "TLS1_2",
            "--allow-blob-public-access", "false", "--allow-shared-key-access", "true",
            "--tags", "cdde-log-collector=" + self.token)
        self.created = True
        self.report["storage_id"] = account["id"]
        self.save()
        keys = self.az("storage", "account", "keys", "list", "-g", self.args.resource_group, "-n", self.account)
        if (not isinstance(keys, list) or not keys or not isinstance(keys[0], dict) or
                not isinstance(keys[0].get("value"), str) or not keys[0]["value"]):
            raise RuntimeError("Could not obtain temporary storage credentials")
        self.auth = {"AZURE_STORAGE_ACCOUNT": self.account, "AZURE_STORAGE_KEY": keys[0]["value"]}
        self.az("storage", "container", "create", "--name", CONTAINER, "--public-access", "off", storage=True)

    def upload_url(self, blob):
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%MZ")
        url = self.az("storage", "blob", "generate-sas", "--container-name", CONTAINER,
            "--name", blob, "--permissions", "cw", "--expiry", expiry,
            "--https-only", "--full-uri", output="tsv", storage=True)
        parsed = urlsplit(url)
        permissions = parse_qs(parsed.query).get("sp", [""])[0]
        if (parsed.scheme != "https" or not parsed.hostname or
                not parsed.hostname.startswith(self.account + ".") or
                not parse_qs(parsed.query).get("sig") or "w" not in permissions or set(permissions) - set("cw")):
            raise RuntimeError("Unexpected temporary upload URL or permissions")
        return url

    def invoke(self, vm, script):
        with tempfile.NamedTemporaryFile(mode="w", prefix="cdde-diagnostics-", suffix=".sh", encoding="utf-8") as payload:
            payload.write(script)
            payload.flush()
            self.uncertain.add(vm)
            value = self.az("vm", "run-command", "invoke", "-g", self.args.resource_group, "-n", vm,
                            "--command-id", "RunShellScript", "--scripts", "@" + payload.name)
            self.uncertain.discard(vm)
        return value

    def collect(self, vm):
        record = self.report["vms"][vm]
        original = record["original_power_state"]
        restore = original != "PowerState/running"
        invoked = False
        try:
            if restore:
                record["power_restore_pending"] = True
                self.save()
                self.az("vm", "start", "-g", self.args.resource_group, "-n", vm)
            self.wait(vm + " guest agent", lambda: self.view(vm), lambda view: any(
                item.get("code") == "ProvisioningState/succeeded"
                for item in (view.get("vmAgent") or {}).get("statuses", [])))
            name = vm + "-cdde-logs.tar.gz"
            url = self.upload_url(name)
            record["capture_started_utc"] = utc()
            self.save()
            invoked = True
            value = self.invoke(vm, upload_script(url))
            expected_hash, expected_size = archive_metadata(value)
            partial = self.directory / (name + ".partial")
            self.az("storage", "blob", "download", "--container-name", CONTAINER, "--name", name,
                    "--file", partial, "--overwrite", "true", storage=True)
            members = verify_archive(partial, expected_hash, expected_size)
            partial.replace(self.directory / name)
            record.update(verified=True, archive=name, sha256=expected_hash, bytes=expected_size,
                          members=members, captured_utc=utc())
            print("Verified archive:", self.directory / name, flush=True)
        finally:
            handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
            try:
                if invoked and vm not in self.uncertain:
                    try:
                        # Replace the upload script so a future OS restore cannot replay it.
                        value = self.invoke(vm, "printf 'CDDE_LOG_FENCE=PASS\\n'")
                        guest_output(value, "CDDE_LOG_FENCE=PASS")
                        record["read_only_fence_completed"] = True
                    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                        self.error(vm + " read-only fence", error)
                if vm in self.uncertain:
                    self.error(vm, "Run Command completion is uncertain; VM and storage left in place. "
                               "A CLI timeout or interruption does not cancel the Azure operation.")
                elif restore:
                    try:
                        verb = "deallocate" if original == "PowerState/deallocated" else "stop"
                        self.az("vm", verb, "-g", self.args.resource_group, "-n", vm)
                        self.wait(vm + " original power state", lambda: self.power(vm), lambda state: state == original)
                        record["power_restore_pending"] = False
                    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                        self.error(vm + " power restoration", error)
            finally:
                self.save()
                for sig, handler in handlers.items():
                    signal.signal(sig, handler)

    def error(self, context, error):
        message = context + ": " + redact(error)
        if self.auth:
            message = message.replace(self.auth["AZURE_STORAGE_KEY"], "<redacted>")
        self.report["errors"].append(message)
        print("ERROR:", message, file=sys.stderr, flush=True)
        self.save()

    def run(self):
        try:
            location = None
            for vm in self.args.vms:
                model = self.az("vm", "show", "-g", self.args.resource_group, "-n", vm)
                expected = (f"/subscriptions/{self.args.subscription}/resourceGroups/{self.args.resource_group}"
                            "/providers/Microsoft.Compute/virtualMachines/" + vm)
                if not isinstance(model, dict) or str(model.get("id", "")).lower() != expected.lower():
                    raise RuntimeError("VM identity mismatch for " + vm)
                location = location or model["location"]
                original = self.power(vm)
                if original not in ("PowerState/running", "PowerState/stopped", "PowerState/deallocated"):
                    raise RuntimeError(vm + " has a transitional/unsupported power state: " + original)
                self.report["vms"][vm] = {"original_power_state": original, "verified": False}
                self.save()
            self.setup_storage(location)
            for vm in self.args.vms:
                try:
                    self.collect(vm)
                except (RuntimeError, OSError, ValueError, EOFError, tarfile.TarError, subprocess.TimeoutExpired) as error:
                    self.error(vm + " collection", error)
        except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            self.error("Collection stopped", str(error) or "Interrupted")
        finally:
            verified = (len(self.report["vms"]) == len(self.args.vms) and
                        all(record["verified"] for record in self.report["vms"].values()))
            if self.created and verified and not self.uncertain:
                try:
                    account = self.az("storage", "account", "show", "-g", self.args.resource_group, "-n", self.account)
                    if (not isinstance(account, dict) or
                            str(account.get("id", "")).lower() != self.report["storage_id"].lower() or
                            not isinstance(account.get("tags"), dict) or
                            account["tags"].get("cdde-log-collector") != self.token):
                        raise RuntimeError("Storage ownership mismatch; deletion refused")
                    self.az("storage", "account", "delete", "-g", self.args.resource_group, "-n", self.account, "--yes")
                    self.wait("temporary storage deletion", lambda: self.az(
                        "storage", "account", "list", "-g", self.args.resource_group,
                        "--query", "[?name=='" + self.account + "'].name"), lambda names: names == [])
                    self.report["storage_deleted"] = True
                except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                    self.error("Temporary storage cleanup", error)
            self.auth = None
            self.report["finished_utc"] = utc()
            self.save()
            lines = [record["sha256"] + "  " + record["archive"] for record in self.report["vms"].values()
                     if record["verified"]]
            (self.directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
            if self.report["storage_creation_attempted"] and not self.report["storage_deleted"]:
                print("Temporary storage may remain:", self.account, "in", self.args.resource_group)
                print("Inspect collection.json before cleanup; an Azure Run Command may still be running.")
            print("Collection report:", self.directory / "collection.json")
        return 0 if verified and not self.report["errors"] else 1


def interrupt(signum, frame):
    raise KeyboardInterrupt()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subscription", required=True)
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--vms", nargs="+", required=True)
    parser.add_argument("--output", default=str(Path(__file__).resolve().parent / "evidence" /
        ("diagnostic-logs-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))))
    parser.add_argument("--timeout", type=int, default=1800, help="Timeout per CLI operation/readiness wait, seconds")
    parser.add_argument("--allow-temporary-resources", action="store_true",
                        help="Consent to temporary storage and restoring stopped/deallocated VMs after collection")
    args = parser.parse_args()
    if not args.allow_temporary_resources:
        parser.error("--allow-temporary-resources is required; storage and VM startup may incur charges")
    try:
        uuid.UUID(args.subscription)
    except ValueError:
        parser.error("--subscription must be a subscription UUID")
    if (args.timeout <= 0 or not re.fullmatch(r"[A-Za-z0-9_.()-]{1,90}", args.resource_group) or
            any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name) for name in args.vms) or
            len({name.lower() for name in args.vms}) != len(args.vms)):
        parser.error("Invalid timeout, resource group or VM names")
    if not sys.platform.startswith("linux") or not shutil.which("az"):
        parser.error("Run inside Linux/WSL with Azure CLI installed and authenticated using az login")
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupt)
    try:
        collector = Collector(args)
    except OSError as error:
        print("ERROR: Cannot create a new collection directory:", error, file=sys.stderr)
        return 2
    print("Output:", collector.directory)
    print("Captures logs only; CDDE is not re-enabled. Starting a VM can change its current failure state.")
    return collector.run()


if __name__ == "__main__":
    sys.exit(main())
