"""Python conformance and recovery validators used by the CDDE lab controller."""
import argparse
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

PUBLISHER = "Microsoft.Azure.Security.ConfidentialDiskEncryption"
PATHS = ("vm-backup", "disk-backup", "snapshot", "restore-point")
CHECKPOINTS = ("initial", "restart", "deallocate-start")


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def timestamp(fine=False):
    value = time.time_ns()
    return time.strftime("%Y%m%dT%H%M%S", time.gmtime(value // 10**9)) + (
        f"{value % 10**9:09d}" if fine else "") + "Z"


def read_json(file):
    try:
        return json.loads(Path(file).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"Cannot read JSON evidence {file}: {error}") from error


def write_json(file, value):
    file = Path(file)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def get(value, path, default=None):
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return default if value is None else value


def lower(value):
    return value.lower() if isinstance(value, str) else ""


def extension_configuration_valid(extension, config):
    sequence = get(extension, "settings.sequenceVersion")
    return (get(extension, "publisher") == config["expected_extension_publisher"] and
            get(extension, "typePropertiesType") == config["expected_extension_type"] and
            isinstance(sequence, str) and bool(sequence) and
            (not config.get("expected_sequence_guid") or sequence == config["expected_sequence_guid"]))


def extension_health(extension):
    state = lower(get(extension, "provisioningState"))
    view = get(extension, "instanceView")
    if view is not None and not isinstance(view, dict):
        return "invalid"
    statuses = get(extension, "instanceView.statuses", [])
    substatuses = get(extension, "instanceView.substatuses", [])
    if (not isinstance(statuses, list) or not isinstance(substatuses, list) or
            any(not isinstance(item, dict) or not isinstance(item.get("code"), str)
                for item in statuses + substatuses)):
        return "invalid"
    if state in ("creating", "updating", "transitioning", "inprogress"):
        return "pending"
    if state in ("failed", "canceled", "cancelled") or any(
            lower(item.get("level")) == "error" or "/failed" in lower(item["code"])
            for item in statuses + substatuses):
        return "failed"
    if state == "succeeded" and any(lower(item["code"]).endswith("/succeeded") for item in statuses):
        return "succeeded"
    if state == "succeeded":
        return "pending"
    return "invalid"


def digest(file):
    value = hashlib.sha256()
    with Path(file).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def hash_bundle(directory, conformance=False):
    directory = Path(directory)
    if conformance:
        files = sorted((directory / "raw").rglob("*"))
        files += [directory / name for name in ("report.json", "junit.xml", "summary.md")]
    else:
        files = sorted(directory.rglob("*"))
    lines = [digest(file) + "  " + ("" if conformance else "./") +
             file.relative_to(directory).as_posix() for file in files
             if file.is_file() and file.name != "SHA256SUMS" and not file.name.endswith(".tmp")]
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def check_checksums(directory):
    directory = Path(directory).resolve()
    try:
        lines = (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise RuntimeError(f"Cannot read checksum manifest: {error}") from error
    if not lines:
        raise RuntimeError("Checksum manifest is empty")
    output, failed = [], False
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        if not match:
            raise RuntimeError("Malformed checksum manifest entry: " + line)
        expected, name = match.groups()
        file = (directory / name).resolve()
        if directory not in file.parents:
            raise RuntimeError("Checksum entry escapes the evidence bundle: " + name)
        try:
            valid = file.is_file() and digest(file) == expected
        except OSError as error:
            raise RuntimeError(f"Cannot hash {name}: {error}") from error
        output.append(name + (": OK" if valid else ": FAILED"))
        failed |= not valid
    return not failed, "\n".join(output) + "\n"


def instant(value):
    if not isinstance(value, str):
        raise RuntimeError("Evidence timestamp must be a string")
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeError("Invalid evidence timestamp: " + value) from error
    if result.tzinfo is None:
        raise RuntimeError("Evidence timestamp must include a UTC offset: " + value)
    return result


def safe_mount(value):
    return (isinstance(value, str) and re.fullmatch(r"/[A-Za-z0-9._/-]+", value) is not None
            and value not in ("/", "/mnt") and ".." not in value)


def load_config(file):
    config = read_json(file)
    if not isinstance(config, dict):
        raise RuntimeError("Validator configuration must be a JSON object")
    for key in ("subscription_id", "resource_group", "vm_name", "vault_name",
                "key_name", "des_name", "identity_name", "mount_point"):
        if not isinstance(config.get(key), str) or not config[key]:
            raise RuntimeError("Missing configuration setting: " + key)
    defaults = {
        "api_version": "2026-03-01", "expected_extension_name": "CDELinux",
        "expected_extension_publisher": PUBLISHER, "expected_extension_type": "CDELinux",
        "allow_lifecycle_tests": False, "allow_fail_closed_tests": False,
        "allow_recovery_tests": False, "data_lun": 0, "lifecycle_test_size_mb": 16,
        "guest_command_retries": 6, "rbac_revocation_wait_seconds": 600,
        "rbac_restore_wait_seconds": 180, "failclosed_lun": 1, "failclosed_disk_size_gb": 4,
        "failclosed_mount_point": "/cdde-failclosed", "failclosed_detection_wait_seconds": 120,
    }
    for key, default in defaults.items():
        config.setdefault(key, default)
    for key in ("data_lun", "lifecycle_test_size_mb", "guest_command_retries",
                "rbac_revocation_wait_seconds", "rbac_restore_wait_seconds",
                "failclosed_lun", "failclosed_disk_size_gb", "failclosed_detection_wait_seconds"):
        value = config[key]
        if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
            raise RuntimeError(key + " must be a non-negative integer")
        config[key] = int(value)
        if not config[key] and key not in ("data_lun", "failclosed_lun"):
            raise RuntimeError(key + " must be greater than zero")
    for key in ("allow_lifecycle_tests", "allow_fail_closed_tests", "allow_recovery_tests"):
        if config[key] in ("true", "false"):
            config[key] = config[key] == "true"
        if not isinstance(config[key], bool):
            raise RuntimeError(key + " must be a boolean")
    if not safe_mount(config["mount_point"]):
        raise RuntimeError("Unsafe mount_point")
    if (not safe_mount(config["failclosed_mount_point"]) or
            config["failclosed_mount_point"] == config["mount_point"]):
        raise RuntimeError("failclosed_mount_point must be a dedicated safe absolute path")
    return config


class AzureEvidence:
    def __init__(self, settings, raw):
        self.settings = settings
        self.raw = Path(raw)
        self.raw.mkdir(parents=True, exist_ok=True)

    def collect(self, name, *args, subscription=True):
        command = ["az", *map(str, args)]
        if subscription:
            command += ["--subscription", self.settings["subscription_id"]]
        command += ["--output", "json"]
        completed = subprocess.run(command, text=True, capture_output=True)
        (self.raw / name).write_text(completed.stdout, encoding="utf-8")
        (self.raw / (name + ".stderr")).write_text(completed.stderr, encoding="utf-8")
        if completed.returncode:
            print(f"Azure CLI failed ({name}): {completed.stderr.strip()}", file=sys.stderr)
        return completed

    def fetch(self, name, *args, subscription=True):
        result = self.collect(name, *args, subscription=subscription)
        if result.returncode:
            return None
        try:
            return json.loads(result.stdout)
        except ValueError as error:
            print(f"Invalid Azure JSON ({name}): {error}", file=sys.stderr)
            return None

    def required(self, name, *args):
        result = self.fetch(name, *args)
        if result is None:
            raise RuntimeError("Azure operation failed; inspect " + str(self.raw / name))
        return result

    def vm_url(self, vm=None, group=None):
        c = self.settings
        return (f"https://management.azure.com/subscriptions/{c['subscription_id']}/resourceGroups/"
                f"{group or c['resource_group']}/providers/Microsoft.Compute/virtualMachines/"
                f"{vm or c['vm_name']}?api-version={c['api_version']}")

    def guest(self, name, script, retries=1):
        output = ""
        self.guest_succeeded = False
        for attempt in range(1, retries + 1):
            value = self.fetch(name + ".json", "vm", "run-command", "invoke",
                "--resource-group", self.settings["resource_group"], "--name", self.settings["vm_name"],
                "--command-id", "RunShellScript", "--scripts", script)
            entries = get(value, "value")
            if (not isinstance(entries, list) or any(not isinstance(item, dict) or
                    not isinstance(item.get("message", ""), str) for item in entries)):
                print("Invalid Run Command response shape: " + str(self.raw / (name + ".json")), file=sys.stderr)
                entries = []
            output = "\n".join(item.get("message", "") for item in entries)
            if any(lower(item.get("code")).endswith("/succeeded") for item in entries):
                self.guest_succeeded = True
                break
            if attempt < retries:
                time.sleep(15)
        (self.raw / (name + ".txt")).write_text(output, encoding="utf-8")
        (self.raw / (name + ".attempts")).write_text(str(attempt) + "\n", encoding="utf-8")
        return output


def vm_disks(vm):
    return get(vm, "properties.storageProfile.dataDisks", [])


def secure_vm(vm, size=None):
    properties = get(vm, "properties", {})
    identity = get(properties, "securityProfile.confidentialDataDiskEncryptionIdentity.userAssignedIdentityResourceId")
    attached = get(vm, "identity.userAssignedIdentities", {})
    return bool(identity and lower(identity) in {lower(key) for key in attached} and
        get(properties, "securityProfile.securityType") == "ConfidentialVM" and
        get(properties, "securityProfile.uefiSettings.secureBootEnabled") is True and
        get(properties, "securityProfile.uefiSettings.vTpmEnabled") is True and
        get(properties, "storageProfile.osDisk.managedDisk.securityProfile.securityEncryptionType") ==
            "DiskWithVMGuestState" and
        (size is None or get(properties, "hardwareProfile.vmSize") == size))


class Recovery(AzureEvidence):
    def __init__(self, bundle=None, config=None, output=None):
        if config:
            c = load_config(config)
            if not c["allow_recovery_tests"]:
                raise RuntimeError("Set allow_recovery_tests=true only for disposable resources")
            if not re.fullmatch(r"Standard_(DC|EC)\d+[a-z]*_v6", c.get("expected_vm_size", "")):
                raise RuntimeError("Recovery profile must target a confidential v6 size")
            self.bundle = Path(output) / timestamp(True)
            settings = {"subscription": c["subscription_id"], "resource_group": c["resource_group"],
                "vm_name": c["vm_name"], "api_version": c["api_version"], "mount_point": c["mount_point"],
                "des_name": c["des_name"], "token": self.bundle.name, "lun": c["data_lun"],
                "vm_size": c["expected_vm_size"]}
            write_json(self.bundle / "settings.json", settings)
        else:
            self.bundle = Path(bundle)
            settings = read_json(self.bundle / "settings.json")
            read_json(self.bundle / "manifest.json")
        if (not safe_mount(settings["mount_point"]) or
                not re.fullmatch(r"\d{8}T\d{6}(?:\d{1,9})?Z", settings["token"]) or
                isinstance(settings["lun"], bool) or not isinstance(settings["lun"], int) or settings["lun"] < 0):
            raise RuntimeError("Unsafe recovery bundle settings")
        self.bundle_settings = settings
        self.token = settings["token"]
        c = {"subscription_id": settings["subscription"], "resource_group": settings["resource_group"],
             "vm_name": settings["vm_name"], "api_version": settings["api_version"],
             "mount_point": settings["mount_point"], "data_lun": settings["lun"]}
        super().__init__(c, self.bundle / "raw")

    def probe(self, name, script):
        output = self.guest(name, script)
        if not self.guest_succeeded or "RECOVERY_PROBE=PASS" not in output.splitlines():
            failed = [line for line in output.splitlines() if line.startswith("RECOVERY_FAILED_STEP=")]
            raise RuntimeError(f"Recovery guest check failed ({name}): " +
                               ("; ".join(failed) or "missing authoritative result marker"))
        return output

    def storage_guard(self):
        c = self.settings
        return f"""set -eu
probe_step='data LUN discovery'
trap 'echo "RECOVERY_FAILED_STEP=$probe_step" >&2; echo RECOVERY_PROBE=ERROR' EXIT
mount_point={shlex.quote(c['mount_point'])}
target='/dev/disk/azure/scsi1/lun{c['data_lun']}'
test -b "$target"
probe_step='mounted data volume discovery'
source_device=$(findmnt -rn -o SOURCE --mountpoint "$mount_point")
source_device=$(readlink -f "$source_device")
probe_step='dm-crypt mapping'
test "$(lsblk -dn -o TYPE "$source_device")" = crypt
raw_device=$(readlink -f "$target")
probe_step='data LUN ancestry'
lsblk -srn -p -o NAME "$source_device" | grep -Fx "$raw_device" >/dev/null
probe_step='LUKS2 header'
cryptsetup luksDump "$target" | grep -Eq '^Version:[[:space:]]*2$'
dir="$mount_point/.cdde-recovery-{self.token}"
"""

    def prepare(self):
        vm = self.required("source-vm.json", "rest", "--method", "get", "--url", self.vm_url())
        disks = [disk for disk in vm_disks(vm) if disk.get("lun") == self.settings["data_lun"]]
        if (not secure_vm(vm, self.bundle_settings["vm_size"]) or len(disks) != 1 or
                get(disks[0], "managedDisk.securityProfile.securityEncryptionType") !=
                "DataDiskEncryptedWithCustomerKey"):
            raise RuntimeError("Source must be v6 with confidential OS and data disk encryption")
        script = self.storage_guard() + f"""
probe_step='synthetic dataset directory creation'
test ! -e "$dir"
mkdir -m 750 "$dir"
mkdir -m 700 "$dir/nested"
probe_step='synthetic dataset writes'
dd if=/dev/urandom of="$dir/random.bin" bs=1M count=4 conv=fsync 2>/dev/null
printf '%s\\n' '{self.token}' > "$dir/checkpoint.txt"
printf '%s\\n' 'CDDE recovery fixture' > "$dir/nested/permissions.txt"
chmod 640 "$dir/random.bin"
chmod 600 "$dir/checkpoint.txt" "$dir/nested/permissions.txt"
sync
cd "$dir"
probe_step='synthetic dataset manifest'
echo LUKS_UUID=$(cryptsetup luksUUID "$target")
for file in checkpoint.txt random.bin nested/permissions.txt; do
  hash=$(sha256sum "$file" | awk '{{print $1}}')
  metadata=$(stat -c '%a %u %g %s' "$file")
  printf 'FIXTURE=%s %s %s\\n' "$file" "$hash" "$metadata"
done
trap - EXIT
echo RECOVERY_PROBE=PASS
"""
        output = self.probe("prepare", script)
        fixtures = []
        luks_uuid = ""
        for line in output.splitlines():
            if line.startswith("LUKS_UUID="):
                luks_uuid = line.partition("=")[2]
            if line.startswith("FIXTURE="):
                fields = line.partition("=")[2].split()
                if len(fields) != 6:
                    raise RuntimeError("Incomplete fixture output")
                fixtures.append(dict(zip(("file", "sha256", "mode", "uid", "gid", "size"), fields)))
        manifest = {"prepared_utc": utc(), "source_vm_id": vm["id"],
            "source_disk_id": get(disks[0], "managedDisk.id"),
            "des_id": get(disks[0], "managedDisk.securityProfile.diskEncryptionSet.id"),
            "identity_id": get(vm, "properties.securityProfile.confidentialDataDiskEncryptionIdentity.userAssignedIdentityResourceId"),
            "location": vm["location"], "luks_uuid": luks_uuid, "fixtures": fixtures}
        self.validate_manifest(manifest)
        if not all(isinstance(manifest[key], str) and manifest[key] for key in
                   ("source_disk_id", "des_id", "identity_id")):
            raise RuntimeError("Incomplete source encryption metadata")
        write_json(self.bundle / "fixtures.json", fixtures)
        write_json(self.bundle / "manifest.json", manifest)
        hash_bundle(self.bundle)
        print("Prepared bundle:", self.bundle)
        print("Capture ALL selected recovery points before mutate. Preserve encryption assets.")

    @staticmethod
    def validate_manifest(manifest):
        fixtures = manifest.get("fixtures", [])
        if (not re.fullmatch(r"[0-9a-fA-F-]{36}", manifest.get("luks_uuid", "")) or
                len(fixtures) != 3 or {entry.get("file") for entry in fixtures} !=
                {"checkpoint.txt", "random.bin", "nested/permissions.txt"}):
            raise RuntimeError("Invalid dataset manifest")
        for entry in fixtures:
            if (not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")) or
                    any(not re.fullmatch(r"[0-9]+", str(entry.get(key, "")))
                        for key in ("mode", "uid", "gid", "size"))):
                raise RuntimeError("Invalid fixture hash or metadata")

    def fixture_script(self):
        manifest = read_json(self.bundle / "manifest.json")
        self.validate_manifest(manifest)
        script = self.storage_guard() + f"""
probe_step='recovered dataset directories and permissions'
test -d "$dir" && test ! -L "$dir"
test -d "$dir/nested" && test ! -L "$dir/nested"
test "$(stat -c '%a' "$dir")" = 750
test "$(stat -c '%a' "$dir/nested")" = 700
probe_step='original LUKS UUID'
test "$(cryptsetup luksUUID "$target")" = {shlex.quote(manifest['luks_uuid'])}
probe_step='point-in-time dataset'
test ! -e "$dir/after-capture.txt"
cd "$dir"
"""
        for entry in manifest["fixtures"]:
            file = shlex.quote(entry["file"])
            metadata = " ".join(str(entry[key]) for key in ("mode", "uid", "gid", "size"))
            script += f"""
probe_step={shlex.quote('fixture integrity: ' + entry['file'])}
test -f {file} && test ! -L {file}
test "$(sha256sum {file} | awk '{{print $1}}')" = {shlex.quote(entry['sha256'])}
test "$(stat -c '%a %u %g %s' {file})" = {shlex.quote(metadata)}
"""
        return script

    def check_source(self):
        self.probe("check-source", self.fixture_script() + "\ntrap - EXIT\necho RECOVERY_PROBE=PASS\n")
        hash_bundle(self.bundle)
        print("Original encrypted source dataset matches the prepared bundle.")

    def mutate(self):
        if (self.bundle / "mutated.json").exists():
            raise RuntimeError("Bundle already mutated")
        self.probe("mutate", self.storage_guard() + f"""
probe_step='recovered dataset directories and permissions'
test -d "$dir"
printf '%s\\n' 'AFTER-CAPTURE-{self.token}' > "$dir/checkpoint.txt"
printf '%s\\n' 'Must not appear in restored recovery point' > "$dir/after-capture.txt"
sync
trap - EXIT
echo RECOVERY_PROBE=PASS
""")
        write_json(self.bundle / "mutated.json", {"mutated_utc": utc()})
        # Restoring the OS can replay the active Run Command; retire the writer.
        try:
            self.probe("mutation-fence", "set -eu\necho RECOVERY_MUTATION_FENCE=PASS\necho RECOVERY_PROBE=PASS\n")
        except RuntimeError as error:
            raise RuntimeError("Source was mutated but Run Command fencing failed; do not restore this bundle") from error
        write_json(self.bundle / "mutation-fenced.json",
                   {"fenced_utc": utc(), "evidence": "raw/mutation-fence.json"})
        hash_bundle(self.bundle)
        print("Source changed. Restored data must match manifest and must not contain after-capture.txt.")

    def verify(self, case_file, checkpoint):
        case_file = Path(case_file)
        case = read_json(case_file)
        if (case.get("path") not in PATHS or case.get("target") not in ("original", "replacement") or
                case.get("support") not in ("confirmed", "exploratory", "blocked") or
                not isinstance(case.get("support_reference"), str) or not case["support_reference"] or
                checkpoint not in CHECKPOINTS):
            raise RuntimeError("Invalid recovery case or checkpoint")
        prefix = f"{case['path']}-{case['target']}-{checkpoint}-{timestamp(True)}"
        self.raw = self.bundle / "raw" / prefix
        self.raw.mkdir(parents=True)
        shutil.copyfile(case_file, self.raw / "case.json")
        status, message, code = "ERROR", "Verification did not complete", 2
        try:
            if case["support"] == "blocked":
                status, message, code = "BLOCKED", case["support_reference"], 3
                return code
            manifest = read_json(self.bundle / "manifest.json")
            mutation = read_json(self.bundle / "mutated.json")
            self.validate_manifest(manifest)
            for key in ("target_resource_group", "target_vm_name", "restored_disk_id", "capture_resource_id",
                        "restore_reference", "capture_completed_utc", "restore_completed_utc"):
                if not isinstance(case.get(key), str) or not case[key] or "<" in case[key]:
                    raise RuntimeError("Fill in all case parameters: " + key)
            if (not safe_mount(case.get("target_mount_point")) or
                    isinstance(case.get("target_lun"), bool) or
                    not isinstance(case.get("target_lun"), int) or case["target_lun"] < 0):
                raise RuntimeError("Invalid target mount or LUN")
            if not (instant(manifest["prepared_utc"]) <= instant(case["capture_completed_utc"]) <=
                    instant(mutation["mutated_utc"]) <= instant(case["restore_completed_utc"])):
                raise RuntimeError("Invalid capture/mutation/restore order")
            for kind in ("capture", "restore"):
                files = case.get(kind + "_evidence_files")
                if not isinstance(files, list) or not files:
                    raise RuntimeError("Missing exported " + kind + " evidence")
                for index, name in enumerate(files):
                    file = Path(name)
                    if not file.is_absolute():
                        file = case_file.parent / file
                    if not isinstance(read_json(file), (dict, list)):
                        raise RuntimeError("Evidence must be exported JSON: " + str(file))
                    shutil.copyfile(file, self.raw / f"{kind}-{index}.json")
            self.settings.update(resource_group=case["target_resource_group"], vm_name=case["target_vm_name"],
                                 mount_point=case["target_mount_point"], data_lun=case["target_lun"])
            vm = self.required("target-vm.json", "rest", "--method", "get", "--url", self.vm_url())
            disk = self.required("restored-disk.json", "disk", "show", "--ids", case["restored_disk_id"])
            original, restored = lower(manifest["source_disk_id"]), lower(case["restored_disk_id"])
            selected = [item for item in vm_disks(vm) if item.get("lun") == case["target_lun"]]
            identity = get(vm, "properties.securityProfile.confidentialDataDiskEncryptionIdentity.userAssignedIdentityResourceId")
            original_target = lower(vm["id"]) == lower(manifest["source_vm_id"])
            valid = (secure_vm(vm, self.bundle_settings.get("vm_size", "Standard_DC2ads_v6")) and
                     restored != original and original_target == (case["target"] == "original"))
            valid = valid and (
                get(vm, "properties.provisioningState") == "Succeeded" and
                lower(vm.get("location")) == lower(manifest["location"]) and
                lower(identity) == lower(manifest["identity_id"]) and
                all(lower(get(item, "managedDisk.id")) != original for item in vm_disks(vm)) and
                len(selected) == 1 and lower(get(selected[0], "managedDisk.id")) == restored and
                get(selected[0], "managedDisk.securityProfile.securityEncryptionType") ==
                    "DataDiskEncryptedWithCustomerKey" and
                lower(get(selected[0], "managedDisk.securityProfile.diskEncryptionSet.id")) ==
                    lower(manifest["des_id"]) and lower(disk.get("id")) == restored and
                disk.get("provisioningState") == "Succeeded" and disk.get("diskState") == "Attached")
            if not valid:
                status, message, code = "FAIL", "Restored VM/disk metadata, target identity, or source-disk independence failed", 1
                return code
            script = self.fixture_script() + f"""
probe_step='recovered-volume I/O'
test ! -e io-probe.txt
printf '%s\\n' '{self.token}' > io-probe.txt
sync
test "$(cat io-probe.txt)" = '{self.token}'
rm -- io-probe.txt
trap - EXIT
echo RECOVERY_PROBE=PASS
"""
            output = self.guest("verify", script)
            if self.guest_succeeded and "RECOVERY_PROBE=PASS" in output.splitlines():
                status, message, code = "PASS", (
                    "Metadata, source-disk independence, LUKS2/dm-crypt, recovery-point data, permissions and I/O verified"), 0
            elif self.guest_succeeded and "RECOVERY_PROBE=ERROR" in output.splitlines():
                status, message, code = "FAIL", (
                    "Guest encryption, LUN ancestry, point-in-time integrity, permissions or I/O check failed"), 1
            else:
                status, message, code = "ERROR", "Run Command failed or did not return the authoritative marker; inspect guest/agent evidence", 1
            return code
        except (RuntimeError, OSError, KeyError) as error:
            message = str(error)
            print("ERROR:", message, file=sys.stderr)
            return code
        finally:
            write_json(self.bundle / "cases" / (prefix + ".json"), {
                "path": case["path"], "target": case["target"], "checkpoint": checkpoint,
                "support": case["support"], "status": status, "message": message,
                "recorded_utc": utc(), "case_identity": digest(case_file), "evidence": "raw/" + prefix})
            hash_bundle(self.bundle)
            print(f"[{status}] {case['path']} / {case['target']} / {checkpoint}: {message}")

    def report(self):
        records = [read_json(file) for file in (self.bundle / "cases").glob("*.json")]
        cases = []
        for path in PATHS:
            for target in ("original", "replacement"):
                matches = sorted((record for record in records if record["path"] == path and
                                  record["target"] == target), key=lambda value: value["recorded_utc"])
                checks = [next((record for record in reversed(matches) if record["checkpoint"] == checkpoint),
                               {"checkpoint": checkpoint, "status": "NOT_EVALUATED"}) for checkpoint in CHECKPOINTS]
                if all(check["status"] == "PASS" for check in checks) and len({check.get("case_identity") for check in checks}) == 1:
                    status = "PASS"
                elif any(check["status"] == "FAIL" for check in checks):
                    status = "FAIL"
                elif matches and matches[-1]["status"] == "BLOCKED":
                    status = "BLOCKED"
                elif any(check["status"] == "ERROR" for check in checks):
                    status = "ERROR"
                else:
                    status = "NOT_EVALUATED"
                cases.append({"path": path, "target": target, "checkpoints": checks, "status": status})
        counts = {status: sum(case["status"] == status for case in cases) for status in
                  sorted({case["status"] for case in cases})}
        write_json(self.bundle / "report.json", {"scope": "Staged CDDE recovery verification; capture/restore jobs are operator-reviewed evidence",
                                                "cases": cases, "counts": counts})
        lines = ["# CDDE recovery validation", "",
                 "PASS requires all three checkpoints for the same restored resource and recovery point.",
                 "Backup/restore support and job success are not inferred from guest verification.", "",
                 "| Path | Target | Result | Support disposition |", "|---|---|---|---|"]
        for case in cases:
            support = ", ".join(sorted({check.get("support", "not evaluated") for check in case["checkpoints"]}))
            lines.append(f"| {case['path']} | {case['target']} | {case['status']} | {support} |")
        lines += [""] + [f"- {status}: {count}" for status, count in counts.items()]
        (self.bundle / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        hash_bundle(self.bundle)
        print("\n".join(lines))
        return 0 if counts.get("PASS") == 8 else 1


def guest_settings(config, **extra):
    values = {"target": f"/dev/disk/azure/scsi1/lun{config['data_lun']}",
              "mount_point": config["mount_point"], "lun": config["data_lun"], **extra}
    return "set -u\n" + "\n".join(key + "=" + shlex.quote(str(value))
                                  for key, value in values.items()) + "\n"


def inspection_script(config):
    return guest_settings(config) + r"""
echo '=== CDE_GUEST_BEGIN ==='
echo "TARGET=$target"
echo "MOUNT_POINT=$mount_point"
echo '=== LSBLK ==='
lsblk -o NAME,KNAME,TYPE,FSTYPE,MOUNTPOINTS,PKNAME
echo '=== CRYPTTAB ==='
cat /etc/crypttab 2>/dev/null || true
echo '=== DMSETUP ==='
dmsetup ls --tree 2>/dev/null || true
echo '=== LUKS ==='
cryptsetup luksDump "$target" 2>/dev/null | sed -n '1,20p' || true
echo '=== CDE LOG TAILS ==='
for log in /var/log/azure/Microsoft.Azure.Security.ConfidentialDiskEncryption.CDELinux/extension.log /var/log/azure/Microsoft.Azure.Security.ConfidentialDiskEncryption.CDELinux/CommandExecution.log /var/log/azure/Microsoft.Azure.Security.ConfidentialDiskEncryption.CDELinux/vns.log; do
  echo "--- $log ---"
  tail -n 20 "$log" 2>/dev/null || true
done
echo '=== HANDLER STATUS ==='
find /var/lib/waagent/Microsoft.Azure.Security.ConfidentialDiskEncryption.CDELinux-*/status -maxdepth 1 -type f -name '*.status' -print -exec cat {} \; 2>/dev/null || true
echo
echo '=== CDE_GUEST_RESULT ==='
test -b "$target" && echo 'TARGET_BLOCK_DEVICE=PASS' || echo 'TARGET_BLOCK_DEVICE=FAIL'
source_device=$(findmnt -n -o SOURCE --target "$mount_point" 2>/dev/null || true)
echo "MOUNT_SOURCE=$source_device"
test -n "$source_device" && echo 'MOUNTED=PASS' || echo 'MOUNTED=FAIL'
resolved_source=$(readlink -f "$source_device" 2>/dev/null || true)
source_type=$(lsblk -dn -o TYPE "$resolved_source" 2>/dev/null || true)
case "$source_type:$resolved_source" in
  crypt:*|*:/dev/mapper/*|*:/dev/dm-*) echo 'DM_CRYPT=PASS' ;;
  *) echo 'DM_CRYPT=FAIL' ;;
esac
cryptsetup luksDump "$target" 2>/dev/null | grep -Eq '^Version:[[:space:]]*2$' && echo 'LUKS2=PASS' || echo 'LUKS2=FAIL'
target_path=$(readlink -f "$target" 2>/dev/null || true)
lsblk -srn -p -o NAME "$resolved_source" 2>/dev/null | grep -Fx "$target_path" >/dev/null && echo 'TARGET_ANCESTOR=PASS' || echo 'TARGET_ANCESTOR=FAIL'
status_file=$(find /var/lib/waagent/Microsoft.Azure.Security.ConfidentialDiskEncryption.CDELinux-*/status -maxdepth 1 -type f -name '*.status' 2>/dev/null | sort | tail -n 1)
if test -n "$status_file" && grep -Eq "\"name\"[[:space:]]*:[[:space:]]*\"LUN $lun\"" "$status_file" && grep -Fq "($mount_point) (encrypted)" "$status_file"; then
  echo 'HANDLER_LUN_STATUS=PASS'
else
  echo 'HANDLER_LUN_STATUS=FAIL'
fi
echo '=== CDE_GUEST_END ==='
"""


def integrity_script(config, file, expected, marker, require_luks=False):
    return guest_settings(config, test_file=file, expected_hash=expected, marker=marker,
                          require_luks="true" if require_luks else "false") + r"""
source_device=$(findmnt -n -o SOURCE --target "$mount_point" 2>/dev/null || true)
resolved_source=$(readlink -f "$source_device" 2>/dev/null || true)
source_type=$(lsblk -dn -o TYPE "$resolved_source" 2>/dev/null || true)
actual_hash=$(sha256sum "$test_file" 2>/dev/null | awk '{print $1}' || true)
luks2=false
cryptsetup luksDump "$target" 2>/dev/null | grep -Eq '^Version:[[:space:]]*2$' && luks2=true
if test -b "$target" && test -n "$source_device" && test "$source_type" = crypt && test -n "$expected_hash" && test "$actual_hash" = "$expected_hash" && { test "$require_luks" = false || test "$luks2" = true; }; then
  echo "$marker=PASS"
else
  echo "MOUNT_SOURCE=$source_device"
  echo "SOURCE_TYPE=$source_type"
  echo "LUKS2=$luks2"
  echo "EXPECTED_HASH=$expected_hash"
  echo "ACTUAL_HASH=$actual_hash"
  echo "$marker=FAIL"
fi
"""


class Conformance(AzureEvidence):
    def __init__(self, config, output, lifecycle=False, fail_closed=False):
        c = load_config(config)
        if lifecycle and not c["allow_lifecycle_tests"]:
            raise RuntimeError("Lifecycle mode requires allow_lifecycle_tests=true")
        if fail_closed and not c["allow_fail_closed_tests"]:
            raise RuntimeError("Fail-closed mode requires allow_fail_closed_tests=true")
        self.directory = Path(output) / timestamp(True)
        super().__init__(c, self.directory / "raw")
        self.lifecycle, self.fail_closed = lifecycle, fail_closed
        self.results = []

    def record(self, id, name, status, message, evidence=""):
        self.results.append({"id": id, "name": name, "status": status,
                             "message": message, "evidence": evidence})
        print(f"[{status}] {id:12s} {name}", flush=True)

    def assertion(self, id, name, file, value, valid, failure):
        self.record(id, name, "ERROR" if value is None else "PASS" if valid else "FAIL",
                    "Azure evidence was unavailable or invalid; inspect its stderr." if value is None else
                    "Expected Azure configuration is present." if valid else failure, "raw/" + file)

    def marker(self, id, name, file, output, marker, failure):
        lines = output.splitlines()
        status = ("ERROR" if not self.guest_succeeded else "PASS" if marker + "=PASS" in lines
                  else "FAIL" if marker + "=FAIL" in lines else "ERROR")
        self.record(id, name, status, "Expected guest result was observed." if status == "PASS" else
                    failure if status == "FAIL" else "Guest command did not return the expected result marker.",
                    "raw/" + file + ".txt")

    def probe(self, name, script):
        return self.guest(name, script, self.settings["guest_command_retries"])

    def action(self, name, *args):
        return self.collect(name, *args).returncode == 0

    def vm_action(self, file, verb):
        c = self.settings
        return self.action(file, "vm", verb, "-g", c["resource_group"], "-n", c["vm_name"])

    def reapply_extension(self, file):
        c = self.settings
        return self.action(file, "vm", "extension", "set", "-g", c["resource_group"],
            "--vm-name", c["vm_name"], "--publisher", c["expected_extension_publisher"],
            "--name", c["expected_extension_name"], "--version", "1.0",
            "--settings", json.dumps({"sequenceVersion": str(uuid.uuid4())}))

    def baseline(self):
        c = self.settings
        account = self.fetch("account.json", "account", "show", subscription=False)
        self.assertion("PRE-001", "Azure CLI authentication", "account.json", account,
            get(account, "id") == c["subscription_id"], "The active Azure CLI subscription does not match subscription_id.")
        feature = self.fetch("feature.json", "feature", "show", "--namespace", "Microsoft.Compute",
                             "--name", "ConfidentialVMDataDiskEncryptionPreview")
        self.assertion("PRE-002", "CDE preview feature registration", "feature.json", feature,
            get(feature, "properties.state") == "Registered", "The CDDE preview feature is not Registered.")
        for provider in ("Microsoft.Compute", "Microsoft.KeyVault", "Microsoft.ManagedIdentity"):
            suffix = provider.split(".")[-1]
            file = "provider-" + suffix + ".json"
            value = self.fetch(file, "provider", "show", "--namespace", provider)
            self.assertion("PRE-RP-" + suffix, provider + " resource provider", file, value,
                get(value, "registrationState") == "Registered", provider + " is not registered.")
        self.vm = vm = self.fetch("vm.json", "rest", "--method", "get", "--url", self.vm_url())
        checks = [
            ("VM-001", "Confidential VM security type", get(vm, "properties.securityProfile.securityType") == "ConfidentialVM",
             "VM securityType is not ConfidentialVM."),
            ("VM-002", "Secure Boot and vTPM", get(vm, "properties.securityProfile.uefiSettings.secureBootEnabled") is True and
             get(vm, "properties.securityProfile.uefiSettings.vTpmEnabled") is True, "Secure Boot and vTPM must both be enabled."),
            ("VM-003", "Confidential OS disk encryption",
             get(vm, "properties.storageProfile.osDisk.managedDisk.securityProfile.securityEncryptionType") == "DiskWithVMGuestState",
             "The OS disk does not use DiskWithVMGuestState."),
            ("VM-004", "Expected VM location and size",
             (not c.get("expected_location") or lower(get(vm, "location")) == lower(c["expected_location"])) and
             (not c.get("expected_vm_size") or get(vm, "properties.hardwareProfile.vmSize") == c["expected_vm_size"]),
             "The VM location or size does not match the configured expected value.")]
        for id, name, valid, failure in checks:
            self.assertion(id, name, "vm.json", vm, valid, failure)
        identity = self.fetch("identity.json", "identity", "show", "-g", c["resource_group"], "-n", c["identity_name"])
        self.principal = get(identity, "principalId", "")
        identity_id = get(identity, "id", "")
        self.assertion("IDENT-001", "CDDE user-assigned identity", "identity.json",
            identity if identity_id else None,
            (not c.get("expected_uami_id") or lower(identity_id) == lower(c["expected_uami_id"])) and
            (not c.get("expected_uami_principal_id") or self.principal == c["expected_uami_principal_id"]),
            "The managed identity resource ID or principal ID does not match the expected value.")
        self.assertion("VM-005", "VM CDDE identity assignment", "vm.json", vm,
            bool(identity_id) and lower(get(vm, "properties.securityProfile.confidentialDataDiskEncryptionIdentity.userAssignedIdentityResourceId")) ==
                lower(identity_id) and lower(identity_id) in {lower(key) for key in get(vm, "identity.userAssignedIdentities", {})},
            "The CDDE identity field and attached VM identity must both reference identity_name.")
        vault = self.fetch("vault.json", "keyvault", "show", "-g", c["resource_group"], "-n", c["vault_name"])
        self.vault_id = get(vault, "id", "")
        self.assertion("VAULT-001", "Expected Key Vault", "vault.json", vault,
            (not c.get("expected_vault_id") or lower(self.vault_id) == lower(c["expected_vault_id"])) and
            get(vault, "properties.enableRbacAuthorization") is True and
            get(vault, "properties.enablePurgeProtection") is True and get(vault, "properties.sku.name") == "premium",
            "The Key Vault ID, Premium SKU, RBAC authorization, or purge protection is invalid.")
        des = self.fetch("des.json", "disk-encryption-set", "show", "-g", c["resource_group"], "-n", c["des_name"])
        self.des_id = get(des, "id", "")
        des_principal = get(des, "identity.principalId", "")
        self.assertion("DES-001", "Confidential disk encryption set", "des.json", des,
            get(des, "encryptionType") == "ConfidentialVmEncryptedWithCustomerKey" and
            bool(get(des, "activeKey.keyUrl")) and lower(get(des, "provisioningState")) == "succeeded" and bool(des_principal),
            "DES encryptionType or active key URL is invalid.")
        disks = [item for item in vm_disks(vm) if item.get("lun") == c["data_lun"]]
        self.assertion("DISK-001", "CDE data disk metadata", "vm.json", vm if self.des_id else None,
            len(disks) == 1 and get(disks[0], "managedDisk.securityProfile.securityEncryptionType") ==
            "DataDiskEncryptedWithCustomerKey" and
            lower(get(disks[0], "managedDisk.securityProfile.diskEncryptionSet.id")) == lower(self.des_id),
            "The selected LUN is not DataDiskEncryptedWithCustomerKey with the configured DES.")
        disk_id = get(disks[0], "managedDisk.id") if len(disks) == 1 else None
        disk = self.fetch("disk.json", "disk", "show", "--ids", disk_id) if disk_id else None
        self.assertion("DISK-002", "Managed disk operational state", "disk.json", disk,
            lower(get(disk, "provisioningState")) == "succeeded" and
            lower(get(disk, "location")) == lower(get(vm, "location")),
            "The managed disk is not provisioned successfully in the VM location.")
        key = self.fetch("key.json", "keyvault", "key", "show", "--vault-name", c["vault_name"], "--name", c["key_name"])
        ops = get(key, "key.keyOps", [])
        self.assertion("KEY-001", "Secure Key Release key", "key.json", key,
            get(key, "key.kty") == "RSA-HSM" and len(get(key, "key.n", "")) == 512 and
            get(key, "attributes.exportable") is True and bool(get(key, "releasePolicy.encodedPolicy")) and
            "wrapKey" in ops and "unwrapKey" in ops,
            "Key must be exportable RSA-HSM 3072 with wrapKey, unwrapKey, and a release policy.")
        now = dt.datetime.now(dt.timezone.utc)
        active = get(key, "attributes.enabled") is True
        for attr, future in (("expires", True), ("notBefore", False)):
            date = get(key, "attributes." + attr)
            if date is not None:
                try:
                    active &= instant(date) > now if future else instant(date) <= now
                except RuntimeError as error:
                    print(str(error), file=sys.stderr)
                    active = False
        self.assertion("KEY-002", "Key operational state", "key.json", key, active,
            "The CDDE key is disabled, expired, not yet valid, or has invalid validity dates.")
        self.assertion("DES-002", "DES active key version", "des.json", des,
            bool(get(key, "key.kid")) and lower(get(des, "activeKey.keyUrl")) == lower(get(key, "key.kid")),
            "The DES active key URL does not match the configured Key Vault key version.")
        self.roles = []
        if not all((self.vault_id, des_principal, self.principal)):
            for id, name in (("RBAC-001", "DES Key Vault role"), ("RBAC-002", "VM identity Key Vault roles")):
                self.record(id, name, "ERROR", "Unable to resolve vault or identity principals for RBAC validation.")
        else:
            des_roles = self.fetch("des-rbac.json", "role", "assignment", "list", "--assignee", des_principal,
                                   "--scope", self.vault_id, "--include-inherited")
            self.assertion("RBAC-001", "DES Key Vault role", "des-rbac.json", des_roles,
                any(item.get("roleDefinitionName") == "Key Vault Crypto Service Encryption User" for item in des_roles or []),
                "The DES identity lacks Key Vault Crypto Service Encryption User.")
            roles = self.fetch("uami-rbac.json", "role", "assignment", "list", "--assignee", self.principal,
                               "--scope", self.vault_id, "--include-inherited")
            self.roles = roles or []
            names = {item.get("roleDefinitionName") for item in self.roles}
            self.assertion("RBAC-002", "VM identity Key Vault roles", "uami-rbac.json", roles,
                "Key Vault Crypto Service Encryption User" in names and bool(names &
                    {"Key Vault Crypto Service Release User", "Key Vault Crypto Officer"}),
                "The VM identity lacks the required Key Vault encryption or key-release role.")
        extension = self.fetch("extension.json", "vm", "extension", "show", "-g", c["resource_group"],
            "--vm-name", c["vm_name"], "--name", c["expected_extension_name"], "--expand", "instanceView")
        self.assertion("EXT-001", "CDE extension configuration", "extension.json", extension,
            extension_configuration_valid(extension, c),
            "The CDE extension publisher, type, or sequenceVersion is invalid.")
        self.assertion("EXT-002", "CDE extension provisioning", "extension.json", extension,
            extension_health(extension) == "succeeded",
            "The CDE extension or its instance view does not report success.")
        output = self.probe("guest-run-command", inspection_script(c))
        (self.raw / "guest-inspection.txt").write_text(output, encoding="utf-8")
        complete = self.guest_succeeded and "=== CDE_GUEST_RESULT ===" in output and "=== CDE_GUEST_END ===" in output
        for index, (name, marker, failure) in enumerate((
            ("Expected LUN is a block device", "TARGET_BLOCK_DEVICE", "The configured Azure LUN was not found."),
            ("Data volume is mounted", "MOUNTED", "The configured mount point is not mounted."),
            ("Data volume uses dm-crypt", "DM_CRYPT", "The mount source is not a dm-crypt device."),
            ("Data disk uses LUKS2", "LUKS2", "The configured LUN has no valid LUKS2 header."),
            ("Mount maps to expected LUN", "TARGET_ANCESTOR", "The encrypted mount does not map to the configured LUN."),
            ("Extension reports LUN encrypted", "HANDLER_LUN_STATUS", "The handler does not report the LUN encrypted.")), 1):
            id = f"GUEST-{index:03d}"
            if complete:
                self.marker(id, name, "guest-inspection", output, marker, failure)
            else:
                self.record(id, name, "ERROR", "Guest inspection did not complete; inspect Run Command evidence.",
                            "raw/guest-inspection.txt")

    def run_lifecycle(self):
        c = self.settings
        file = c["mount_point"] + "/.cdde-lifecycle-" + self.directory.name + ".bin"
        output = self.probe("lifecycle-setup", guest_settings(c, test_file=file, size=c["lifecycle_test_size_mb"]) + r"""
if findmnt -n --mountpoint "$mount_point" >/dev/null 2>&1; then
  if dd if=/dev/urandom of="$test_file" bs=1M count="$size" conv=fsync 2>/dev/null; then
    hash=$(sha256sum "$test_file" | awk '{print $1}')
    echo "LIFECYCLE_FILE=$test_file"
    echo "LIFECYCLE_HASH=$hash"
    echo 'LIFECYCLE_SETUP=PASS'
  else
    echo 'LIFECYCLE_SETUP=FAIL'
  fi
else
  echo 'LIFECYCLE_SETUP=FAIL'
fi
""")
        expected = next((line.partition("=")[2] for line in reversed(output.splitlines())
                         if line.startswith("LIFECYCLE_HASH=")), "")
        self.marker("LIFE-001", "Create synthetic integrity data", "lifecycle-setup", output,
                    "LIFECYCLE_SETUP", "Unable to create and sync the synthetic lifecycle test file.")
        names = ("Integrity after VM restart", "Integrity after deallocate and start",
                 "Integrity after extension reapplication", "Remove synthetic integrity data")
        if (not self.guest_succeeded or "LIFECYCLE_SETUP=PASS" not in output.splitlines() or
                not re.fullmatch(r"[0-9a-f]{64}", expected)):
            for index, name in enumerate(names, 2):
                self.record(f"LIFE-{index:03d}", name, "ERROR", "Lifecycle setup produced no valid data hash; operation skipped.",
                            "raw/lifecycle-setup.txt")
            return
        try:
            operations = (
                ("lifecycle-after-restart", lambda: self.vm_action("lifecycle-restart.json", "restart")),
                ("lifecycle-after-deallocate", lambda: self.vm_action("lifecycle-deallocate.json", "deallocate") and
                 self.vm_action("lifecycle-start.json", "start")),
                ("lifecycle-after-extension", lambda: self.reapply_extension("lifecycle-extension-reapply.json")))
            for index, (label, action) in enumerate(operations, 2):
                if not action():
                    self.record(f"LIFE-{index:03d}", names[index - 2], "ERROR",
                                "Lifecycle Azure operation failed; inspect raw stderr.", "raw/" + label + ".txt")
                    continue
                output = self.probe(label, integrity_script(c, file, expected, "LIFECYCLE_VERIFY"))
                self.marker(f"LIFE-{index:03d}", names[index - 2], label, output, "LIFECYCLE_VERIFY",
                            "The encrypted mount or synthetic hash did not survive the lifecycle operation.")
        finally:
            output = self.probe("lifecycle-cleanup", guest_settings(c, test_file=file) + r"""
if rm -f "$test_file" && test ! -e "$test_file"; then
  echo LIFECYCLE_CLEANUP=PASS
else
  echo LIFECYCLE_CLEANUP=FAIL
fi
""")
            self.marker("LIFE-005", names[-1], "lifecycle-cleanup", output, "LIFECYCLE_CLEANUP",
                        "Unable to remove the synthetic lifecycle test file.")

    def restore_release_role(self, assignment):
        if not self.role_removed:
            return True
        c = self.settings
        for attempt in range(1, c["guest_command_retries"] + 1):
            restored = self.action("failclosed-role-restore.json", "role", "assignment", "create",
                "--name", assignment["name"], "--assignee-object-id", self.principal,
                "--assignee-principal-type", "ServicePrincipal", "--role", assignment["roleDefinitionId"],
                "--scope", self.vault_id)
            if not restored:
                roles = self.fetch("failclosed-role-restore-check.json", "role", "assignment", "list",
                    "--assignee", self.principal, "--scope", self.vault_id, "--include-inherited")
                restored = any(lower(item.get("id")) == lower(assignment["id"]) and
                    item.get("principalId") == self.principal and lower(item.get("scope")) == lower(self.vault_id) and
                    lower(item.get("roleDefinitionId")) == lower(assignment["roleDefinitionId"]) and
                    item.get("condition") is None for item in roles or [])
            if restored:
                self.role_removed = False
                (self.raw / "failclosed-role-restore.attempts").write_text(str(attempt) + "\n")
                return True
            if attempt < c["guest_command_retries"]:
                time.sleep(15)
        print("CRITICAL: Failed to restore the Key Vault release role; manual recovery is required.", file=sys.stderr)
        return False

    def cleanup_failclosed(self, disk_id, disk_name):
        c = self.settings
        vm = self.fetch("failclosed-vm-before-cleanup.json", "rest", "--method", "get", "--url", self.vm_url())
        if vm is None:
            return False
        matches = [disk for disk in vm_disks(vm) if lower(get(disk, "managedDisk.id")) == lower(disk_id)]
        if matches:
            output = self.probe("failclosed-guest-cleanup",
                guest_settings(c, mount_point=c["failclosed_mount_point"]) + r"""
systemctl start azure-cde-mount-monitor.service 2>/dev/null || true
if findmnt -n --mountpoint "$mount_point" >/dev/null 2>&1; then
  umount "$mount_point" || { echo GUEST_CLEANUP=FAIL; exit 1; }
fi
if test -d "$mount_point"; then
  rmdir "$mount_point" || { echo GUEST_CLEANUP=FAIL; exit 1; }
fi
echo GUEST_CLEANUP=PASS
""")
            if not self.guest_succeeded or "GUEST_CLEANUP=PASS" not in output.splitlines():
                return False
            if not self.vm_action("failclosed-cleanup-deallocate.json", "deallocate"):
                return False
            detached = self.action("failclosed-disk-detach.json", "vm", "disk", "detach",
                                  "-g", c["resource_group"], "--vm-name", c["vm_name"], "--name", disk_name)
            started = self.vm_action("failclosed-cleanup-start.json", "start")
            if not detached or not started:
                return False
            output = self.probe("failclosed-post-cleanup", guest_settings(c) + r"""
source_device=$(findmnt -rn -o SOURCE --mountpoint "$mount_point" 2>/dev/null || true)
source_type=$(lsblk -dn -o TYPE "$(readlink -f "$source_device")" 2>/dev/null || true)
if test -b "$target" && test "$source_type" = crypt; then
  echo ORIGINAL_DISK_HEALTHY=PASS
else
  echo ORIGINAL_DISK_HEALTHY=FAIL
fi
""")
            if not self.guest_succeeded or "ORIGINAL_DISK_HEALTHY=PASS" not in output.splitlines():
                return False
        result = self.collect("failclosed-disk-before-delete.json", "disk", "show", "--ids", disk_id)
        if result.returncode:
            return bool(re.search(r"ResourceNotFound|DiskNotFound|\(NotFound\)", result.stderr))
        disk = read_json(self.raw / "failclosed-disk-before-delete.json")
        if lower(disk.get("id")) != lower(disk_id) or disk.get("managedBy") or disk.get("managedByExtended"):
            print("CRITICAL: Temporary disk is still attached or its identity does not match; deletion refused.", file=sys.stderr)
            return False
        return self.action("failclosed-disk-delete.json", "disk", "delete", "--ids", disk_id, "--yes")

    def run_failclosed(self):
        c = self.settings
        names = ("Attach temporary CDDE disk", "Remove direct release role",
                 "Deny first-time encryption without release role", "Restore direct release role",
                 "Encrypt temporary disk after recovery", "Delete temporary CDDE disk")
        release = [item for item in self.roles if item.get("principalId") == self.principal and
                   item.get("roleDefinitionName") == "Key Vault Crypto Service Release User" and
                   lower(item.get("scope")) == lower(self.vault_id) and item.get("condition") is None]
        capable = [item for item in self.roles if item.get("roleDefinitionName") in
                   ("Key Vault Crypto Service Release User", "Key Vault Crypto Officer", "Key Vault Administrator")]
        write_json(self.raw / "failclosed-release-assignment.json", release)
        occupied = any(disk.get("lun") == c["failclosed_lun"] for disk in vm_disks(self.vm))
        safe = (len(release) == 1 and len(capable) == 1 and all(release[0].get(key) for key in
                ("id", "name", "roleDefinitionId")) and self.vm is not None and bool(self.des_id))
        if not safe or occupied:
            for index, name in enumerate(names, 1):
                status = "PASS" if index == 6 or (occupied and index == 4) else "ERROR"
                self.record(f"FC-{index:03d}", name, status,
                    "No temporary disk was created or release role removed." if status == "PASS" else
                    "Temporary LUN is occupied." if occupied else "Safe release-role precondition failed.",
                    "raw/failclosed-release-assignment.json")
            return
        assignment = release[0]
        disk_name = "cdde-failclosed-" + timestamp(True).lower()
        disk_id = (f"/subscriptions/{c['subscription_id']}/resourceGroups/{c['resource_group']}"
                   "/providers/Microsoft.Compute/disks/" + disk_name)
        test_file = c["failclosed_mount_point"] + "/.cdde-skr-denial.bin"
        temporary = {**c, "data_lun": c["failclosed_lun"], "mount_point": c["failclosed_mount_point"]}
        self.role_removed = False
        attempted, expected, workflow_complete = False, "", False
        try:
            fields = ("name", "lun", "caching", "createOption", "deleteOption", "diskSizeGB")
            disks = [{**{key: item[key] for key in fields if key in item},
                      "managedDisk": copy.deepcopy(item["managedDisk"])} for item in vm_disks(self.vm)]
            disks.append({"name": disk_name, "lun": c["failclosed_lun"], "createOption": "Empty",
                "deleteOption": "Detach", "diskSizeGB": c["failclosed_disk_size_gb"],
                "managedDisk": {"storageAccountType": "Premium_LRS", "securityProfile": {
                    "securityEncryptionType": "DataDiskEncryptedWithCustomerKey", "diskEncryptionSet": {"id": self.des_id}}}})
            body = self.raw / "failclosed-disk-attach-body.json"
            write_json(body, {"properties": {"storageProfile": {"dataDisks": disks}}})
            attempted = True
            attached = self.action("failclosed-disk-attach.json", "rest", "--method", "patch", "--headers",
                                  "Content-Type=application/json", "--url", self.vm_url(), "--body", "@" + str(body))
            ready = attached and self.action("failclosed-disk-attach-wait.json", "vm", "wait",
                "-g", c["resource_group"], "-n", c["vm_name"], "--updated", "--interval", "5", "--timeout", "300")
            vm = self.fetch("failclosed-vm-after-attach.json", "rest", "--method", "get", "--url", self.vm_url()) if ready else None
            disk = self.fetch("failclosed-disk-after-attach.json", "disk", "show", "--ids", disk_id) if ready else None
            matches = [item for item in vm_disks(vm) if item.get("lun") == c["failclosed_lun"] and
                       lower(get(item, "managedDisk.id")) == lower(disk_id)]
            ready = (ready and len(matches) == 1 and lower(get(disk, "id")) == lower(disk_id) and
                     lower(get(disk, "provisioningState")) == "succeeded" and lower(get(disk, "diskState")) == "attached")
            self.record("FC-001", names[0], "PASS" if ready else "ERROR",
                "A temporary unformatted CDDE-marked disk was attached." if ready else
                "The temporary CDDE disk attachment did not reach a verified ready state.", "raw/failclosed-vm-after-attach.json")
            deleted = False
            if ready:
                # Restore even if the delete response is lost after Azure applies it.
                self.role_removed = True
                deleted = self.action("failclosed-role-delete.json", "role", "assignment", "delete", "--ids", assignment["id"])
            self.record("FC-002", names[1], "PASS" if deleted else "ERROR",
                        "The exact direct release-role assignment was removed." if deleted else
                        "Disk attachment or release-role deletion failed.", "raw/failclosed-role-delete.json")
            if deleted:
                (self.raw / "failclosed-role-deleted-at.txt").write_text(utc() + "\n")
                time.sleep(c["rbac_revocation_wait_seconds"])
                (self.raw / "failclosed-denial-started-at.txt").write_text(utc() + "\n")
                output = self.probe("failclosed-denial-trigger",
                    guest_settings(temporary, test_file=test_file, size=c["lifecycle_test_size_mb"]) + r"""
set -e
test -b "$target"
systemctl stop azure-cde-mount-monitor.service 2>/dev/null || true
mkfs.ext4 -F "$target" >/dev/null 2>&1
mkdir -p "$mount_point"
mount "$target" "$mount_point"
dd if=/dev/urandom of="$test_file" bs=1M count="$size" conv=fsync 2>/dev/null
sync
hash=$(sha256sum "$test_file" | awk '{print $1}')
denial_guest_time=$(date -u +%Y-%m-%dT%H:%M:%S)
systemctl start azure-cde-mount-monitor.service 2>/dev/null || true
echo "FAILCLOSED_HASH=$hash"
echo "DENIAL_GUEST_TIME=$denial_guest_time"
echo DENIAL_SETUP=PASS
""")
                values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
                expected, cutoff = values.get("FAILCLOSED_HASH", ""), values.get("DENIAL_GUEST_TIME", "")
                setup = (self.guest_succeeded and values.get("DENIAL_SETUP") == "PASS" and re.fullmatch(r"[0-9a-f]{64}", expected)
                         and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", cutoff))
                if setup:
                    time.sleep(c["failclosed_detection_wait_seconds"])
                    output = self.probe("failclosed-denial", guest_settings(temporary, cutoff=cutoff) + r"""
source_device=$(findmnt -n -o SOURCE --target "$mount_point" 2>/dev/null || true)
source_type=$(lsblk -dn -o TYPE "$(readlink -f "$source_device")" 2>/dev/null || true)
luks2=false
cryptsetup luksDump "$target" 2>/dev/null | grep -Eq '^Version:[[:space:]]*2$' && luks2=true
diagnostics=$(awk -v cutoff="$cutoff" '$1 >= cutoff' /var/log/azure/Microsoft.Azure.Security.ConfidentialDiskEncryption.CDELinux/*.log 2>/dev/null |
  grep -Ehi 'release.*denied|AzureAttestSKR.*(exit code[ :]*4|failed|error|denied)|CDE800|failed to retrieve key|authorization.*(failed|denied)' |
  tail -n 40 || true)
echo "MOUNT_SOURCE=$source_device"
echo "SOURCE_TYPE=$source_type"
echo "LUKS2=$luks2"
echo '=== SKR DIAGNOSTICS ==='
printf '%s\n' "$diagnostics"
if test -n "$cutoff" && test "$source_type" != crypt && test -n "$diagnostics"; then
  echo SKR_DENIAL=PASS
else
  echo SKR_DENIAL=FAIL
fi
""")
                    self.marker("FC-003", names[2], "failclosed-denial", output, "SKR_DENIAL",
                                "The temporary disk encrypted or explicit SKR denial diagnostics were absent.")
                else:
                    expected = ""
                    self.record("FC-003", names[2], "ERROR", "Denial setup did not produce a valid hash/time; validation skipped.",
                                "raw/failclosed-denial-trigger.txt")
            else:
                self.record("FC-003", names[2], "ERROR", "The release role was not removed.", "raw/failclosed-role-delete.json")
            workflow_complete = True
        finally:
            previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
            try:
                restored = self.restore_release_role(assignment)
                self.record("FC-004", names[3], "PASS" if restored else "ERROR",
                    "The original release-role assignment is restored or was never removed." if restored else
                    "CRITICAL: Role restoration failed; manual recovery is required.", "raw/failclosed-role-restore.json")
                if restored and expected and workflow_complete:
                    (self.raw / "failclosed-role-restored-at.txt").write_text(utc() + "\n")
                    time.sleep(c["rbac_restore_wait_seconds"])
                    output = self.probe("failclosed-recovery-mount", guest_settings(temporary) + r"""
mkdir -p "$mount_point"
if ! findmnt -n --mountpoint "$mount_point" >/dev/null 2>&1; then
  mount "$target" "$mount_point"
fi
findmnt -n --mountpoint "$mount_point" >/dev/null 2>&1 && echo RECOVERY_MOUNT=PASS || echo RECOVERY_MOUNT=FAIL
""")
                    reapplied = (self.guest_succeeded and "RECOVERY_MOUNT=PASS" in output.splitlines() and
                                 self.reapply_extension("failclosed-extension-recovery.json"))
                    if reapplied:
                        output = self.probe("failclosed-recovery",
                            integrity_script(temporary, test_file, expected, "FAILCLOSED_RECOVERY", True))
                        self.marker("FC-005", names[4], "failclosed-recovery", output, "FAILCLOSED_RECOVERY",
                                    "The temporary encrypted volume did not recover its original data hash.")
                    else:
                        self.record("FC-005", names[4], "ERROR", "Recovery mount or extension operation failed.",
                                    "raw/failclosed-recovery-mount.txt")
                else:
                    self.record("FC-005", names[4], "ERROR", "Recovery prerequisites failed or validation was interrupted.",
                                "raw/failclosed-role-restore.json")
            finally:
                try:
                    cleaned = not attempted or self.cleanup_failclosed(disk_id, disk_name)
                    self.record("FC-006", names[5], "PASS" if cleaned else "ERROR",
                        "Temporary disk removed and original source health verified." if cleaned else
                        "CRITICAL: Temporary disk cleanup failed; manual cleanup is required.", "raw/failclosed-disk-delete.json")
                    if not cleaned:
                        print("CRITICAL: Temporary disk cleanup failed; inspect retained evidence.", file=sys.stderr)
                finally:
                    for sig, handler in previous.items():
                        signal.signal(sig, handler)

    def save_report(self):
        counts = {status: sum(result["status"] == status for result in self.results) for status in ("PASS", "FAIL", "ERROR")}
        c = self.settings
        write_json(self.directory / "report.json", {"schemaVersion": "1.0", "generatedAt": utc(),
            "target": {"subscriptionId": c["subscription_id"], "resourceGroup": c["resource_group"], "vmName": c["vm_name"]},
            "mode": {"lifecycle": self.lifecycle, "failClosed": self.fail_closed},
            "summary": {"passed": counts["PASS"], "failed": counts["FAIL"], "errors": counts["ERROR"], "total": len(self.results)},
            "tests": self.results})
        suite = ET.Element("testsuite", name="Azure CDDE validation", tests=str(len(self.results)),
                           failures=str(counts["FAIL"]), errors=str(counts["ERROR"]))
        for result in self.results:
            case = ET.SubElement(suite, "testcase", classname="Azure.CDDE", name=result["id"] + " - " + result["name"])
            if result["status"] != "PASS":
                ET.SubElement(case, "failure" if result["status"] == "FAIL" else "error", message=result["message"])
            ET.SubElement(case, "system-out").text = "Evidence: " + result["evidence"]
        ET.ElementTree(suite).write(self.directory / "junit.xml", encoding="utf-8", xml_declaration=True)
        lines = ["# Azure CDDE validation evidence", "", "- Generated (UTC): " + utc(),
                 f"- Subscription: `{c['subscription_id']}`", f"- Resource group: `{c['resource_group']}`",
                 f"- VM: `{c['vm_name']}`", f"- Lifecycle mode: `{self.lifecycle}`", f"- Fail-closed mode: `{self.fail_closed}`",
                 f"- Result: **{counts['PASS']} passed, {counts['FAIL']} failed, {counts['ERROR']} errors**", "",
                 "| ID | Status | Test | Evidence |", "|---|---|---|---|"]
        lines += [f"| {result['id']} | {result['status']} | {result['name']} | {result['evidence']} |" for result in self.results]
        (self.directory / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        hash_bundle(self.directory, conformance=True)
        print("\nEvidence bundle:", self.directory)
        print(f"Results: {counts['PASS']} passed, {counts['FAIL']} failed, {counts['ERROR']} errors")
        return 1 if counts["FAIL"] or counts["ERROR"] else 0

    def run(self):
        try:
            print("Collecting CDDE evidence in", self.directory)
            self.baseline()
            if self.lifecycle:
                self.run_lifecycle()
            if self.fail_closed:
                self.run_failclosed()
        except (RuntimeError, OSError, KeyError, ValueError) as error:
            self.record("EXECUTION", "Validator execution", "ERROR", str(error))
            print("ERROR:", error, file=sys.stderr)
        except KeyboardInterrupt:
            self.record("EXECUTION", "Validator interrupted", "ERROR", "Interrupted; inspect recovery and cleanup evidence.")
            raise
        finally:
            self.save_report()
        return 0 if all(result["status"] == "PASS" for result in self.results) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    conformance = commands.add_parser("conformance")
    conformance.add_argument("--config", required=True)
    conformance.add_argument("--output", required=True)
    conformance.add_argument("--lifecycle", action="store_true")
    conformance.add_argument("--fail-closed", action="store_true")
    recovery = commands.add_parser("recovery")
    recovery.add_argument("action", choices=("prepare", "check-source", "mutate", "verify", "report"))
    recovery.add_argument("--config")
    recovery.add_argument("--output")
    recovery.add_argument("--bundle")
    recovery.add_argument("--case", dest="case_file")
    recovery.add_argument("--checkpoint", choices=CHECKPOINTS)
    args = parser.parse_args()
    if args.command != "recovery" or args.action != "report":
        if not shutil.which("az"):
            parser.error("Azure CLI is missing; install it and run az login before validation")
    try:
        if args.command == "conformance":
            def terminate(signum, frame):
                raise KeyboardInterrupt("Termination requested; restoring test resources")
            signal.signal(signal.SIGTERM, terminate)
            return Conformance(args.config, args.output, args.lifecycle, args.fail_closed).run()
        if args.action == "prepare":
            if not args.config or not args.output:
                parser.error("Recovery prepare requires --config and --output")
            validator = Recovery(config=args.config, output=args.output)
        else:
            if not args.bundle:
                parser.error("Recovery action requires --bundle")
            validator = Recovery(bundle=args.bundle)
        if args.action == "verify":
            if not args.case_file or not args.checkpoint:
                parser.error("Recovery verify requires --case and --checkpoint")
            return validator.verify(args.case_file, args.checkpoint)
        result = getattr(validator, args.action.replace("-", "_"))()
        return result if isinstance(result, int) else 0
    except (RuntimeError, OSError, KeyError, ValueError) as error:
        print("ERROR:", error, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("ERROR: Validation interrupted; inspect retained evidence and cleanup status.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
