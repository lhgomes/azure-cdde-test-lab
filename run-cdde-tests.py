#!/usr/bin/env python3
"""Provision a disposable CDDE lab and run conformance and recovery tests."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.parse import urlencode
import xml.etree.ElementTree as ET
import cdde_validation as validation

ROOT = Path(__file__).resolve().parent
API = "2026-03-01"
IMAGE = "Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest"
PUBLISHER = "Microsoft.Azure.Security.ConfidentialDiskEncryption"
RECOVERY_EXTENSION_POLICY = "check-first-v1"
PATHS = ("snapshot", "restore-point", "disk-backup", "vm-backup")
TARGETS = ("original", "replacement")
VM_RESTORE_OPERATOR = "dfce8971-25e3-42e3-ba33-6055438e3080"
MANAGED_IDENTITY_OPERATOR = "f1a07417-d97a-45cb-824c-7a7467783830"
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


class AzureError(RuntimeError):
    def __init__(self, command, stderr):
        super().__init__(f"{command}: {stderr.strip()}")
        self.stderr = stderr


class VerificationFailure(RuntimeError):
    pass


def choose_size(skus, usages, requested=None, machines=1):
    available = {}
    for usage in usages:
        name = usage["name"]["value"].lower()
        limit, current = usage["limit"], usage["currentValue"]
        try:
            if any(isinstance(v, bool) or not isinstance(v, (int, str)) for v in (limit, current)):
                raise ValueError("Quota counts must be integers or integer strings")
            limit, current = int(limit), int(current)
            if limit < 0 or current < 0:
                raise ValueError("Quota counts must be non-negative")
        except ValueError as error:
            raise RuntimeError(
                f"Invalid Azure quota counts for {name}: limit={usage['limit']!r}, "
                f"currentValue={usage['currentValue']!r}; expected non-negative integers") from error
        available[name] = limit - current
    candidates = []
    quota_blocked = []
    for sku in skus:
        name = sku["name"]
        # Discover SNP and TDX confidential v6 sizes, not ordinary D/E v6 VMs.
        if not re.fullmatch(r"Standard_(DC|EC)\d+[a-z]*_v6", name):
            continue
        if requested and name.lower() != requested.lower():
            continue
        if any(r.get("type") == "Location" for r in sku.get("restrictions", [])):
            continue
        caps = {c["name"]: c["value"] for c in sku.get("capabilities", [])}
        cores = int(caps.get("vCPUs", 0))
        memory = float(caps.get("MemoryGB", 0))
        if not cores or not memory:
            continue
        demand = cores * machines
        family = sku.get("family", "").lower()
        if available.get(family, -1) < demand or available.get("cores", -1) < demand:
            quota_blocked.append((cores, memory, name,
                f"{name} requires {demand} vCPUs for {machines} VM(s); "
                f"{family} remaining={available.get(family, 'unknown')}, "
                f"regional cores remaining={available.get('cores', 'unknown')}"))
            continue
        candidates.append((cores, memory, name))
    if not candidates:
        detail = (" Quota checks: " + "; ".join(item[3] for item in sorted(quota_blocked)[:4])
                  if quota_blocked else "")
        raise RuntimeError("No unrestricted confidential v6 SKU with sufficient "
                           "family/regional quota was found. No v5 or larger-series fallback is used." + detail)
    return min(candidates)[2]


def terminal_job(status, detail=""):
    if status in ("Completed", "Succeeded"):
        return True
    if status in ("Failed", "Cancelled", "Canceled", "CompletedWithWarnings",
                  "CompletedWithErrors", "PartiallySucceeded"):
        raise RuntimeError(f"Service job ended with {status}" + (": " + detail if detail else ""))
    return False


def job_progress(job):
    properties = job["properties"]
    parts = ["status=" + properties["status"]]
    if properties.get("duration"):
        parts.append("duration=" + str(properties["duration"]))
    info = properties.get("extendedInfo") or {}
    if info.get("progressPercentage") is not None:
        parts.append(f"progress={info['progressPercentage']}%")
    tasks = info.get("tasksList") or []
    if tasks:
        parts.append("tasks: " + "; ".join(
            f"{task.get('taskId', 'unnamed')}={task.get('status', 'Unknown')}" for task in tasks))
    if properties.get("errorDetails"):
        parts.append("errors=" + json.dumps(properties["errorDetails"])[:2000])
    if info.get("dynamicErrorMessage"):
        parts.append("error=" + str(info["dynamicErrorMessage"])[:2000])
    return ", ".join(parts)


def newest_point(points, requested_at):
    cutoff = dt.datetime.fromisoformat(requested_at.replace("Z", "+00:00"))
    candidates = [p for p in points if dt.datetime.fromisoformat(
        p["properties"]["recoveryPointTime"].replace("Z", "+00:00")) >= cutoff]
    return max(candidates, key=lambda p: p["properties"]["recoveryPointTime"]) if candidates else None


def known_cde306(extension):
    if validation.extension_health(extension) != "failed":
        return False
    statuses = (validation.get(extension, "instanceView.statuses", []) +
                validation.get(extension, "instanceView.substatuses", []))
    failures = [s for s in statuses if validation.lower(s.get("level")) == "error" or
                "failed" in s.get("code", "").lower()]
    return (extension.get("provisioningState") == "Failed" and bool(failures) and
            all(s.get("code", "").lower().endswith("/failed/306") for s in failures) and
            any(isinstance(s.get("message"), str) and "[CDE306]" in s["message"] for s in failures))


class Lab:
    def __init__(self, args):
        self.args = args
        if args.resume:
            self.directory = Path(args.resume).resolve()
            self.state = json.loads((self.directory / "state.json").read_text())
            if self.state.get("destroyed"):
                raise RuntimeError("This environment was destroyed; start a new run.")
            if args.subscription_id and args.subscription_id != self.state["subscription"]:
                raise RuntimeError("--subscription-id conflicts with retained state.")
            if args.region and args.region != self.state["region"]:
                raise RuntimeError("--region conflicts with retained state.")
            for key, enabled in (("lifecycle", args.lifecycle), ("fail_closed", args.fail_closed),
                                 ("backup_restore", args.backup_restore)):
                if enabled and not self.state["modes"][key]:
                    self.state["modes"][key] = True
                    self.state["results"].pop("conformance", None)
        else:
            sub = args.subscription_id or input("Subscription ID: ").strip()
            region = args.region or input("Azure region (for example uaenorth): ").strip()
            uuid.UUID(sub)
            if not re.fullmatch(r"[a-z0-9]+", region):
                raise RuntimeError("Region must be an Azure location name, not a display name.")
            token = uuid.uuid4().hex[:12]
            self.directory = Path(args.output).resolve() / ("auto-" + token)
            self.state = {
                "schema": 1, "token": token, "subscription": sub, "region": region,
                "resource_group": "cdde-test-" + token,
                "modes": {"lifecycle": args.lifecycle, "fail_closed": args.fail_closed,
                          "backup_restore": args.backup_restore},
                "steps": {}, "results": {}, "created_utc": utc(),
                "destroyed": False,
            }
        if args.recovery_paths and not self.state["modes"]["backup_restore"]:
            raise RuntimeError("--recovery-paths requires --backup-restore or a retained backup/restore run")
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.raw = self.directory / "raw"
        self.raw.mkdir(exist_ok=True)
        self.attempt = uuid.uuid4().hex[:8]
        self.log_index = 0
        self.save()

    @property
    def sub(self):
        return self.state["subscription"]

    @property
    def rg(self):
        return self.state["resource_group"]

    @property
    def region(self):
        return self.state["region"]

    @property
    def rg_id(self):
        return f"/subscriptions/{self.sub}/resourceGroups/{self.rg}"

    def save(self):
        write_json(self.directory / "state.json", self.state)

    def progress(self, message):
        print(f"[{utc()}] [INFO] {message}", flush=True)

    def pause(self, seconds, description):
        self.progress(f"{description}: {seconds}s")
        remaining = seconds
        while remaining > 0:
            interval = min(60, remaining)
            time.sleep(interval)
            remaining -= interval
            if remaining:
                self.progress(f"{description}: {remaining}s remaining")
        self.progress(f"{description}: wait completed")

    def az(self, *args, private=False):
        self.log_index += 1
        command = ["az", *map(str, args)]
        if args[0] != "extension":
            command += ["--subscription", self.sub]
        command += ["--output", "json"]
        verbs = []
        for arg in args:
            if str(arg).startswith("-"):
                break
            verbs.append(str(arg))
        description = "Azure CLI: " + " ".join(verbs)
        if not private:
            self.progress(description + " started")
        started = time.monotonic()
        completed = subprocess.run(command, text=True, capture_output=True)
        label = f"{self.attempt}-{self.log_index:04d}"
        if not private:
            write_json(self.raw / (label + "-command.json"), command)
            (self.raw / (label + ".stdout")).write_text(completed.stdout, encoding="utf-8")
            (self.raw / (label + ".stderr")).write_text(completed.stderr, encoding="utf-8")
        if completed.returncode:
            raise AzureError(" ".join(command[:5]), completed.stderr)
        if not private:
            self.progress(f"{description} completed ({time.monotonic() - started:.0f}s)")
        if not completed.stdout.strip():
            return None
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"Azure CLI returned invalid JSON; evidence {label}") from error

    def rest(self, method, resource, body=None, version=API):
        args = ["rest", "--method", method, "--url",
                "https://management.azure.com" + resource + "?api-version=" + version]
        if body is not None:
            file = self.raw / f"{self.attempt}-{self.log_index + 1:04d}-body.json"
            write_json(file, body)
            args += ["--headers", "Content-Type=application/json", "--body", "@" + str(file)]
        vm_patch = (method.lower() == "patch" and
                    re.search(r"/providers/Microsoft\.Compute/virtualMachines/[^/]+$", resource, re.I))
        for attempt in range(5):
            try:
                return self.az(*args)
            except AzureError as error:
                if not vm_patch or "ConflictingConcurrentWriteNotAllowed" not in error.stderr or attempt == 4:
                    raise
                delay = min(15 * 2 ** attempt, 60)
                self.progress(f"Concurrent VM write rejected PATCH; retry {attempt + 1}/4 "
                              f"after {delay}s for {resource.rsplit('/', 1)[1]}")
                self.pause(delay, "Waiting for conflicting VM write to settle")
                def ready(value):
                    state = value["properties"].get("provisioningState")
                    if state in ("Failed", "Canceled"):
                        raise RuntimeError(f"VM provisioning {state} while waiting to retry PATCH")
                    return state == "Succeeded"
                self.wait("VM readiness before PATCH retry",
                          lambda: self.rest("get", resource, version=version), ready)

    def once(self, key, operation):
        if key not in self.state["steps"]:
            self.progress("Starting step: " + key)
            started = time.monotonic()
            self.state["steps"][key] = operation()
            self.save()
            self.progress(f"Completed step: {key} ({time.monotonic() - started:.0f}s)")
        else:
            self.progress("Reusing completed step: " + key)
        return self.state["steps"][key]

    def wait(self, description, query, ready, timeout=None, interval=15, describe=None):
        started = time.monotonic()
        limit = timeout or self.args.timeout
        deadline = started + limit
        last_update = started
        observed = False
        self.progress(f"Waiting for {description} (timeout {limit}s)")
        while True:
            value = query()
            now = time.monotonic()
            detail = describe(value) if describe else ""
            if ready(value):
                self.progress(f"Ready: {description} ({now - started:.0f}s)" +
                              (": " + detail if detail else ""))
                return value
            if detail and not observed:
                self.progress(description + ": " + detail)
                observed = True
            if now >= deadline:
                raise RuntimeError(f"Timed out waiting for {description}" +
                                   (". Last observed: " + detail if detail else ""))
            if now - last_update >= 60:
                self.progress(f"Still waiting for {description}: {now - started:.0f}s elapsed" +
                              (": " + detail if detail else ""))
                last_update = now
            time.sleep(interval)

    def vm(self, name):
        return self.rest("get", self.rg_id + "/providers/Microsoft.Compute/virtualMachines/" + name)

    def vm_wait(self, name):
        def ready(value):
            status = value["properties"].get("provisioningState")
            if status in ("Failed", "Canceled"):
                raise RuntimeError(f"VM {name} provisioning {status}")
            return status == "Succeeded"
        return self.wait("VM update " + name, lambda: self.vm(name), ready)

    def guest(self, name, script):
        result = self.az("vm", "run-command", "invoke", "-g", self.rg, "-n", name,
                         "--command-id", "RunShellScript", "--scripts",
                         "set -eu\n" + script + "\necho AUTO_GUEST_PASS")
        text = "\n".join(v.get("message", "") for v in result.get("value", []))
        if not re.search(r"^AUTO_GUEST_PASS$", text, re.MULTILINE):
            raise RuntimeError(f"Guest command failed or truncated on {name}; see raw evidence")
        return text

    def encrypted_guest(self, name, mount_recovered=False):
        script = """
target=/dev/disk/azure/scsi1/lun0
test -b "$target"
cryptsetup isLuks "$target"
"""
        if mount_recovered:
            script += """
uuid=$(cryptsetup luksUUID "$target")
mapper="/dev/mapper/$uuid"
if ! findmnt -rn --mountpoint /cde-data >/dev/null; then
  test -b "$mapper"
  test "$(lsblk -dn -o TYPE "$mapper")" = crypt
  mkdir -p /cde-data
  mount "$mapper" /cde-data
fi
"""
        script += """
source=$(findmnt -rn -o SOURCE --mountpoint /cde-data)
test "$(lsblk -dn -o TYPE "$(readlink -f "$source")")" = crypt
"""
        last_error = []
        def query():
            try:
                self.guest(name, script)
                return True
            except RuntimeError as error:
                if isinstance(error, AzureError):
                    if not any(code in error.stderr for code in
                               ("VMAgentStatusCommunicationError", "VMAgentNotReady", "Conflict")):
                        raise
                elif not str(error).startswith("Guest command failed or truncated"):
                    raise
                last_error[:] = [str(error)]
                print("Waiting for encrypted guest readiness:", name)
                return False
        try:
            self.wait("encrypted guest " + name, query, bool, timeout=min(self.args.timeout, 900))
        except RuntimeError as error:
            raise RuntimeError(f"{error}; last guest error: {last_error}") from error

    def role(self, principal, role, scope, kind="ServicePrincipal"):
        name = str(uuid.uuid5(uuid.NAMESPACE_URL,
                             self.state["token"] + "|" + principal + "|" + role + "|" + scope.lower()))
        return self.az("role", "assignment", "create", "--assignee-object-id", principal,
                       "--assignee-principal-type", kind, "--role", role, "--scope", scope, "--name", name)

    def register(self):
        providers = ["Microsoft.Compute", "Microsoft.KeyVault", "Microsoft.ManagedIdentity",
                     "Microsoft.Network"]
        if self.state["modes"]["backup_restore"]:
            providers += ["Microsoft.RecoveryServices", "Microsoft.DataProtection", "Microsoft.Storage"]
        for provider in providers:
            self.once("provider-" + provider,
                      lambda p=provider: self.az("provider", "register", "-n", p, "--wait"))
        feature = "ConfidentialVMDataDiskEncryptionPreview"
        enrollment = self.az("feature", "show", "--namespace", "Microsoft.Compute", "-n", feature)
        state = enrollment["properties"]["state"]
        if state != "Registered":
            raise RuntimeError(
                f"CDDE preview enrollment is {state}. This feature does not support self-service "
                "registration; request enrollment through your Microsoft account team or support.")
        if self.state["modes"]["backup_restore"] and any(
                path in ("restore-point", "vm-backup") for path in (self.args.recovery_paths or PATHS)):
            feature = "RestorePointSupportForConfidentialVMV2"
            enrollment = self.az("feature", "show", "--namespace", "Microsoft.Compute", "-n", feature)
            if enrollment["properties"]["state"] == "Registered":
                return
            self.once("feature-request-" + feature,
                      lambda f=feature: self.az("feature", "register", "--namespace", "Microsoft.Compute", "-n", f))
            self.wait(feature, lambda f=feature: self.az("feature", "show", "--namespace", "Microsoft.Compute", "-n", f),
                      lambda v: v["properties"]["state"] == "Registered")
            self.az("provider", "register", "-n", "Microsoft.Compute", "--wait")

    def create_vm(self, name, os_disk=None, data_disks=None):
        security = {
            "securityType": "ConfidentialVM",
            "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True},
            "confidentialDataDiskEncryptionIdentity": {
                "userAssignedIdentityResourceId": self.state["identity"]["id"]},
        }
        self.state.setdefault("owned_vm_names", [])
        if name not in self.state["owned_vm_names"]:
            self.state["owned_vm_names"].append(name)
            self.save()
        args = ["vm", "create", "-g", self.rg, "-n", name, "-l", self.region,
                "--size", self.state["vm_size"], "--security-type", "ConfidentialVM",
                "--os-disk-security-encryption-type", "DiskWithVMGuestState",
                "--enable-vtpm", "true", "--enable-secure-boot", "true",
                "--disk-controller-type", "SCSI", "--os-disk-delete-option", "Detach",
                "--public-ip-sku", "Standard", "--vnet-name", "cdde-network",
                "--subnet", "workloads", "--nsg-rule", "NONE",
                "--tags", "cdde-test-run=" + self.state["token"]]
        if os_disk:
            args += ["--attach-os-disk", os_disk, "--os-type", "Linux"]
        else:
            args += ["--image", self.state["image"], "--admin-username", "cddeadmin",
                     "--ssh-key-values", str(self.directory / "ssh-key.pub"),
                     "--storage-sku", "Premium_LRS"]
        self.once("vm-base-" + name, lambda: self.az(*args))
        self.vm_wait(name)
        resource = self.rg_id + "/providers/Microsoft.Compute/virtualMachines/" + name
        self.once("vm-identity-" + name, lambda: self.rest("patch", resource, {
            "identity": {"type": "UserAssigned",
                         "userAssignedIdentities": {self.state["identity"]["id"]: {}}},
            "properties": {"securityProfile": security}}))
        self.vm_wait(name)
        if data_disks:
            self.once("vm-data-disks-" + name, lambda: self.rest("patch", resource, {
                "properties": {"storageProfile": {"dataDisks": data_disks}}}))
        return self.vm_wait(name)

    def attachment(self, disk_id=None):
        model = {"lun": 0, "name": "cdde-source-data", "createOption": "Empty",
                 "deleteOption": "Detach", "diskSizeGB": self.state.get("disk_size_gb", 4), "caching": "None",
                 "managedDisk": {"storageAccountType": "Premium_LRS", "securityProfile": {
                    "securityEncryptionType": "DataDiskEncryptedWithCustomerKey",
                    "diskEncryptionSet": {"id": self.state["des"]["id"]}}}}
        if disk_id:
            model.update({"name": disk_id.rsplit("/", 1)[1], "createOption": "Attach"})
            model["managedDisk"]["id"] = disk_id
        return model

    def provision(self):
        self.progress("Provisioning: validating subscription and provider/feature enrollment")
        account = self.az("account", "show")
        if account["id"].lower() != self.sub.lower():
            raise RuntimeError("Azure CLI selected a different subscription")
        self.register()
        if "vm_size" not in self.state:
            self.progress("Provisioning: checking regional confidential v6 SKUs and quota")
            skus = self.az("vm", "list-skus", "--location", self.region,
                           "--resource-type", "virtualMachines", "--all")
            usages = self.az("vm", "list-usage", "--location", self.region)
            machines = 2 if self.state["modes"]["backup_restore"] else 1
            self.state["vm_size"] = choose_size(skus, usages, self.args.vm_size, machines)
            self.save()
        else:
            self.progress("Reusing saved VM size; skipping SKU discovery and selection quota queries")
        self.state.setdefault("image", self.args.image)
        self.state.setdefault("disk_size_gb", self.args.disk_size_gb)
        if "source-vm" not in self.state["steps"]:
            self.once("image-availability", lambda: self.az(
                "vm", "image", "show", "--location", self.region, "--urn", self.state["image"]))
        else:
            self.progress("Reusing provisioned source VM and saved image; skipping image discovery")
        self.progress("Selected confidential v6 size: " + self.state["vm_size"])
        if self.az("group", "exists", "-n", self.rg):
            existing = self.az("group", "show", "-n", self.rg)
            if existing.get("tags", {}).get("cdde-test-run") != self.state["token"]:
                raise RuntimeError("Existing group is not owned by this run; refusing to overwrite its tags")
        self.once("resource-group", lambda: self.az("group", "create", "-n", self.rg,
            "-l", self.region, "--tags", "cdde-test-run=" + self.state["token"]))
        group = self.az("group", "show", "-n", self.rg)
        if group.get("tags", {}).get("cdde-test-run") != self.state["token"]:
            raise RuntimeError("Resource group ownership tag does not match; refusing changes")
        if not (self.directory / "ssh-key.pub").exists():
            self.progress("Provisioning: generating the deployment SSH public key; SSH ingress remains closed")
            with tempfile.TemporaryDirectory(prefix="cdde-ssh-") as temporary:
                key = Path(temporary) / "key"
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
                (self.directory / "ssh-key.pub").write_text(key.with_suffix(".pub").read_text())
        self.state["vault"] = self.once("vault", lambda: self.az("keyvault", "create",
            "-g", self.rg, "-n", "cdde" + self.state["token"], "-l", self.region,
            "--sku", "premium", "--enable-rbac-authorization", "true", "--enable-purge-protection", "true"))
        token = self.az("account", "get-access-token", private=True)["accessToken"]
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        principal = claims.get("oid")
        if not principal:
            raise RuntimeError("Access token has no object ID; cannot assign deployment permissions")
        kind = "User" if account["user"]["type"] == "user" else "ServicePrincipal"
        self.once("operator-role", lambda: self.role(principal, "Key Vault Crypto Officer", self.state["vault"]["id"], kind))
        if "key" not in self.state["steps"]:
            self.progress("Provisioning: creating the release-controlled RSA-HSM key")
            deadline = time.monotonic() + 900
            while True:
                try:
                    self.state["steps"]["key"] = self.az("keyvault", "key", "create",
                        "--vault-name", self.state["vault"]["name"], "-n", "cdde-key",
                        "--kty", "RSA-HSM", "--size", 3072, "--ops", "wrapKey", "unwrapKey",
                        "--exportable", "true", "--policy", ROOT / "DataDiskSKRPolicy.json")
                    self.save()
                    break
                except AzureError as error:
                    if "ForbiddenByRbac" not in error.stderr or time.monotonic() >= deadline:
                        raise
                    self.pause(20, "Waiting for operator Key Vault RBAC propagation")
        def verify_release_policy():
            key = self.az("keyvault", "key", "show",
                          "--vault-name", self.state["vault"]["name"], "-n", "cdde-key")
            policy = key.get("releasePolicy")
            if not isinstance(policy, dict) or not policy.get("encodedPolicy"):
                raise RuntimeError("Key releasePolicy.encodedPolicy is empty; refusing CDDE provisioning")
            return policy["encodedPolicy"]
        self.once("key-release-policy", verify_release_policy)
        self.state["identity"] = self.once("identity", lambda: self.az("identity", "create",
            "-g", self.rg, "-n", "cdde-identity", "-l", self.region))
        self.state["des"] = self.once("des", lambda: self.az("disk-encryption-set", "create",
            "-g", self.rg, "-n", "cdde-des", "-l", self.region,
            "--source-vault", self.state["vault"]["id"],
            "--key-url", self.state["steps"]["key"]["key"]["kid"],
            "--encryption-type", "ConfidentialVmEncryptedWithCustomerKey", "--mi-system-assigned"))
        for who, role in ((self.state["des"]["identity"]["principalId"], "Key Vault Crypto Service Encryption User"),
                          (self.state["identity"]["principalId"], "Key Vault Crypto Service Encryption User"),
                          (self.state["identity"]["principalId"], "Key Vault Crypto Service Release User")):
            self.once("role-" + who + "-" + role, lambda p=who, r=role: self.role(p, r, self.state["vault"]["id"]))
        self.once("rbac-propagation", lambda: self.pause(
            self.args.rbac_wait, "Waiting for DES/VM Key Vault RBAC propagation"))
        self.once("source-vm", lambda: self.create_vm("cdde-source", data_disks=[self.attachment()]))
        if "source-formatted" not in self.state["steps"]:
            value = self.vm_wait("cdde-source")
            disk_id = value["properties"]["storageProfile"]["dataDisks"][0]["managedDisk"]["id"]
            self.state["source_disk_id"] = disk_id
            self.save()
            self.once("source-formatted", lambda: self.guest("cdde-source", """
target=/dev/disk/azure/scsi1/lun0
test -b "$target"
type=$(blkid -s TYPE -o value "$target" || true)
if test -z "$type"; then
  mkfs.ext4 -F "$target"
elif test "$type" != ext4; then
  echo "Owned source disk already contains a non-ext4 filesystem; refusing to format"
  exit 1
fi
mkdir -p /cde-data
if ! findmnt -rn --mountpoint /cde-data >/dev/null; then
  mount "$target" /cde-data
fi
"""))
        self.once("source-extension", lambda: self.az("vm", "extension", "set", "-g", self.rg,
            "--vm-name", "cdde-source", "--publisher", PUBLISHER, "-n", "CDELinux",
            "--version", "1.0", "--settings", json.dumps({"sequenceVersion": str(uuid.uuid4())})))
        self.save()
        self.write_config()
        self.progress("Provisioning completed; starting selected test suites")

    def write_config(self, vm="cdde-source", filename="generated.json"):
        values = {"subscription_id": self.sub, "resource_group": self.rg,
            "vm_name": vm, "vault_name": self.state["vault"]["name"], "key_name": "cdde-key",
            "des_name": "cdde-des", "identity_name": "cdde-identity", "data_lun": 0,
            "mount_point": "/cde-data", "api_version": API,
            "expected_vm_size": self.state["vm_size"], "expected_location": self.region,
            "expected_sequence_guid": "", "allow_lifecycle_tests": True,
            "allow_fail_closed_tests": True, "allow_recovery_tests": True}
        file = self.directory / Path(filename).with_suffix(".json")
        write_json(file, values)
        return file

    def result(self, key, status, message, **details):
        self.state["results"][key] = {"status": status, "message": message, "updated_utc": utc(), **details}
        self.save()
        print(f"[{status}] {key}: {message}", flush=True)

    def conformance_outcome(self, completed, reports):
        if completed.returncode == 0 and reports:
            return "PASS"
        if not self.args.allow_cde306 or completed.returncode != 1 or not reports:
            return "FAIL"
        for file in reports:
            report = json.loads(file.read_text())
            failures = [t for t in report["tests"] if t["status"] != "PASS"]
            if len(failures) != 1 or failures[0]["id"] != "EXT-002" or failures[0]["status"] != "FAIL":
                return "FAIL"
            if not known_cde306(json.loads((file.parent / "raw" / "extension.json").read_text())):
                return "FAIL"
        self.progress("Known CDE306 exception applied; original conformance report remains FAIL")
        return "QUALIFIED"

    def conformance(self, read_only=False):
        self.progress("Source health/conformance checks" if read_only else
                      "Starting conformance and selected lifecycle/fail-closed checks")
        self.encrypted_guest("cdde-source")
        modes = self.state["modes"]
        command = [sys.executable, str(ROOT / "cdde_validation.py"), "conformance", "--config", str(self.write_config()),
                   "--output", str(self.directory / ("conformance-" + self.attempt))]
        if modes["lifecycle"] and not read_only:
            command.append("--lifecycle")
        if modes["fail_closed"] and not read_only:
            command.append("--fail-closed")
        completed = self.suite_command(command)
        reports = list((self.directory / ("conformance-" + self.attempt)).glob("*/report.json"))
        status = self.conformance_outcome(completed, reports)
        self.result("source-health" if read_only else "conformance",
                    status, ("Conformance completed with known CDE306 exception" if status == "QUALIFIED" else
                    "Existing CDDE suite completed" if reports else "Suite exited before producing a report"),
                    reports=[str(p.relative_to(self.directory)) for p in reports], read_only=read_only)
        if status == "FAIL":
            raise RuntimeError("Source conformance/health gate failed; inspect its report for the failing checks")

    def suite_command(self, command):
        def interrupted(signum, frame):
            print("\nInterrupt received. Waiting for the validator's role restoration and cleanup before continuing.")
        previous = signal.signal(signal.SIGINT, interrupted)
        try:
            return subprocess.run(command)
        finally:
            signal.signal(signal.SIGINT, previous)

    def start(self, vm):
        self.az("vm", "start", "-g", self.rg, "-n", vm)
        self.vm_wait(vm)

    def stop(self, vm):
        self.az("vm", "deallocate", "-g", self.rg, "-n", vm)
        self.vm_wait(vm)

    def swap(self, disk_id):
        self.stop("cdde-source")
        model = self.vm("cdde-source")
        disks = model["properties"]["storageProfile"]["dataDisks"]
        if any(d["lun"] != 0 for d in disks):
            raise RuntimeError("Unexpected data LUN on owned source VM; refusing to replace its disk array")
        self.rest("patch", model["id"], {"properties": {"storageProfile": {"dataDisks": []}}})
        self.vm_wait("cdde-source")
        self.rest("patch", model["id"], {"properties": {"storageProfile": {"dataDisks": [self.attachment(disk_id)]}}})
        self.vm_wait("cdde-source")
        if disk_id.lower() == self.state["source_disk_id"].lower():
            original = self.state["steps"]["source-vm"]
            self.rest("patch", model["id"], {
                "identity": original["identity"],
                "properties": {"securityProfile": original["properties"]["securityProfile"]}})
            self.vm_wait("cdde-source")
        self.start("cdde-source")

    def recovery_job(self, job):
        name = job.get("name")
        if not name and job.get("id"):
            name = job["id"].rsplit("/", 1)[1]
        if not name:
            raise RuntimeError("Backup service did not return a correlated job ID")
        self.progress("Azure backup/restore jobs continue if the local script is stopped; "
                      "this wait does not cancel the server-side operation.")
        self.wait("Recovery Services job " + name,
                  lambda: self.az("backup", "job", "show", "-g", self.rg,
                                 "--vault-name", "cdde-rsv", "-n", name),
                  lambda v: terminal_job(v["properties"]["status"], job_progress(v)),
                  describe=job_progress)

    def wait_for_vm_backups(self):
        def query():
            jobs = self.az("backup", "job", "list", "-g", self.rg, "--vault-name", "cdde-rsv")
            active = [j for j in jobs if j["properties"].get("operation") == "Backup" and
                      j["properties"].get("status") in ("InProgress", "Queued", "Cancelling", "Canceling")]
            pending = []
            for job in active:
                current = self.az("backup", "job", "show", "-g", self.rg,
                                  "--vault-name", "cdde-rsv", "-n", job["name"])
                if terminal_job(current["properties"]["status"], job_progress(current)):
                    self.progress("Existing VM backup finished: " + job_progress(current))
                else:
                    pending.append(current)
            return pending
        self.wait("active VM backups before VM/disk changes", query, lambda jobs: not jobs,
                  describe=lambda jobs: "; ".join(
                      f"{j['name']}: {job_progress(j)}" for j in jobs) or "No active backup jobs")

    def dp_job(self, before, operation):
        def query():
            jobs = self.az("dataprotection", "job", "list", "-g", self.rg, "--vault-name", "cdde-bv")
            matches = [j for j in jobs if j["name"] not in before
                       and j["properties"].get("operation", "").lower().startswith(operation.lower())]
            if len(matches) > 1:
                raise RuntimeError("Ambiguous Data Protection jobs; refusing to guess job correlation")
            return matches[0] if matches else None
        return self.wait("Data Protection " + operation,
                         query, lambda j: j is not None and terminal_job(
                             j["properties"]["status"], job_progress(j)),
                         describe=lambda j: job_progress(j) if j else "Waiting for the correlated job to appear")

    def vm_restore_authorization(self, configure=False):
        def vault():
            return self.az("backup", "vault", "show", "-g", self.rg, "-n", "cdde-rsv")
        identity = vault().get("identity") or {}
        if not identity.get("principalId") and configure:
            self.az("backup", "vault", "identity", "assign", "-g", self.rg, "-n", "cdde-rsv",
                    "--system-assigned")
            identity = self.wait("vault system-assigned identity", vault,
                lambda value: bool((value.get("identity") or {}).get("principalId"))).get("identity")
        principal = identity.get("principalId")
        if not principal:
            raise RuntimeError("Recovery Services vault has no system-assigned identity; "
                               "configure restore authorization before changing the source VM")
        required = [(VM_RESTORE_OPERATOR, self.rg_id),
                    (MANAGED_IDENTITY_OPERATOR, self.state["identity"]["id"]),
                    (READER, self.state["des"]["id"])]

        def assigned(role, scope):
            assignments = self.az("role", "assignment", "list", "--assignee-object-id", principal,
                                  "--scope", scope, "--include-inherited")
            return any(a.get("principalId", "").lower() == principal.lower() and
                       a.get("roleDefinitionId", "").rsplit("/", 1)[-1].lower() == role and
                       not a.get("condition") and
                       (scope.lower() == a.get("scope", "").lower() or
                        scope.lower().startswith(a.get("scope", "").lower().rstrip("/") + "/"))
                       for a in assignments if a.get("scope"))

        changed = False
        for role, scope in required:
            if assigned(role, scope):
                continue
            if not configure:
                raise RuntimeError(f"Vault restore authorization missing role {role} at {scope}; "
                                   "restore was not started")
            self.role(principal, role, scope)
            changed = True
            self.wait("vault restore role " + role, lambda: assigned(role, scope), bool)
        if changed:
            self.pause(self.args.rbac_wait, "Waiting for vault restore role propagation")
        verified = {"principal_id": principal, "verified_utc": utc(),
                    "required_roles": [{"role_id": role, "scope": scope} for role, scope in required]}
        self.state["vm_restore_authorization"] = verified
        self.save()
        self.progress("Vault restore identity and scoped role assignments verified")
        return verified

    def setup_vm_backup(self):
        self.once("rsv", lambda: self.az("backup", "vault", "create", "-g", self.rg, "-n", "cdde-rsv", "-l", self.region))
        self.once("rsv-redundancy", lambda: self.az("backup", "vault", "backup-properties", "set",
            "-g", self.rg, "-n", "cdde-rsv", "--backup-storage-redundancy", "LocallyRedundant"))
        schedule = dt.datetime.now(dt.timezone.utc).replace(hour=2, minute=0, second=0, microsecond=0).isoformat()
        policy = {"properties": {"backupManagementType": "AzureIaasVM", "policyType": "V2",
            "timeZone": "UTC", "instantRpRetentionRangeInDays": 2,
            "schedulePolicy": {"schedulePolicyType": "SimpleSchedulePolicyV2",
                "scheduleRunFrequency": "Daily", "dailySchedule": {"scheduleRunTimes": [schedule]}},
            "retentionPolicy": {"retentionPolicyType": "LongTermRetentionPolicy",
                "dailySchedule": {"retentionTimes": [schedule],
                    "retentionDuration": {"count": 7, "durationType": "Days"}}}}}
        policy_file = self.directory / "vm-policy.json"
        write_json(policy_file, policy)
        self.once("vm-policy", lambda: self.az("backup", "policy", "create", "-g", self.rg,
            "--vault-name", "cdde-rsv", "-n", "cdde-enhanced", "--backup-management-type", "AzureIaasVM",
            "--policy", "@" + str(policy_file)))
        # Key backup/read is separate from guest SKR authorization.
        if "backup-key-role" not in self.state["steps"]:
            query = urlencode({"$filter": "appId eq '262044b1-e2ce-469f-a196-69ab7ada62d3'",
                               "$select": "id"})
            response = self.az("rest", "--method", "get", "--resource", "https://graph.microsoft.com/",
                               "--url", "https://graph.microsoft.com/v1.0/servicePrincipals?" + query)
            services = response.get("value", [])
            if len(services) != 1:
                raise RuntimeError("Cannot uniquely resolve the Backup Management Service principal "
                                   "in the requested subscription's tenant")
            service = services[0]
            role = {"Name": "cdde-backup-" + self.state["token"], "IsCustom": True,
                    "Description": "Owned CDDE test lab key metadata and backup only",
                    "Actions": [], "DataActions": ["Microsoft.KeyVault/vaults/keys/read",
                                                  "Microsoft.KeyVault/vaults/keys/backup/action"],
                    "AssignableScopes": [self.rg_id]}
            file = self.directory / "backup-key-role.json"
            write_json(file, role)
            definition = self.once("backup-key-role-definition",
                lambda: self.az("role", "definition", "create", "--role-definition", str(file)))
            self.state["custom_role_id"] = definition["id"]
            self.save()
            self.once("backup-key-role", lambda: self.role(service["id"], definition["id"], self.state["vault"]["id"]))
            self.pause(self.args.rbac_wait, "Waiting for VM Backup key role propagation")
        self.once("vm-protection", lambda: self.az("backup", "protection", "enable-for-vm",
            "-g", self.rg, "--vault-name", "cdde-rsv", "--vm", "cdde-source", "--policy-name", "cdde-enhanced"))
        def protected_items():
            items = self.az("backup", "item", "list", "-g", self.rg, "--vault-name", "cdde-rsv",
                           "--backup-management-type", "AzureIaasVM", "--workload-type", "VM")
            matches = [i for i in items if i["properties"].get("virtualMachineId", "").lower() ==
                       (self.rg_id + "/providers/Microsoft.Compute/virtualMachines/cdde-source").lower()]
            if len(matches) > 1:
                raise RuntimeError("Cannot uniquely resolve the protected VM backup item")
            for item in matches:
                properties = item["properties"]
                state = properties.get("protectionState")
                if (str(properties.get("isScheduledForDeferredDelete")).lower() == "true" or
                        state == "SoftDeleted"):
                    raise RuntimeError("VM Backup item is soft-deleted; undelete it and resume protection "
                                       "with the cdde-enhanced policy before retrying. "
                                       "No automatic undelete or protection change was attempted")
                if state in ("ProtectionStopped", "ProtectionError"):
                    raise RuntimeError(f"VM Backup protection is {state}; restore active protection "
                                       "with the cdde-enhanced policy before retrying")
            return matches
        matches = self.wait("VM backup protection", protected_items,
            lambda values: len(values) == 1 and
                values[0]["properties"].get("protectionState") in ("Protected", "IRPending") and
                bool(values[0]["properties"].get("policyId")),
            describe=lambda values: json.dumps([{
                "state": item["properties"].get("protectionState"),
                "policyId": item["properties"].get("policyId"),
                "softDeleted": item["properties"].get("isScheduledForDeferredDelete")}
                for item in values]))
        self.state["vm_item"] = matches[0]["name"]
        self.state["vm_container"] = matches[0]["id"].split("/protectionContainers/")[1].split("/")[0]
        self.save()
        self.once("staging", lambda: self.az("storage", "account", "create", "-g", self.rg,
            "-n", "cdde" + self.state["token"] + "st", "-l", self.region, "--sku", "Standard_LRS",
            "--kind", "StorageV2", "--allow-blob-public-access", "false"))
        self.vm_restore_authorization(configure=True)

    def setup_disk_backup(self):
        self.once("dataprotection-extension", lambda: self.az("extension", "add", "-n", "dataprotection"))
        if "bv" not in self.state["steps"]:
            self.progress("Disk Backup vault: Always-On soft delete with 14-day retention cannot be "
                          "disabled; cleanup may retain backup data and charges.")
        vault = self.once("bv", lambda: self.az("dataprotection", "backup-vault", "create",
            "-g", self.rg, "--vault-name", "cdde-bv", "-l", self.region,
            "--mi-system-assigned", "true", "--soft-delete-state", "AlwaysOn",
            "--soft-delete-retention", "14",
            "--storage-settings", "datastore-type=VaultStore", "type=LocallyRedundant"))
        principal = vault["identity"]["principalId"]
        for role, scope in (("Disk Backup Reader", self.state["source_disk_id"]),
                            ("Disk Snapshot Contributor", self.rg_id),
                            ("Disk Restore Operator", self.rg_id)):
            self.once("bv-role-" + role, lambda r=role, s=scope: self.role(principal, r, s))
        template = self.once("disk-policy-template", lambda: self.az(
            "dataprotection", "backup-policy", "get-default-policy-template", "--datasource-type", "AzureDisk"))
        file = self.directory / "disk-policy.json"
        write_json(file, template)
        policy = self.once("disk-policy", lambda: self.az("dataprotection", "backup-policy", "create",
            "-g", self.rg, "--vault-name", "cdde-bv", "-n", "cdde-policy", "--policy", str(file)))
        rules = policy["properties"]["policyRules"]
        self.state["disk_backup_rule"] = next(r["name"] for r in rules if r["objectType"] == "AzureBackupRule")
        request = self.az("dataprotection", "backup-instance", "initialize",
            "--datasource-type", "AzureDisk", "-l", self.region, "--policy-id", policy["id"],
            "--datasource-id", self.state["source_disk_id"])
        parameters = request["properties"]["policy_info"]["policy_parameters"]["data_store_parameters_list"]
        for parameter in parameters:
            if parameter.get("data_store_type") == "OperationalStore":
                parameter["resource_group_id"] = self.rg_id
        file = self.directory / "disk-instance.json"
        write_json(file, request)
        self.once("disk-backup-rbac-propagation", lambda: self.pause(
            self.args.rbac_wait, "Waiting for Disk Backup role propagation"))
        instance = self.once("disk-instance", lambda: self.az("dataprotection", "backup-instance", "create",
            "-g", self.rg, "--vault-name", "cdde-bv", "--backup-instance", str(file)))
        self.state["disk_instance"] = instance["name"]
        self.save()

    def capture(self, path, name):
        if path == "snapshot":
            # No workload writes after fixture sync; source is deallocated for this capture.
            self.stop("cdde-source")
            try:
                value = self.az("snapshot", "create", "-g", self.rg, "-n", name, "-l", self.region,
                    "--source", self.state["source_disk_id"], "--incremental", "false")
                return {"id": value["id"], "name": name, "completed": utc()}
            finally:
                self.start("cdde-source")
        if path == "restore-point":
            collection = "cdde-rpc"
            self.once("rpc", lambda: self.az("restore-point", "collection", "create", "-g", self.rg,
                "--collection-name", collection, "-l", self.region, "--source-id", self.vm("cdde-source")["id"]))
            self.az("restore-point", "create", "-g", self.rg, "--collection-name", collection, "-n", name)
            value = self.wait("restore point", lambda: self.az("restore-point", "show", "-g", self.rg,
                "--collection-name", collection, "-n", name),
                lambda v: terminal_job(v.get("provisioningState", v.get("properties", {}).get("provisioningState", ""))))
            properties = value.get("properties", value)
            self.progress("Restore-point consistency reported by Azure: " +
                          str(properties.get("consistencyMode", "not reported")))
            return {"id": value["id"], "name": name, "value": value,
                    "consistency_mode": properties.get("consistencyMode"), "completed": utc()}
        if path == "disk-backup":
            self.setup_disk_backup()
            before = {j["name"] for j in self.az("dataprotection", "job", "list", "-g", self.rg, "--vault-name", "cdde-bv")}
            requested = utc()[:19] + "Z"
            self.az("dataprotection", "backup-instance", "adhoc-backup", "-g", self.rg,
                "--vault-name", "cdde-bv", "-n", self.state["disk_instance"],
                "--rule-name", self.state["disk_backup_rule"])
            job = self.dp_job(before, "Backup")
            point = self.wait("new disk recovery point", lambda: newest_point(
                self.az("dataprotection", "recovery-point", "list", "-g", self.rg,
                    "--vault-name", "cdde-bv", "--backup-instance-name", self.state["disk_instance"]), requested), bool)
            return {"id": point["id"], "name": point["name"], "job": job, "completed": utc()}
        self.setup_vm_backup()
        self.wait_for_vm_backups()
        requested = utc()[:19] + "Z"
        job = self.az("backup", "protection", "backup-now", "-g", self.rg,
            "--vault-name", "cdde-rsv", "--container-name", self.state["vm_container"],
            "--item-name", self.state["vm_item"], "--backup-management-type", "AzureIaasVM",
            "--retain-until", (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).strftime("%d-%m-%Y"))
        self.recovery_job(job)
        point = self.wait("new VM recovery point", lambda: newest_point(
            self.az("backup", "recoverypoint", "list", "-g", self.rg,
                "--vault-name", "cdde-rsv", "--container-name", self.state["vm_container"],
                "--item-name", self.state["vm_item"], "--backup-management-type", "AzureIaasVM"), requested), bool)
        return {"id": point["id"], "name": point["name"], "completed": utc()}

    def restored_disk(self, path, point, name):
        if path == "disk-backup":
            target_id = self.rg_id + "/providers/Microsoft.Compute/disks/" + name
            request = self.az("dataprotection", "backup-instance", "restore", "initialize-for-data-recovery",
                "--datasource-type", "AzureDisk", "--restore-location", self.region,
                "--source-datastore", "OperationalStore", "--recovery-point-id", point["name"],
                "--target-resource-id", target_id)
            file = self.directory / (name + "-restore.json")
            write_json(file, request)
            before = {j["name"] for j in self.az("dataprotection", "job", "list", "-g", self.rg, "--vault-name", "cdde-bv")}
            self.az("dataprotection", "backup-instance", "restore", "trigger", "-g", self.rg,
                "--vault-name", "cdde-bv", "--backup-instance-name", self.state["disk_instance"],
                "--restore-request-object", str(file))
            job = self.dp_job(before, "Restore")
            self.az("disk", "show", "--ids", target_id)
            return target_id, None, job["id"]
        if path == "restore-point":
            model = point["value"].get("sourceMetadata", point["value"].get("properties", {}).get("sourceMetadata", {}))
            storage = model["storageProfile"]
            matches = [d for d in storage["dataDisks"] if
                       d.get("managedDisk", {}).get("id", "").lower() == self.state["source_disk_id"].lower()]
            if len(matches) != 1:
                raise RuntimeError("Restore point does not uniquely reference the exact source CDDE disk")
            data = matches[0]
            value = self.az("disk", "create", "-g", self.rg, "-n", name,
                            "--source", data["diskRestorePoint"]["id"], "--sku", "Premium_LRS")
            return value["id"], storage["osDisk"]["diskRestorePoint"]["id"], value["id"]
        value = self.az("disk", "create", "-g", self.rg, "-n", name, "-l", self.region,
                        "--source", point["id"], "--sku", "Premium_LRS")
        return value["id"], None, value["id"]

    def restore_vm_backup(self, point, target, name):
        self.vm_restore_authorization()
        args = ["backup", "restore", "restore-disks", "-g", self.rg, "--vault-name", "cdde-rsv",
                "--container-name", self.state["vm_container"], "--item-name", self.state["vm_item"],
                "--rp-name", point["name"], "--storage-account", "cdde" + self.state["token"] + "st",
                "--mi-system-assigned"]
        if target == "original":
            self.stop("cdde-source")
            args += ["--restore-mode", "OriginalLocation"]
        else:
            self.state.setdefault("owned_vm_names", [])
            if name not in self.state["owned_vm_names"]:
                self.state["owned_vm_names"].append(name)
                self.save()
            args += ["--restore-mode", "AlternateLocation", "--target-resource-group", self.rg,
                     "--target-vm-name", name, "--target-vnet-name", "cdde-network",
                     "--target-vnet-resource-group", self.rg, "--target-subnet-name", "workloads"]
        job = self.az(*args)
        self.recovery_job(job)
        vm = "cdde-source" if target == "original" else name
        self.start(vm)
        model = self.vm_wait(vm)
        disk = next(d for d in model["properties"]["storageProfile"]["dataDisks"] if d["lun"] == 0)
        return vm, disk["managedDisk"]["id"], job.get("id") or job["name"]

    def reuse_vm_backup_point(self):
        bundle = Path(self.args.recovery_bundle).resolve()
        registered = {Path(p).resolve() for p in self.state.get("recovery_bundles", [])}
        if bundle not in registered or self.directory not in bundle.parents:
            raise RuntimeError("Reuse requires a recovery bundle registered in this retained run")
        if (bundle / "mutated.json").exists():
            raise RuntimeError("Reuse bundle was already mutated; no automatic reuse or new capture attempted")
        try:
            manifest = json.loads((bundle / "manifest.json").read_text())
            settings = json.loads((bundle / "settings.json").read_text())
            prepared = dt.datetime.fromisoformat(manifest["prepared_utc"].replace("Z", "+00:00"))
        except (OSError, ValueError, KeyError) as error:
            raise RuntimeError("Cannot read the original prepared recovery bundle: " + str(error)) from error
        source_vm = self.rg_id + "/providers/Microsoft.Compute/virtualMachines/cdde-source"
        if (manifest.get("source_vm_id", "").lower() != source_vm.lower() or
                manifest.get("source_disk_id", "").lower() != self.state["source_disk_id"].lower() or
                settings.get("subscription") != self.sub or settings.get("resource_group") != self.rg or
                settings.get("vm_name") != "cdde-source" or settings.get("lun") != 0 or
                settings.get("mount_point") != "/cde-data" or prepared.tzinfo is None):
            raise RuntimeError("Reuse bundle does not match this source VM, disk, mount, LUN or subscription")
        evidence = self.raw / (self.attempt + "-reuse-bundle-checksums.txt")
        try:
            valid, output = validation.check_checksums(bundle)
        except RuntimeError as error:
            evidence.write_text(str(error) + "\n", encoding="utf-8")
            raise RuntimeError("Reuse bundle checksum validation failed; see " + evidence.name) from error
        evidence.write_text(output, encoding="utf-8")
        if not valid:
            raise RuntimeError("Reuse bundle checksum validation failed; see " + evidence.name)
        items = self.az("backup", "item", "list", "-g", self.rg, "--vault-name", "cdde-rsv",
                        "--backup-management-type", "AzureIaasVM", "--workload-type", "VM")
        matches = [item for item in items if item["name"] == self.state["vm_item"] and
                   item["properties"].get("virtualMachineId", "").lower() == source_vm.lower()]
        if len(matches) != 1:
            raise RuntimeError("Reuse cannot uniquely associate the backup item with the source VM")
        item_id = matches[0]["id"]
        points = self.az("backup", "recoverypoint", "list", "-g", self.rg,
                         "--vault-name", "cdde-rsv", "--container-name", self.state["vm_container"],
                         "--item-name", self.state["vm_item"], "--backup-management-type", "AzureIaasVM")
        matches = [point for point in points if point["name"] == self.args.reuse_vm_backup_point]
        if len(matches) != 1:
            raise RuntimeError("The explicit recovery point was not uniquely found; no new capture attempted")
        point = matches[0]
        properties = point["properties"]
        tiers = properties.get("recoveryPointTierDetails") or []
        if not any(tier.get("type") == "HardenedRP" and tier.get("status") == "Valid" for tier in tiers):
            raise RuntimeError("Reuse requires a valid completed vault-tier recovery point")
        try:
            captured = dt.datetime.fromisoformat(properties["recoveryPointTime"].replace("Z", "+00:00"))
        except (KeyError, ValueError) as error:
            raise RuntimeError("Recovery point does not provide a valid capture timestamp") from error
        if (captured.tzinfo is None or captured < prepared or captured > dt.datetime.now(dt.timezone.utc) or
                not point["id"].lower().startswith(item_id.lower() + "/recoverypoints/")):
            raise RuntimeError("Recovery point predates the dataset or does not belong to its backup item")
        value = {"id": point["id"], "name": point["name"], "completed": captured.isoformat(),
                 "consistency_mode": properties.get("recoveryPointType"), "reused": True,
                 "bundle": str(bundle), "value": point}
        write_json(self.raw / (self.attempt + "-vm-backup-capture.json"), value)
        self.progress("Reusing completed VM Backup point " + point["name"] +
                      "; skipping prepare and backup-now; bundle " + str(bundle))
        return bundle, value

    def run_stage(self, *args):
        action = str(args[0])
        self.progress("Recovery stage started: " + action)
        completed = subprocess.run([sys.executable, str(ROOT / "cdde_validation.py"), "recovery", *map(str, args)],
                                   text=True, capture_output=True)
        self.log_index += 1
        file = self.raw / f"{self.attempt}-{self.log_index:04d}-recovery-stage.txt"
        file.write_text(completed.stdout + "\n" + completed.stderr, encoding="utf-8")
        if completed.returncode:
            if args and args[0] == "verify":
                cases = list(Path(args[args.index("--bundle") + 1]).glob("cases/*.json"))
                if cases:
                    latest = max(cases, key=lambda p: p.stat().st_mtime_ns)
                    if json.loads(latest.read_text()).get("status") == "FAIL":
                        raise VerificationFailure(f"Restored guest validation failed; see {file.name}")
            detail = (completed.stderr.strip() or completed.stdout.strip())[-1200:]
            raise RuntimeError(f"Recovery {action} failed; see {file.name}" +
                               (": " + detail if detail else ""))
        self.progress(f"Recovery stage completed: {action}; evidence {file.name}")
        return completed.stdout

    def check_recovery_extension(self, vm, case_file, checkpoint, configure_missing=False):
        prefix = Path(case_file).stem + "-" + checkpoint + "-extension"
        decision_file = self.raw / (prefix + "-decision.json")
        decision = {"policy": RECOVERY_EXTENSION_POLICY, "vm": vm, "checkpoint": checkpoint,
                    "observed_utc": utc(), "action": "inspect", "extension_set_requested": False}
        config = {"expected_extension_publisher": PUBLISHER, "expected_extension_type": "CDELinux"}

        def save_evidence(label, value):
            file = self.raw / (prefix + "-" + label + ".json")
            write_json(file, value)
            decision[label] = str(file.relative_to(self.directory))
            write_json(decision_file, decision)

        def inspect(label):
            extension = self.az("vm", "extension", "show", "-g", self.rg, "--vm-name", vm,
                                "-n", "CDELinux", "--expand", "instanceView")
            save_evidence(label, extension)
            if not isinstance(extension, dict):
                raise RuntimeError("Invalid extension response; inspect " + decision[label])
            return extension

        def settled(extension):
            health = validation.extension_health(extension)
            if health == "invalid":
                raise RuntimeError("Invalid or unexpected extension status; inspect " + str(decision_file))
            return health != "pending"

        try:
            inventory = self.az("vm", "extension", "list", "-g", self.rg, "--vm-name", vm)
            save_evidence("inventory", inventory)
            if (not isinstance(inventory, list) or any(not isinstance(item, dict) or
                    not isinstance(item.get("name"), str) or not item["name"] or
                    not isinstance(item.get("publisher"), str) or not item["publisher"] for item in inventory)):
                raise RuntimeError("Invalid extension inventory; absence cannot be established")
            matches = [item for item in inventory if item["name"].lower() == "cdelinux" or
                       validation.lower(item.get("publisher")) == PUBLISHER.lower()]
            if len(matches) > 1 or (matches and matches[0]["name"].lower() != "cdelinux"):
                raise VerificationFailure("Conflicting CDDE extension resources; refusing to configure another")
            decision["present_before"] = bool(matches)
            installation_error = None
            if matches:
                extension = inspect("before")
                decision["action"] = "observe-existing"
            else:
                save_evidence("before", {"present": False})
                decision["action"] = "install-missing" if configure_missing else "preserve-missing"
                write_json(decision_file, decision)
                if not configure_missing:
                    raise VerificationFailure("CDELinux disappeared after recovery; refusing to reinstall during " + checkpoint)
                decision["extension_set_requested"] = True
                write_json(decision_file, decision)
                self.progress(f"{vm}: CDELinux is absent; installing it once, with absence evidence saved")
                try:
                    self.az("vm", "extension", "set", "-g", self.rg, "--vm-name", vm,
                            "--publisher", PUBLISHER, "-n", "CDELinux", "--version", "1.0",
                            "--settings", json.dumps({"sequenceVersion": str(uuid.uuid4())}))
                except AzureError as error:
                    installation_error = error
                    decision["installation_error"] = str(error)
                extension = inspect("after")
                if installation_error and not (self.args.allow_cde306 and
                        "VMExtensionProvisioningError" in installation_error.stderr and known_cde306(extension)):
                    raise installation_error
            if not settled(extension):
                self.progress(f"{vm}: waiting for extension processing; no additional enable requested")
                extension = self.wait("CDELinux status " + vm, lambda: inspect("settled"), settled,
                    describe=lambda value: str(value.get("provisioningState")) + "; " +
                        validation.extension_health(value))
            if not validation.extension_configuration_valid(extension, config):
                decision["action"] = "preserve-invalid-configuration"
                raise VerificationFailure("CDELinux configuration is invalid; refusing automatic reconfiguration")
            decision["health"] = validation.extension_health(extension)
            if decision["health"] != "succeeded":
                if matches:
                    decision["action"] = "preserve-failure"
                decision["cde306_exception_applied"] = bool(self.args.allow_cde306 and known_cde306(extension))
                if not decision["cde306_exception_applied"]:
                    codes = ", ".join(item["code"] for item in
                        validation.get(extension, "instanceView.statuses", []) +
                        validation.get(extension, "instanceView.substatuses", []))
                    raise VerificationFailure(
                        f"CDELinux health failed at {checkpoint} ({codes}); preserved without repair. Evidence: {decision_file}")
                self.progress(f"{vm}: evidenced CDE306 at {checkpoint}; preserving failure and continuing under explicit exception")
            else:
                if matches:
                    decision["action"] = "keep-existing"
                self.progress(f"{vm}: CDELinux healthy at {checkpoint}; no re-enable requested" if matches else
                              f"{vm}: initial CDELinux installation is healthy")
            return decision
        except RuntimeError as error:
            decision["error"] = str(error)
            raise
        finally:
            write_json(decision_file, decision)

    def verify_recovery(self, bundle, case_file, vm):
        checks = {"initial": self.check_recovery_extension(vm, case_file, "initial", configure_missing=True)}
        self.encrypted_guest(vm, mount_recovered=True)
        for checkpoint in ("initial", "restart", "deallocate-start"):
            self.progress(f"Recovery verification: {vm}, checkpoint {checkpoint}")
            if checkpoint == "restart":
                self.az("vm", "restart", "-g", self.rg, "-n", vm)
            elif checkpoint == "deallocate-start":
                self.stop(vm)
                self.start(vm)
            # Agent readiness is checked by successful guest commands, not assumed
            # from an ARM VM provisioning status.
            self.wait("guest agent", lambda: self.az("vm", "get-instance-view", "-g", self.rg, "-n", vm),
                lambda v: any(s.get("code") == "ProvisioningState/succeeded"
                              for s in v["instanceView"].get("vmAgent", {}).get("statuses", [])),
                describe=lambda v: "agent statuses=" + json.dumps(
                    v["instanceView"].get("vmAgent", {}).get("statuses", [])))
            if checkpoint != "initial":
                checks[checkpoint] = self.check_recovery_extension(vm, case_file, checkpoint)
            # Only the initial recovery permits an explicit mount.
            self.encrypted_guest(vm)
            self.run_stage("verify", "--bundle", bundle, "--case", case_file, "--checkpoint", checkpoint)
        return checks

    def backup_restore(self):
        selected = tuple(dict.fromkeys(self.args.recovery_paths or PATHS))
        self.state["last_recovery_paths"] = list(selected)
        self.save()
        self.progress("Recovery paths selected for this attempt: " + ", ".join(selected))
        excluded = [path for path in PATHS if path not in selected]
        if excluded:
            self.progress("Recovery paths excluded from this attempt (prior results preserved): " +
                          ", ".join(excluded))
        pending = [(p, t) for p in selected for t in TARGETS
                   if not self.args.retry_failed or self.state["results"].get(p + "/" + t, {}).get("status")
                   not in (("PASS", "QUALIFIED") if self.args.allow_cde306 else ("PASS",))]
        if not pending:
            self.progress("Backup/restore: all requested cases already passed")
            return
        reused = None
        if any(path == "vm-backup" for path, _ in pending):
            self.progress("Checking VM Backup protection and restore authorization before source-data changes")
            try:
                self.setup_vm_backup()
                self.wait_for_vm_backups()
                if getattr(self.args, "reuse_vm_backup_point", None):
                    reused = self.reuse_vm_backup_point()
            except (AzureError, RuntimeError, KeyError, StopIteration) as error:
                for path, target in pending:
                    if path == "vm-backup":
                        self.result(path + "/" + target, "ERROR", "VM Backup preflight failed: " + str(error),
                                    support="exploratory", phase="preflight")
                raise
        self.progress(f"Backup/restore: starting {len(pending)} pending path/target cases")
        self.progress("Backup/restore: preparing the encrypted source and synthetic dataset before capture")
        self.swap(self.state["source_disk_id"])
        self.encrypted_guest("cdde-source")
        points = {}
        if reused:
            bundle, points["vm-backup"] = reused
            self.run_stage("check-source", "--bundle", bundle)
        else:
            text = self.run_stage("prepare", "--config", self.write_config(),
                                  "--output", self.directory / ("recovery-" + self.attempt))
            bundle = Path(next(line.removeprefix("Prepared bundle: ") for line in text.splitlines()
                               if line.startswith("Prepared bundle: ")))
            self.state.setdefault("recovery_bundles", []).append(str(bundle))
            self.save()
            for path in dict.fromkeys(p for p, _ in pending):
                try:
                    self.progress(f"Backup/restore capture started: {path}")
                    points[path] = self.capture(path, path.replace("-", "") + "-" + self.attempt)
                    write_json(self.raw / (self.attempt + "-" + path + "-capture.json"), points[path])
                    self.progress(f"Backup/restore capture completed: {path}")
                except (AzureError, RuntimeError, KeyError, StopIteration) as error:
                    for p, target in pending:
                        if p == path:
                            self.result(p + "/" + target, "ERROR", "Capture rejected/failed: " + str(error),
                                        support="exploratory", phase="capture")
                    self.start("cdde-source")
                    self.encrypted_guest("cdde-source")
        if points:
            self.progress("Backup/restore: captures finished; mutating source data for point-in-time validation")
            self.run_stage("mutate", "--bundle", bundle)
        else:
            self.progress("Backup/restore: all selected captures failed; skipping mutation and restore; "
                          "running final source-health checks")
        for index, (path, target) in enumerate(pending, 1):
            if path not in points:
                continue
            self.progress(f"Backup/restore case {index}/{len(pending)}: {path}/{target} restore and verification")
            name = "r-" + path.replace("-", "") + "-" + self.attempt
            try:
                if path == "vm-backup":
                    vm, disk_id, reference = self.restore_vm_backup(points[path], target, name)
                else:
                    disk_id, os_point, reference = self.restored_disk(path, points[path], name + "-" + target)
                    if target == "original":
                        self.swap(disk_id)
                        vm = "cdde-source"
                    else:
                        vm = name
                        if os_point:
                            os_disk = self.az("disk", "create", "-g", self.rg, "-n", name + "-os",
                                "--source", os_point, "--sku", "Premium_LRS")
                            self.create_vm(vm, os_disk=os_disk["id"], data_disks=[self.attachment(disk_id)])
                        else:
                            self.create_vm(vm, data_disks=[self.attachment(disk_id)])
                # Never format a restored disk or manufacture a new LUKS volume.
                # A supported restore must make the original dataset accessible.
                restored = self.vm_wait(vm)
                export = self.raw / (self.attempt + "-" + path + "-" + target + "-restored.json")
                write_json(export, restored)
                case = {"path": path, "target": target, "support": "exploratory",
                    "extension_policy": RECOVERY_EXTENSION_POLICY,
                    "support_reference": "Automated exploratory execution; support not inferred",
                    "target_resource_group": self.rg, "target_vm_name": vm, "target_lun": 0,
                    "target_mount_point": "/cde-data", "restored_disk_id": disk_id,
                    "capture_resource_id": points[path]["id"], "restore_reference": reference,
                    "capture_completed_utc": points[path]["completed"][:19] + "Z",
                    "restore_completed_utc": utc()[:19] + "Z",
                    "capture_evidence_files": [str(self.raw / (self.attempt + "-" + path + "-capture.json"))],
                    "restore_evidence_files": [str(export)]}
                case_file = self.directory / (self.attempt + "-" + path + "-" + target + ".json")
                write_json(case_file, case)
                extension_checks = self.verify_recovery(bundle, case_file, vm)
                base_config = self.write_config(vm, self.attempt + "-" + vm + ".json")
                base = self.suite_command([sys.executable, str(ROOT / "cdde_validation.py"), "conformance", "--config", str(base_config),
                    "--output", str(self.directory / ("restored-conformance-" + self.attempt + "-" + vm))])
                reports = list((self.directory / ("restored-conformance-" + self.attempt + "-" + vm)).glob("*/report.json"))
                status = self.conformance_outcome(base, reports)
                if status == "FAIL":
                    raise RuntimeError("Restored VM conformance (key/RBAC/extension/encryption) failed")
                if self.args.allow_cde306:
                    status = "QUALIFIED"
                self.result(path + "/" + target, status,
                            "Data recovery and all three checkpoints passed with CDE306 exception enabled; not an unqualified PASS"
                            if status == "QUALIFIED" else
                            "Capture, restore, conformance and all three guest checkpoints passed",
                            support="exploratory", case=str(case_file), bundle=str(bundle),
                            extension_policy=RECOVERY_EXTENSION_POLICY, extension_checks=extension_checks,
                            consistency_mode=points[path].get("consistency_mode"),
                            cde306_exception_enabled=self.args.allow_cde306)
            except (AzureError, RuntimeError, KeyError, StopIteration) as error:
                self.result(path + "/" + target, "FAIL" if isinstance(error, VerificationFailure) else "ERROR",
                            str(error), support="exploratory", phase="restore/verify")
            finally:
                if target == "original":
                    try:
                        self.swap(self.state["source_disk_id"])
                    except (AzureError, RuntimeError) as error:
                        self.result("rollback", "ERROR", str(error))
                        raise RuntimeError("Original disk rollback failed; environment retained for recovery") from error
                elif name in self.state.get("owned_vm_names", []) or path == "vm-backup":
                    try:
                        self.stop(name)
                    except AzureError as error:
                        if "ResourceNotFound" not in error.stderr:
                            self.result("deallocate-" + name, "ERROR", str(error))
                        else:
                            print("Replacement VM was not created; no deallocation needed:", name)
        self.conformance(read_only=True)
        self.result("rollback", "PASS", "Original data disk reattached")

    def report(self, display=False):
        tests = [{"id": k, **v} for k, v in self.state["results"].items()]
        if self.state["modes"]["backup_restore"]:
            for path in PATHS:
                for target in TARGETS:
                    key = path + "/" + target
                    if key not in self.state["results"]:
                        tests.append({"id": key, "status": "NOT_EVALUATED",
                                      "message": "Requested recovery case has not completed"})
        counts = {s: sum(t["status"] == s for t in tests) for s in
                  ("PASS", "QUALIFIED", "FAIL", "ERROR", "NOT_EVALUATED")}
        write_json(self.directory / "report.json", {"generated_utc": utc(), "summary": counts,
            "environment": {"subscription": self.sub, "region": self.region, "resource_group": self.rg,
                            "vm_size": self.state.get("vm_size")},
            "last_recovery_paths": self.state.get("last_recovery_paths"), "tests": tests})
        lines = ["# Automated CDDE test run", "", f"- Resource group: `{self.rg}`",
                 f"- Results: {counts}", "", "| Test | Result | Details |", "|---|---|---|"]
        lines += [f"| {t['id']} | {t['status']} | {t['message'].replace('|', '/').replace(chr(10), ' ')} |" for t in tests]
        (self.directory / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        suite = ET.Element("testsuite", name="Azure.CDDE.Automated", tests=str(len(tests)),
                           failures=str(counts["FAIL"]), errors=str(counts["ERROR"]),
                           skipped=str(counts["QUALIFIED"] + counts["NOT_EVALUATED"]))
        for test in tests:
            case = ET.SubElement(suite, "testcase", name=test["id"])
            if test["status"] in ("NOT_EVALUATED", "QUALIFIED"):
                ET.SubElement(case, "skipped", message=test["message"])
            elif test["status"] != "PASS":
                ET.SubElement(case, "failure" if test["status"] == "FAIL" else "error",
                              message=test["message"])
        ET.ElementTree(suite).write(self.directory / "junit.xml", encoding="utf-8", xml_declaration=True)
        # SSH private key and tokens must never be promoted into evidence.
        checksums = []
        for file in sorted(self.directory.rglob("*")):
            if file.is_file() and file.name not in ("ssh-key", "SHA256SUMS") and not file.name.endswith(".tmp"):
                checksums.append(hashlib.sha256(file.read_bytes()).hexdigest() + "  " + str(file.relative_to(self.directory)))
        (self.directory / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
        if display:
            for test in tests:
                if test["status"] == "NOT_EVALUATED":
                    print(f"[NOT_EVALUATED] {test['id']}: {test['message']}", flush=True)
            self.progress("Final results: " + ", ".join(f"{count} {status}" for status, count in counts.items()))
        return bool(tests) and counts["QUALIFIED"] + counts["FAIL"] + counts["ERROR"] + counts["NOT_EVALUATED"] == 0

    def destroy(self):
        # Never delete a user-supplied/existing resource group.
        exists = self.az("group", "exists", "-n", self.rg)
        if exists:
            group = self.az("group", "show", "-n", self.rg)
            if group.get("tags", {}).get("cdde-test-run") != self.state["token"]:
                raise RuntimeError("Ownership tag mismatch; resource deletion refused")
        if exists and "vm-protection" in self.state["steps"] and self.state.get("vm_item"):
            self.az("backup", "protection", "disable", "-g", self.rg, "--vault-name", "cdde-rsv",
                "--container-name", self.state["vm_container"], "--item-name", self.state["vm_item"],
                "--backup-management-type", "AzureIaasVM", "--delete-backup-data", "true", "--yes")
        if exists and self.state.get("disk_instance"):
            self.az("dataprotection", "backup-instance", "delete", "-g", self.rg,
                "--vault-name", "cdde-bv", "-n", self.state["disk_instance"], "--yes")
        if exists:
            self.az("group", "delete", "-n", self.rg, "--yes")
        if self.state.get("custom_role_id"):
            self.az("role", "definition", "delete", "--name", self.state["custom_role_id"].rsplit("/", 1)[1])
        self.state["destroyed"] = True
        self.save()
        (self.directory / "ssh-key").unlink(missing_ok=True)
        print("Owned environment deleted. Vault soft delete/purge protection may retain deleted assets.")

    def disposition(self):
        decision = self.args.retention
        if decision == "ask":
            if not sys.stdin.isatty():
                raise RuntimeError("Retention decision requires interactive input. Environment retained; "
                                   "use --retention retain or --retention destroy for unattended runs.")
            while True:
                answer = input("Retain environment for revalidation, or destroy it? [retain/destroy]: ").strip().lower()
                if answer in ("retain", "destroy"):
                    decision = answer
                    break
                print("Enter retain or destroy.")
        if decision == "destroy":
            self.destroy()
        else:
            self.state["retained_utc"] = utc()
            self.save()
            print("Retained. Revalidate failed tests with:")
            selector = (" --recovery-paths " + " ".join(self.args.recovery_paths)
                        if self.args.recovery_paths else "")
            if self.args.allow_cde306:
                selector += " --allow-cde306"
            print(f"python3 ./run-cdde-tests.py --resume {shlex.quote(str(self.directory))} --retry-failed{selector}")


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subscription-id")
    parser.add_argument("--region")
    parser.add_argument("--vm-size", help="Optional eligible confidential v6 override")
    parser.add_argument("--image", default=IMAGE, help="Optional confidential Linux image URN")
    parser.add_argument("--disk-size-gb", type=int, default=4)
    parser.add_argument("--lifecycle", action="store_true")
    parser.add_argument("--fail-closed", action="store_true")
    parser.add_argument("--backup-restore", action="store_true")
    parser.add_argument("--allow-cde306", action="store_true",
                        help="Allow only evidenced CDE306 extension-health failures for recovery validation; "
                             "results are QUALIFIED, never an unqualified PASS")
    parser.add_argument("--recovery-paths", nargs="+", choices=PATHS,
                        help="Recovery paths to execute this attempt; defaults to all four. "
                             "Excluded paths keep their previous results.")
    parser.add_argument("--resume", help="Retained run directory containing state.json")
    parser.add_argument("--reuse-vm-backup-point",
                        help="Explicit completed vault-tier recovery point; skips prepare and backup-now")
    parser.add_argument("--recovery-bundle", help="Original, unmutated prepared bundle for explicit backup reuse")
    parser.add_argument("--retry-failed", action="store_true")
    parser.add_argument("--cleanup", action="store_true", help="Destroy an owned retained environment without rerunning tests")
    parser.add_argument("--retention", choices=("ask", "retain", "destroy"), default="ask")
    parser.add_argument("--output", default=str(ROOT / "evidence"))
    parser.add_argument("--timeout", type=int, default=7200, help="Maximum wait per operation, seconds")
    parser.add_argument("--rbac-wait", type=int, default=600)
    args = parser.parse_args()
    if (args.cleanup or args.retry_failed) and not args.resume:
        parser.error("--cleanup and --retry-failed require --resume")
    if args.allow_cde306 and not (args.backup_restore or args.resume):
        parser.error("--allow-cde306 requires a recovery run")
    if args.timeout <= 0 or args.rbac_wait < 0:
        parser.error("Timeout must be positive and RBAC wait non-negative")
    if args.reuse_vm_backup_point or args.recovery_bundle:
        if (not args.reuse_vm_backup_point or not args.recovery_bundle or not args.resume or
                not args.retry_failed or args.recovery_paths != ["vm-backup"] or args.cleanup or
                args.lifecycle or args.fail_closed or args.backup_restore):
            parser.error("Backup reuse requires --resume, --retry-failed, --recovery-paths vm-backup, "
                         "--reuse-vm-backup-point and --recovery-bundle; do not combine with "
                         "--cleanup, --lifecycle, --fail-closed or --backup-restore")
    if args.disk_size_gb < 4 or len(args.image.split(":")) != 4:
        parser.error("Disk size must be at least 4 GiB; image must be a four-part URN")
    return args


def main():
    args = arguments()
    if not sys.platform.startswith("linux"):
        print("ERROR: Run this entry point inside Linux/WSL.", file=sys.stderr)
        return 2
    tools = ["az"] + ([] if args.resume else ["ssh-keygen"])
    missing = [tool for tool in tools if not shutil.which(tool)]
    if missing:
        print("ERROR: Missing required tools: " + ", ".join(missing) +
              ". Install them explicitly, then run az login. See README.md.", file=sys.stderr)
        return 2
    try:
        lab = Lab(args)
    except (RuntimeError, ValueError, OSError, EOFError) as error:
        print("ERROR: Cannot initialize run:", error, file=sys.stderr)
        return 2
    print("Run state and evidence:", lab.directory)
    print("This run creates billable resources. New VMs use Standard public IPs; "
          "SSH ingress is not opened. Retained labs keep their existing networking.")
    try:
        try:
            lab.az("account", "show")
        except AzureError:
            subprocess.run(["az", "login", "--use-device-code"], check=True)
        if args.cleanup:
            lab.destroy()
            lab.report()
            return 0
        lab.provision()
        if "vm-protection" in lab.state["steps"]:
            lab.progress("Checking for Azure backup jobs left running by an interrupted attempt")
            lab.wait_for_vm_backups()
        if args.resume:
            lab.progress("Ensuring the retained source VM is running before source-health checks")
            lab.start("cdde-source")
        previously_passed = lab.state["results"].get("conformance", {}).get("status") in ("PASS", "QUALIFIED")
        lab.conformance(read_only=args.retry_failed and previously_passed)
        if lab.state["modes"]["backup_restore"]:
            lab.backup_restore()
    except (AzureError, RuntimeError, KeyError, StopIteration, subprocess.CalledProcessError, KeyboardInterrupt) as error:
        lab.result("execution", "ERROR", str(error) or "Interrupted; inspect retained state before retry")
    else:
        lab.state["results"].pop("execution", None)
        lab.save()
    passed = lab.report()
    try:
        lab.disposition()
    except (AzureError, RuntimeError, KeyboardInterrupt, EOFError) as error:
        lab.result("cleanup", "ERROR", str(error) or "Retention selection interrupted; resources retained")
    else:
        lab.state["results"].pop("cleanup", None)
        lab.save()
    passed = lab.report(display=True)
    print("Evidence:", lab.directory / "summary.md")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
