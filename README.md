# Fully automated CDDE test lab

The recommended entry point for a **new disposable environment** is
`python3 ./run-cdde-tests.py`. It provisions its own resources, runs the CDDE
validator, and optionally performs lifecycle, SKR denial and backup/restore
testing. No configuration file, manually created VM, manually configured backup vault,
or manually executed restore is required.

For customers who prefer to execute and inspect each Azure CLI operation, use the
[manual test suite](MANUAL-TEST-SUITE.md). It covers fresh provisioning,
conformance, optional disruptive lifecycle/SKR-denial tests, and all four
exploratory backup/restore paths without invoking the Python runner.

## Runtime files

This folder contains the automated runner and an optional diagnostic collector:

| File | Purpose |
|---|---|
| [run-cdde-tests.py](run-cdde-tests.py) | Single user entry point: provisioning, orchestration, recovery, reporting and cleanup |
| [cdde_validation.py](cdde_validation.py) | Python conformance, lifecycle, fail-closed and recovery validators |
| [collect-cdde-logs.py](collect-cdde-logs.py) | Optional diagnostic log archive collection from existing VMs |
| [DataDiskSKRPolicy.json](DataDiskSKRPolicy.json) | Secure Key Release policy required when creating the encryption key |
| [MANUAL-TEST-SUITE.md](MANUAL-TEST-SUITE.md) | Customer-operated Azure CLI test cases, expected results, evidence and cleanup |
| [README.md](README.md) | Run instructions and operational safeguards |

Keep the Python files together. The controller invokes the validators
using the same Python interpreter. No local Bash scripts are required.
The runner generates JSON configuration profiles, request payloads and case
manifests inside each evidence bundle.
Manual setup/configuration examples are in the separate manual test suite.
Offline regression tests are not included in this repository.

The generated `evidence/` directory is local output, not an
input required for a new deployment. It is required to inspect or resume a
retained run. Do not resume a lab that was deleted through the portal, even if
its historical local state still says it was retained.

## Run from Linux / WSL

```bash
python3 ./run-cdde-tests.py \
  --subscription-id "<subscription-id>" \
  --region uaenorth \
  --lifecycle --fail-closed --backup-restore
```

If subscription or region is omitted, the script prompts for that value.
Authentication remains necessary: it starts `az login --use-device-code` if
Azure CLI cannot access the requested subscription.

Install these prerequisites explicitly before running:

- Python 3.10 or later.
- [Azure CLI for Linux](https://learn.microsoft.com/cli/azure/install-azure-cli-linux),
  available as `az`, with permission to sign in to the intended tenant.
- OpenSSH's `ssh-keygen` for new lab deployments. Retained-run operations do not
  require it.

The Python application uses only the standard library; there is no pip
requirements file. It checks for missing tools and stops with an explicit
diagnostic rather than installing system software or running sudo. Selected
backup modes still install their required Azure CLI extensions as before.
Local `jq`, `sha256sum`, `curl`, and Bash are no longer application dependencies.
JSON, checksums, timestamps, XML, configuration and report generation run in
Python.

Linux shell payloads are still submitted to the VM using Azure Run Command for
`cryptsetup`, mounts, filesystem metadata and integrity checks. Those commands
run inside the Linux guest, not through a local Bash subprocess; guest Python
is not required by the validators.

The application does not silently change the active Azure subscription;
subscription-scoped commands explicitly select the requested subscription.
Local CLI extension management does not accept `--subscription` and omits it.
Directory lookup uses Microsoft Graph through `az rest` with the requested
subscription, so authentication uses that subscription's tenant.

**Executing this command authorizes creation of billable lab resources and the
selected disruptive tests.** The signed-in principal must already have permission
to register resource providers, create resources and assign roles. Backup
testing additionally needs permission to create a narrowly scoped custom key
backup role, read the Backup Management Service principal and register the
self-service restore-point preview feature if needed. CDDE enrollment must
already be approved; its feature does not support self-service registration.
The script cannot
grant itself permissions that its caller does not have. Azure Policy, quota or
preview enrollment rejections are collected as errors, not bypassed.

## Modes

| Flags | Provisioning and tests |
|---|---|
| No test flags | Fresh confidential v6 VM, identity, Premium Key Vault/key, confidential DES, encrypted data disk, network and conformance checks |
| `--lifecycle` | Synthetic integrity testing across restart, deallocate/start and extension reapplication |
| `--fail-closed` | Temporary CDDE disk, exact release-role removal, first-time SKR denial, role restoration and integrity recovery |
| `--backup-restore` | All four capture/restore paths, each to the original and a replacement CVM |

Flags can be combined. Backup vaults, the staging storage account and replacement
VMs are created only when backup/restore is selected.

### Automatic defaults

- **VM size:** query regional resource SKUs and subscription usage/quota; choose
  the smallest unrestricted confidential DC/EC v6 size by vCPU count, then RAM,
  then name. Quota counts are normalized from integers or numeric strings;
  invalid counts stop provisioning with an explicit error rather than assuming
  available capacity. Ordinary D/E v6 sizes and v5 are excluded.
- Backup mode reserves selection headroom for two simultaneous VMs. Recovered
  replacement VMs are deallocated after their case to release allocated cores.
  Two 2-vCPU VMs require at least 4 remaining vCPUs in both the chosen SKU family
  and the regional quota. Selection errors report required and remaining quota.
- **Region:** the requested region only; no hidden region fallback.
- **Image:** Ubuntu 22.04 confidential image
  `Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest`.
- **Resources:** uniquely named, run-owned resource group; 4 GiB data disk;
  `/cde-data`; LUN 0; same-region identity, key and DES.
- **Key:** RSA-HSM 3072, exportable only through SKR, using the packaged
  [release policy](DataDiskSKRPolicy.json).
- **Network:** `az vm create --public-ip-sku Standard` creates the NIC and Standard public IP,
  with automatic VNet/subnet creation on the first VM. The VM public IP provides
  outbound connectivity; no separate NAT gateway is provisioned. The lab names
  the shared network `cdde-network` and subnet `workloads` for recovery targeting.
  The automation uses `--nsg-rule NONE`:
  no SSH ingress rule is opened because tests use Azure Run Command, not SSH.
  Standard public IPs incur cost. Azure VM Backup creates its own replacement
  VM networking through the alternate-location restore service; the CLI
  creation flags above apply only to VMs created directly by the script.
- **Waits:** bounded service polling, 600-second provisioning RBAC propagation
  wait, guest readiness checks and the existing fail-closed propagation waits.

Overrides include `--vm-size`, `--image`, `--disk-size-gb`, `--timeout`,
`--rbac-wait` and `--output`. A size override is still checked for v6 eligibility,
regional restrictions and quota. A supported size/image listing does not prove
capacity or CDDE compatibility: creation can still fail and is reported.

### Provisioning sequence

The automated source lab provisions Premium RBAC Key Vault with the packaged
Secure Key Release policy; it does not provision Managed HSM:

1. Register providers, verify existing CDDE enrollment, register the
   restore-point feature only if backup/restore is selected and it is not yet
   registered, check the confidential image and choose the smallest eligible
   v6 SKU with sufficient quota.
2. Create the run-owned resource group and Premium RBAC Key Vault with purge
   protection; grant the operator Key Vault Crypto Officer.
3. Create the exportable RSA-HSM 3072 key using the packaged SKR policy and
   verify that `releasePolicy.encodedPolicy` is non-empty.
4. Create the user-assigned identity and confidential DES; assign the required
   Key Vault encryption/release roles and wait for propagation.
5. Create the confidential VM using `az vm create`, Secure Boot, vTPM,
   `DiskWithVMGuestState` and a Standard public IP.
6. PATCH the VM identity and CDDE identity field with Compute API `2026-03-01`;
   then PATCH the data-disk attachment with its CDDE security profile and DES.
   Wait for each VM operation before proceeding.
7. Format only the new source disk as ext4, mount it at `/cde-data`, then install
   `CDELinux` 1.0 with a fresh `sequenceVersion`.
8. Run the selected conformance, lifecycle, fail-closed and recovery tests.

The v6 size selection, small test disk, generated deployment SSH public key,
closed SSH ingress and resume safeguards are deliberate automation adaptations.
Recovered disks are attached, never formatted. Resuming a retained lab does not
replace its existing network or remove a NAT gateway from an older run; start a
new run to exercise the revised provisioning topology.

The script registers required resource providers and checks the state of
`Microsoft.Compute/ConfidentialVMDataDiskEncryptionPreview`. Already-registered
features are not registered again. CDDE does not support self-service feature
registration: a state other than `Registered` stops provisioning with an
explicit enrollment error directing the operator to Microsoft support.
The script cannot grant preview access.

For backup/restore, the separate
`Microsoft.Compute/RestorePointSupportForConfidentialVMV2` feature is
[documented as self-service and auto-approved](https://learn.microsoft.com/azure/virtual-machines/concepts-restore-points#confidential-virtual-machines-preview).
If it is not registered, the script requests registration, polls up to the
configured timeout and re-registers the Compute provider to propagate the change.
Registration failures remain explicit errors, not assumed support.
Provider/feature registrations are subscription-level changes and are not
unregistered during cleanup.

## Automated backup/restore flow

### Reusing a completed VM backup after a capture-wait timeout

An explicit reuse invocation can continue with the original prepared dataset
without another `prepare` or `backup-now`:

```bash
python3 ./run-cdde-tests.py \
  --resume "$RUN" --retry-failed --recovery-paths vm-backup \
  --reuse-vm-backup-point "$RECOVERY_POINT_NAME" \
  --recovery-bundle "$ORIGINAL_PREPARED_BUNDLE" \
  --allow-cde306 --timeout 14400 --retention retain
```

Set the three variables to the retained run directory, the exact Recovery
Services recovery-point name, and the original prepared bundle respectively.
This is restricted to a retained VM Backup retry; it cannot be combined with
cleanup or newly requested conformance/lifecycle modes. Successful cases remain
skipped under the usual retry and CDE306 rules.

The runner requires an unmutated bundle registered in that run, matching source
VM/disk/subscription/mount/LUN, valid bundle checksums, a point belonging to the
source backup item, a valid vault tier, and a capture timestamp after dataset
preparation. Before mutation it verifies the live source dataset using the
same LUKS, ancestry, directory, marker, hash and permission checks as recovery.
The helper's `check-source` stage is read-only with respect to guest data.
Any failed prerequisite stops reuse; there is no silent new capture or
substitution of another recovery point. The original capture timestamp and
explicit recovery-point ID are preserved in new case evidence.

Reuse then performs the normal mutation/fence, restore, three integrity
checkpoints, restored conformance, data-disk rollback and source-health checks.
It is not a validation-only command: original-location recovery replaces the
source VM's OS/data disks, and rollback restores the original data disk, not
the pre-restore OS disk. Azure may create a preservation backup as part of that
restore. Use only on the retained disposable lab, with no other controller
running. Once mutation has succeeded, this reuse command refuses the bundle
on another invocation; inspect recovery/evidence rather than repeating writes.
Historical unrelated errors and qualified results remain in the aggregate
report, so overall exit status alone does not determine this case's outcome.

### Console progress and evidence

The controller prints flushed UTC-timestamped progress for provisioning steps,
safe Azure CLI operation names (not arguments, tokens or key contents), reused
steps, capture/restore phases and each verification checkpoint. RBAC propagation
waits report the remaining time every 60 seconds; service polling reports
elapsed waiting time at least every 60 seconds between responses. Blocking Azure
CLI calls announce their operation before execution and elapsed duration on
completion; they do not stream raw CLI output to the console.

Backup job polling prints the server-reported status, duration, task statuses
and percentage when Azure provides one. It does not fabricate a percentage or
ETA when the service returns null. Terminal failures include available service
error details; polling timeouts include the last observed job state. The default
`--timeout` is 7200 seconds per service wait, not a guarantee of backup duration.

VM PATCH requests retry only the explicit Azure
`ConflictingConcurrentWriteNotAllowed` error: up to four retries with
15/30/60/60-second delays and VM readiness polling before each retry. The same
request body is reused and every CLI attempt remains in raw evidence. Other
conflicts, authorization failures and invalid requests are not silently retried.
VM deallocation also waits for provisioning readiness before subsequent writes.

The 39-check conformance/lifecycle/fail-closed suite runs **before** backup/restore.
Recovery first prepares a synthetic dataset, then captures all four paths and
validates each against the original and replacement VMs. If preparation fails,
no backup/restore capture has run: the final console summary and reports show
the eight requested cases as `NOT_EVALUATED`, not PASS. Stage errors identify
`prepare`, `mutate` or `verify` and the relevant evidence location. Guest storage
and fixture failures include a `RECOVERY_FAILED_STEP` diagnostic marker.
Guest-agent readiness reads `instanceView.vmAgent.statuses` from
`az vm get-instance-view`, not the VM's ARM `provisioningState`. The waiting
message includes agent status details, and successful guest encryption/data
checks are still required after the agent reports Ready.

### Execution sequence

1. Pass source conformance (and other selected modes).
2. Prepare a synthetic recovery dataset and its hashes/permissions manifest.
3. Capture direct data-disk snapshot, VM restore point using the default capture mode,
   Azure Disk Backup recovery point and Azure VM Backup recovery point.
4. Wait for operation/job completion; capture explicit service rejections.
5. Change source checkpoint data after all available captures, then replace the
   active Run Command with a completed read-only fence before any restore.
6. Restore each available path to the original and a replacement VM.
7. Validate exact restored disk, original/replacement target, confidential
   settings, CDDE identity/DES, LUKS2/dm-crypt, LUN ancestry, file hashes,
   ownership/permissions, point-in-time marker and recovered-volume I/O.
8. Perform and verify restart and deallocate/start checkpoints.
9. Run the existing conformance suite against each recovered VM.
10. Roll back the original data disk and check source health.

The post-mutation fence is mandatory: replacing the original VM's OS disk can
rewind the guest agent state and cause the active Run Command configuration to
execute again on boot. If the mutation script is still active, it can recreate
`after-capture.txt` on correctly restored data. The mutation stage now leaves a
harmless command active, saves `raw/mutation-fence.*` and `mutation-fenced.json`,
and fails explicitly if fencing does not complete. `mutated.json` is written
before fencing so a failed fence cannot lead to silently repeating mutation.
This prevents an observed test-induced contamination path; it does not waive
the marker/hash checks or retroactively turn earlier failures into PASS.

The paths are not substituted:

- **Direct snapshot:** new data disks reconstructed from a full (non-incremental) snapshot, attached
  separately to original and fresh CVM. The source is deallocated for capture.
  The direct path requests a full snapshot explicitly, not an incremental
  snapshot. This does not
  establish full-snapshot CDDE support; creation and recovery must still pass.
- **VM restore point:** disk restore point reconstruction. The replacement CVM
  uses the restored OS disk as well as the restored CDDE data disk. The original
  target case is **data-disk recovery on the original VM**, not a claim of
  full original-location VM reconstruction.
  Confidential VM creation supplies OS-disk encryption type
  `DiskWithVMGuestState` for both image-based and restored-OS attachment paths;
  the CLI requires this argument even when attaching an existing OS disk.
  The captured CDDE data disk is identified by its exact source managed-disk ID,
  not by `lun`, which may be absent from restore-point metadata. Azure's actual
  `consistencyMode` is recorded in capture evidence and case results.
  `FileSystemConsistent` does not establish application-consistent recovery.
  The create request omits an explicit consistency mode and uses the Compute
  API's default capture behavior.
- **Azure Disk Backup:** Backup vault, operational snapshot protection, new-disk
  restore and attachment. It is not vaulted disk protection or service OLR.
  The current vault API requires `--soft-delete-state AlwaysOn`; the lab uses a
  system-assigned identity and a 14-day soft-delete retention period. Always-On
  soft delete cannot later be disabled. Deleted backup data remains retained,
  so immediate complete cleanup cannot be promised and retained data may incur
  charges. The script does not downgrade the API or disable this protection.
- **Azure VM Backup:** Recovery Services vault, Enhanced/V2 policy, original-
  location recovery and alternate-location full-VM recovery using the service's
  restore operation. It is not silently replaced with a fresh OS VM.

Restored disks are never formatted. Recovery uses the **check-first-v1**
extension policy:

- Inspect extension inventory, configuration and instance-view health before
  requesting any extension changes.
- Leave a healthy CDELinux extension and its `sequenceVersion` unchanged.
- Wait, with the operation timeout, for in-progress extension processing rather
  than requesting another enable.
- Preserve failed or invalid existing extensions without repairing, reinstalling
  or assigning a new sequence. Strict validation stops that case; only an
  explicitly allowed, evidenced CDE306 can continue as qualified diagnostics.
- Install CDELinux once only when the initial inventory proves it absent.
  A new replacement VM may have no ARM extension resource even when its restored
  OS contains cached handler files. Record this installation as an intervention,
  not a restore-only reproduction.
- Inspect health again after restart and deallocate/start, without reapplying
  the extension. A disappearing extension is a failure, not an invitation to
  reinstall it.

Each attempted check saves
`raw/<case>-<checkpoint>-extension-decision.json`, inventory and before-status
evidence, plus after-installation or settled-status evidence when applicable.
The decision records `extension_set_requested`, the action, health and any error
or CDE306 exception. Successful case results include `extension_policy` and
`extension_checks`. Existing historical results are not relabeled.

EXT-002 remains read-only and now also rejects failed/error component statuses
even if the top-level status reports success. An initial mount of an existing
decrypted mapper is allowed; later lifecycle checkpoints must remount normally.
No manual key export, plaintext conversion or re-encryption of lost data is used
to fabricate a successful recovery.

### Fresh status-first restore-point comparison

To test this path independently, start a new retained lab:

```bash
python3 ./run-cdde-tests.py \
  --subscription-id "<subscription-id>" --region uaenorth \
  --backup-restore --recovery-paths restore-point \
  --retention retain
```

Do not add `--lifecycle`, `--fail-closed` or `--allow-cde306` to this strict
comparison. The separate opt-in lifecycle and fail-closed suites still
intentionally reapply the extension; the recovery policy does not change those
tests. `--retry-failed` preserves earlier successful cases, so it is not a clean
comparison with the old policy. Do not resume a lab whose cleanup partially
deleted its resources.

Read the decision evidence to distinguish an existing failure before any
extension write, a failure after a necessary initial installation, and a failure
after a boot checkpoint. This records ordering; it does not by itself prove a
root cause or guarantee that CDE306 will reproduce.

**Support is exploratory:** general CVM backup documentation does not establish
CDDE backup/restore support. The automation executes the paths and records actual
service responses. Rejections are ERROR,
guest integrity/encryption assertion failures are FAIL, and cases never reached
are NOT_EVALUATED. Exploratory PASS is evidence of the tested behavior, not a
support commitment.

The round does not establish application-consistent database recovery, cross-
region/tenant recovery, all restore tiers, emergency revocation semantics or
replacement-key recovery. VMGS/CVM reconstruction uses the platform restore
operations; successful guest recovery is not a separate attestation audit of
VMGS.

## Retain or destroy

At the end, including after a reported failure, the default question is:

```text
Retain environment for revalidation, or destroy it? [retain/destroy]:
```

### Retain and revalidate failures

```bash
python3 ./run-cdde-tests.py \
  --resume "./evidence/auto-<run-id>" \
  --retry-failed
```

### Recovery validation with the optional CDE306 exception

Once the subscription has the required feature access, validate the two paths
separately:

```bash
python3 ./run-cdde-tests.py \
  --resume "./evidence/auto-<run-id>" \
  --retry-failed --recovery-paths restore-point --allow-cde306
```

Then, after that invocation finishes and the source is rolled back:

```bash
python3 ./run-cdde-tests.py \
  --resume "./evidence/auto-<run-id>" \
  --retry-failed --recovery-paths vm-backup --allow-cde306
```

Run only one controller against this lab at a time and choose `retain` between
invocations. Each path prepares a fresh dataset and capture, mutates the source,
then restores to original and replacement targets and verifies all three guest
checkpoints. These commands perform disruptive, billable recovery operations;
the second command starts a new server-side VM Backup job.

`--allow-cde306` is opt-in on each invocation and is not a global test bypass.
It permits conformance to continue only when EXT-002 is the sole failed test
and the saved extension response reports Failed with all error/failure statuses
ending in `/failed/306` and an explicit `[CDE306]` message. Other test failures,
missing reports, authorization errors and other extension errors still block.
Existing failed extensions are never reprocessed to clear the error. If a
necessary initial installation fails, its live instance view must meet the same
narrow CDE306 check and the CLI error must be `VMExtensionProvisioningError`
before guest validation continues. All original raw
responses and failed child reports remain unchanged.

With the exception enabled, completed recovery cases are `QUALIFIED`, never
unqualified `PASS`, even if final extension health later becomes clean. All
encryption, exact restored-disk identity, point-in-time dataset integrity,
permissions, I/O and boot checkpoint checks remain mandatory. The qualified
case records `cde306_exception_enabled` and actual restore-point consistency.
The aggregate JSON/Markdown counts qualified results separately, JUnit marks
them skipped, and the overall exit code remains nonzero while qualifications,
errors or unevaluated cases exist. Previous excluded-path errors remain visible.
`--retry-failed --allow-cde306` skips already qualified cases; omitting the
exception causes qualified cases to be retried under strict criteria.

The exception does not resolve CDE306, establish its root cause, or
establish full feature support. VM Backup capture and service restore contracts
still require live validation with the required feature access; service rejections are not
waived. No recovery operations are launched merely by updating this script.

If VM Backup reports `BMSUserErrorDataSourceInDeferredDeleteState`, the protected
item is soft-deleted; this is not a CDDE recovery rejection. Wait for the current
controller to finish its final source-health checks and choose `retain`. In
Recovery Services vault `cdde-rsv`, inspect the soft-deleted Azure VM backup item
for `cdde-source`. An authorized operator must undelete the item and resume
backup using policy `cdde-enhanced` before retrying VM Backup. Undelete alone
does not resume scheduled protection. Do not disable soft delete, purge data,
or run a second controller while the first is active.

Protection state is queried live even on resume. Soft-deleted or stopped
protection blocks backup capture with an explicit diagnostic; the script never
automatically undeletes or resumes stopped protection. Other initializing states
are polled until the item is `Protected` or `IRPending` with a nonempty policy
ID. `IRPending` means the initial recovery point is pending; it permits the first
backup request, but is not evidence that backup or recovery has succeeded. If all
selected captures fail, source-data mutation and restore are skipped, while
final health checks and rollback reporting still run. These changes apply to
new invocations, not a controller that was already running when updated.

### VM Backup restore authorization

Before preparing or mutating the source dataset for a VM Backup run, setup
enables the Recovery Services vault's system-assigned managed identity and
ensures these role assignments:

| Vault identity role | Scope |
|---|---|
| VM Restore Operator (preview) | Owned lab resource group, including its VNet and staging storage account |
| Managed Identity Operator | Exact CDDE VM user-assigned identity |
| Reader | Exact CDDE disk encryption set |

VM Restore Operator covers the VM/disk/network create, update, delete and
staging-storage operations used by service restore. Its permissions do not
include assignment of the VM's user-assigned identity or reading the disk
encryption set; the two resource-scoped grants cover those linked dependencies.
No subscription-wide Contributor/Owner grant or additional Key Vault key-release
permission is given to the vault identity. The existing CDDE VM identity still
performs guest Secure Key Release.

Setup requires permission to enable the vault identity and create these RBAC
assignments. It queries live assignments, repairs missing grants, waits for
assignment visibility and the configured RBAC propagation delay, and saves the
verified principal/scopes in run state. Read-only authorization checks repeat
immediately before each service restore, before deallocating the source VM.
Saved provisioning steps do not bypass these checks. Restore requests explicitly
use `--mi-system-assigned` to select the vault identity, not the CDDE VM identity.
RBAC assignment visibility is a prerequisite check, not a guarantee against
service-side propagation delay, deny policies, or preview support restrictions.

`CompletedWithWarnings` remains an error; it is never accepted as a successful
restore or a reason to manufacture a VM manually. Generated create/cleanup
templates are evidence only. Do not deploy cleanup templates without inspecting
their exact targets and confirming that no retained/source resource is attached.
After failed restore, disks, NICs, public IPs or staging artifacts may remain.
The test suite retains this evidence and does not automatically delete it.

To retry only direct-snapshot recovery against both original and replacement
VMs without launching another VM Backup or VM restore-point capture:

```bash
python3 ./run-cdde-tests.py \
  --resume "./evidence/auto-<run-id>" \
  --retry-failed --recovery-paths snapshot
```

`--recovery-paths` accepts one or more of `snapshot`, `restore-point`,
`disk-backup`, `vm-backup`. Omit it to attempt all four paths. It filters only
this invocation, not the saved full test scope. Excluded paths retain previous
results, or remain `NOT_EVALUATED` if never completed. The aggregate report and
exit status still reflect the full requested suite, so a snapshot-only pass does
not hide previous backup errors. The report records `last_recovery_paths`.
Printed resume commands preserve an explicit selector.

The selector requires `--backup-restore` for a new run, or a retained run with
backup/restore already enabled. It skips restore-point feature registration
when neither VM restore points nor VM Backup is selected. Active Azure backups
are still checked before any disruptive operations; filtering paths does not
cancel existing jobs or bypass that safety check.

The retained state supplies subscription, region, selected size and resource
identifiers. No resource names need to be re-entered. Completed provisioning
steps are reused. Source health is checked, failed conformance groups rerun, and
only failed/missing recovery path/target cases are retried.
Saved VM size selection skips the expensive SKU listing and selection quota
queries on resume. Image availability is recorded once and is not queried for
an already-provisioned source VM, including labs saved by older script versions.
Authentication, enrollment, ownership, active backup jobs and source health
remain live checks. Saved selection does not reserve quota or guarantee capacity
for later replacement VM creation; Azure allocation errors remain explicit.

Recovery retries prepare a new synthetic dataset/capture generation on the
retained source so they cannot accidentally validate changed data against an
old manifest. Previously successful case evidence remains available.

Stopping the local process does **not** cancel an Azure backup/restore job.
On resume, an already-protected lab checks and waits for active VM backup jobs
before running tests that may restart, deallocate, swap disks or change synthetic
data. It queries the server-side jobs rather than assuming the interruption
stopped them. A failed active job is reported with its service error; jobs are
not automatically canceled. The VM Backup capture also checks for active jobs
before requesting another backup. Retries still require a fresh capture of the
new dataset; they do not treat a previous attempt's recovery point as its backup.
Resume starts the retained source VM after the active-backup check and before
source-health validation, including when a failed disk swap left it deallocated.

Without `--retry-failed`, the selected suites run again in the retained lab.
Additional test flags can enable new modes on a retained run. Ownership tags
are checked before provisioning changes and deletion.

### Destroy later

```bash
python3 ./run-cdde-tests.py --resume "./evidence/auto-<run-id>" --cleanup
```

Deletion targets only the run-owned resource group and the custom role created
for this run. Backup protection is disabled/deleted before group deletion.
Local evidence remains. The script does not purge Key Vault or bypass backup
soft-delete/retention safeguards.

Azure-managed recovery artifacts and retention policies may prevent immediate
complete deletion or retain deleted data/names. Cleanup errors are explicit;
the run is not marked destroyed if its cleanup fails. Service-managed resources
outside the owned group are not blindly deleted. Review the service response
and retained evidence before retrying cleanup.

For unattended execution, specify `--retention retain` or `--retention destroy`.
With the default `ask` and no interactive stdin, resources are retained and a
retention-decision error is reported; there is no silent deletion.

## Collect CDDE diagnostic log archives

The optional collector archives **only**
`/var/log/azure/Microsoft.Azure.Security.ConfidentialDiskEncryption.CDELinux`
from each named VM. It does not reinstall/re-enable CDDE, change its settings,
restore disks, or run the test suites. Do not run tests or other Run Commands
against these VMs concurrently.

For an existing lab, run inside Linux / WSL, replacing the placeholders with
your subscription, resource group and VM names:

```bash
az login

python3 ./collect-cdde-logs.py \
  --subscription "<subscription-id>" \
  --resource-group "<resource-group>" \
  --vms "<source-vm-name>" "<restored-vm-name>" \
  --allow-temporary-resources
```

No SSH access or local `curl` is required. The collector uses Python 3.10+,
Azure CLI and the accompanying `cdde_validation.py`. Each guest needs a
functioning Azure VM Agent, `tar`, `gzip`, `curl`, `sha256sum`, `stat` and
`mktemp`, plus outbound HTTPS connectivity to Azure Storage. Missing guest
tools cause an explicit failure; nothing is installed automatically.
The signed-in identity needs VM read/start/stop/deallocate/Run Command
permissions and permission to create/delete a storage account and list its
keys in the specified resource group.

`--allow-temporary-resources` authorizes these operations and their costs:

1. Record each VM's original power state. Start stopped/deallocated VMs only
   for collection. **Starting a VM can change the currently observed CDDE
   failure state and append logs**, even though the collector does not
   explicitly re-enable CDDE.
2. Create a uniquely tagged `cddelogs...` Standard_LRS StorageV2 account in the
   lab resource group. Anonymous blob access is disabled, HTTPS/TLS 1.2+
   is enforced, and the container is private. This uses an authenticated
   public HTTPS endpoint, **not a Private Endpoint**.
3. Use a two-hour, per-blob create/write-only SAS for guest uploads.
   Account keys are held in process memory and passed to storage CLI
   commands through their environment, not command arguments.
   Upload scripts are passed through private temporary files rather than
   putting SAS URLs in CLI command arguments; those files are removed when
   the CLI call returns or raises an exception.
   The temporary account requires Shared Key access; an Azure Policy that
   forbids it will cause a failure, not a change to policy or existing accounts.
4. Capture live logs without following symlinks, upload them, then download
   locally. Archive creation retries if `tar` reports changing files and
   fails explicitly if a stable capture cannot be made.
5. Verify guest/local byte counts and SHA-256, fully validate gzip integrity,
   and check tar member paths/types without extracting anything.
6. Complete a harmless read-only Run Command to replace the active upload
   payload, and restore VMs started by the collector to their original
   stopped or deallocated state. Originally running VMs remain running.
7. Delete only the uniquely tagged temporary storage account after **all**
   requested archives verify and no Run Command completion is uncertain.
   The lab resource group, VMs and disks are never deleted.

By default, output goes into a new `evidence/diagnostic-logs-<UTC-timestamp>/` directory:

- `<source-vm-name>-cdde-logs.tar.gz`
- `<restored-vm-name>-cdde-logs.tar.gz`
- `collection.json`: provenance, original power states, hashes, cleanup
  outcomes and explicit errors.
- `SHA256SUMS`: checksums of verified archives only.

`--output "<new-directory>"` changes the destination; it must not already
exist. `--timeout 1800` is the default timeout per CLI operation/readiness
wait, not a global collection deadline. Collection may take several minutes.
The collector does not modify earlier test evidence or change the active
Azure CLI subscription.

**Failure/interruption:** a nonzero exit means collection or cleanup failed.
Verified archives remain usable, but check `collection.json` for unresolved
cleanup. Unverified downloads retain a `.partial` suffix. Storage is retained
if collection is incomplete. If a Run Command times out or is interrupted,
its completion is uncertain: the collector leaves that VM and storage in
place rather than stopping an upload that may still be running. Do not
immediately rerun the collector or delete that account. Check the VM's Run
Command status in Azure first. Once it has finished, replace the active
payload with a completed harmless command:

```bash
az vm run-command invoke \
  --subscription "<subscription-id>" -g "<resource-group>" -n "<affected-vm>" \
  --command-id RunShellScript --scripts "printf 'CDDE_LOG_FENCE=PASS\n'"
```

Confirm its success before restoring the original VM power state recorded
in `collection.json`: use `az vm deallocate` for originally deallocated VMs,
`az vm stop` for originally stopped VMs, and leave originally running VMs
running. If archives are missing, recover the uploaded blob or rerun collection
after reconciliation. Only after preserving the required logs and confirming
no upload is running, inspect the reported account's ownership tag using
`az storage account show`, then delete **that temporary account only** using
`az storage account delete`. Use the explicit subscription and resource group
for each command. Abrupt process termination/power loss may require the same
manual reconciliation; Azure retention policies may retain deleted data.

The collector does not save account keys or usable SAS signatures in its
local report. The guest agent/Azure control plane may retain historical Run
Command payloads containing the short-lived SAS; the read-only fence replaces
the active payload, not all history. Protect the local output with filesystem
access controls. Logs may contain sensitive diagnostic information: review
and redact them before sharing, and use an authorized secure channel.
**There is no automatic submission to a support team or other recipient.**
Guest uploads use only the temporary storage account described above.

## Evidence and validation status

Each run stores:

- `state.json`: provisioning steps, selected modes and latest case outcomes.
- Generated JSON configuration profiles and per-case manifests.
- Raw Azure command output, payloads, stderr and service jobs.
- Existing suite JSON/JUnit/Markdown/checksum evidence.
- Recovery preparation, mutation and guest checkpoint evidence.
- Top-level `report.json`, `junit.xml`, `summary.md` and `SHA256SUMS`.

Top-level conformance is a grouped suite result; its referenced child report
contains individual checks. Backup/restore has eight case outcomes, each
requiring three checkpoints plus restored conformance. Missing requested cases
cannot count as PASS.

Authentication access tokens are not logged. An ephemeral SSH private key is
generated outside the evidence directory and discarded; only its public key is
retained. Do not edit or use untrusted state/manifests. Protect the directory
using filesystem access controls and review evidence before external sharing.

### Publication and sharing

The generated `evidence/` directory, local Azure configuration and environment
files are excluded from Git by [.gitignore](.gitignore). Keep them excluded.
Evidence, diagnostic archives and console output can contain subscription and
tenant identifiers, resource names, identity details, service errors and guest
data. They are not automatically sanitized for publication. Review and redact
any material before copying it into documentation, issues or shared archives.
Git exclusions do not remove files or sensitive examples from earlier commits;
review repository history separately before publishing.

Use the reports and raw evidence from each run to determine its actual
validation status. Historical success does not guarantee current preview
enrollment, capacity, permissions or service behavior. Offline development
tests are not included in this repository.

## Platform references

- [CVM backup](https://learn.microsoft.com/azure/backup/confidential-vm-backup)
- [CVM restore](https://learn.microsoft.com/azure/backup/confidential-vm-restore)
- [Enhanced VM backup policy](https://learn.microsoft.com/azure/backup/backup-azure-vms-enhanced-policy)
- [Disk Backup CLI](https://learn.microsoft.com/azure/backup/backup-managed-disks-cli)
- [Disk restore CLI](https://learn.microsoft.com/azure/backup/restore-managed-disks-cli)
- [VM restore point CLI](https://learn.microsoft.com/azure/virtual-machines/virtual-machines-create-restore-points-cli)
- [Restore point support](https://learn.microsoft.com/azure/virtual-machines/concepts-restore-points)
