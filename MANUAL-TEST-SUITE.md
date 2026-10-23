# CDDE customer manual test suite

This runbook exercises Confidential VM Data Disk Encryption (CDDE) using Azure
CLI and small Linux guest commands. Execute one numbered case at a time,
inspect its evidence, and record the result before continuing. Do not run
`run-cdde-tests.py` or `cdde_validation.py` alongside these steps.

The commands follow the lab's Premium Key Vault design, not Managed HSM.
They use Compute API `2026-03-01` for the CDDE VM fields that require it.
This is a disposable-lab procedure, not a production migration guide.

## Safety, scope and result rules

- Use a **new resource group containing only this lab**, a dedicated key and
  identity, and synthetic data. Never use a production VM, key, disk or vault.
- Provisioning creates billable VMs, Premium disks, public IPs, vaults, snapshots
  and backup data. Deallocated VMs still incur disk and other resource charges.
- Lifecycle tests interrupt the VM. The SKR-denial case temporarily removes a
  key-release role. Recovery changes the source VM's attached disk; VM Backup
  original-location restore can replace **both OS and data disks**.
- Recovery is exploratory. General CVM backup documentation does not establish
  CDDE support. A successful command alone is not a successful recovery, and a
  lab PASS is not a Microsoft support commitment.
- Do not export keys, decrypt to plaintext, format recovered disks, recreate
  missing data, or reinstall a failed extension to manufacture a PASS.
- Purge-protected Key Vaults and soft-deleted backup data outlive deletion.
  Disk Backup below uses irreversible Always-On soft delete with 14-day
  retention. Complete immediate cleanup is not promised.
- No commands in this guide were executed against a customer subscription as
  part of authoring. Validate preview availability and permissions with your
  Microsoft account team before spending money.

| Result | Meaning |
|---|---|
| PASS | All stated assertions passed, with saved evidence |
| FAIL | An operation completed but a required assertion was false |
| ERROR | Authorization, capacity, preview support, service, timeout or tooling blocked the case |
| NOT_EVALUATED | Not selected or a prerequisite prevented execution |
| QUALIFIED | Diagnostic-only observation with an explicitly documented exception; never an unqualified PASS |

Keep original failures when retrying; use a new evidence filename/attempt.
If a capture fails, mark that path ERROR and its unattempted restores
NOT_EVALUATED. Do not silently substitute a different capture/restore path.

## Case inventory

| Case | Purpose | Prerequisite / impact |
|---|---|---|
| MAN-01 | Authentication, preview, region, SKU and quota | Read checks; provider registration changes subscription |
| MAN-02 | Key Vault, SKR key, identities and DES | Billable provisioning and RBAC |
| MAN-03 | Confidential VM, data disk and extension | New disk formatting; new resources only |
| MAN-04 | ARM, RBAC, extension and guest conformance | MAN-03 |
| MAN-05 | Synthetic data and external integrity baseline | MAN-04; writes synthetic files |
| MAN-06 | Restart, deallocate/start, extension reapplication | Optional; MAN-05; disruptive |
| MAN-07 | First-time SKR denial and recovery | Optional; MAN-06 or MAN-05; changes release role |
| MAN-08 | Direct full snapshot capture | MAN-05; VM deallocation |
| MAN-09 | VM restore-point capture | MAN-05; separate CVM restore-point preview |
| MAN-10 | Azure Disk Backup capture | MAN-05; Backup vault, RBAC and retained backup data |
| MAN-11 | Azure VM Backup capture | MAN-05; Enhanced policy, Recovery Services vault, key-backup RBAC |
| MAN-12 | Point-in-time mutation and Run Command fence | After all selected captures complete |
| MAN-13 | Restore each path to original/replacement target | MAN-12; destructive to disposable target |
| MAN-14 | Three recovery checkpoints and rollback | Each MAN-13 case |
| MAN-15 | Evidence, final result and cleanup | Always, including after failures |

Recovery matrix: run MAN-13 and MAN-14 **eight times**, once per row:

| Path | Original target | Replacement target |
|---|---|---|
| snapshot | Recovered data disk on original VM | Fresh confidential OS + recovered data disk |
| restore-point | Recovered data disk on original VM | Recovered OS disk + recovered data disk |
| disk-backup | Recovered data disk on original VM | Fresh confidential OS + recovered data disk |
| vm-backup | Service original-location full-VM recovery | Service alternate-location full-VM recovery |

The original-target restore-point case is data-disk recovery, not full-VM
original-location reconstruction. Disk Backup is operational snapshot
protection, not vaulted disk protection or service original-location restore.

## Operator workstation and conventions

Use Linux or WSL with Bash, Azure CLI, `jq`, OpenSSH `ssh-keygen`, GNU
`date`, `sha256sum` and standard core utilities. The guest image must provide
`cryptsetup`, `lsblk`, `findmnt`, `mkfs.ext4`, `dd`, `stat`, `sha256sum`
and a working Azure Linux agent. No Python is required for this runbook.
Install prerequisites yourself before starting; the guide does not run sudo
or install workstation packages automatically.

The authoring syntax checks used Azure CLI 2.87.0 and the `dataprotection`
extension 1.13.0. This is not a guarantee that another CLI version or a preview
service accepts every operation. Save `az version` with the test evidence.

Run from the repository root so `DataDiskSKRPolicy.json` is available.
Use the same Bash terminal for all cases. `azlab` below adds an explicit
subscription to resource commands. Local extension commands use plain `az`.
The small functions are operator-invoked conveniences, not an unattended
test runner.

```bash
set -euo pipefail
umask 077
export AZURE_CORE_OUTPUT=json
SUB="<subscription-id>"
TENANT="<tenant-id>"
LOCATION="uaenorth"
SIZE="<eligible-confidential-DC-or-EC-v6-size>"
OPERATOR_OBJECT_ID="<signed-in-user-object-id>"
TOKEN="$(date -u +%m%d%H%M%S)$(openssl rand -hex 2)"
RG="cdde-manual-$TOKEN"
KV="cddem$TOKEN"
VM="cdde-source"
UAMI="cdde-identity"
DES="cdde-des"
KEY="cdde-key"
API="2026-03-01"
PUBLISHER="Microsoft.Azure.Security.ConfidentialDiskEncryption"
IMAGE="Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest"
EVIDENCE="$PWD/evidence/manual-$TOKEN"
mkdir -p "$EVIDENCE"
azlab() { az "$@" --subscription "$SUB"; }
RG_ID="/subscriptions/$SUB/resourceGroups/$RG"
VM_ID="$RG_ID/providers/Microsoft.Compute/virtualMachines/$VM"
VM_URL="https://management.azure.com$VM_ID?api-version=$API"
az version > "$EVIDENCE/az-version.json"
printf '%s\n' "Subscription=$SUB" "Tenant=$TENANT" "Region=$LOCATION" \
  "Size=$SIZE" "ResourceGroup=$RG" "RunToken=$TOKEN" > "$EVIDENCE/run.txt"
printf 'case,path,target,checkpoint,result,evidence,notes\n' > "$EVIDENCE/results.csv"
```

`openssl` is used only to add uniqueness to names; it must also be installed.
Replace every angle-bracket placeholder before its command is executed.
For service-principal login, use your approved login method, use that
principal's object ID, and change the operator role's principal type to
`ServicePrincipal`. Never save tokens, credentials or private keys in evidence.

After a shell exits on an error, do not blindly rerun provisioning or formatting.
Reopen the terminal, recover the exact variables from your private operator
notes and saved resource IDs, investigate the error, and resume only the
appropriate case. Preserve all guest scripts and baseline files locally.

### Shared readiness and guest-evidence commands

`wait_vm` waits for ARM readiness **and** the guest agent. It does not prove
encryption health. Each guest script must reach its final
`MANUAL_CHECK=PASS` marker; a successful Run Command HTTP response is not enough.
Do not use verbose guest output: Run Command output can be truncated.

```bash
wait_vm() {
  local name="$1" deadline=$((SECONDS + 1800)) state agent
  azlab vm wait -g "$RG" -n "$name" --updated --timeout 1800 --interval 15
  while (( SECONDS < deadline )); do
    agent="$(azlab vm get-instance-view -g "$RG" -n "$name" -o json)"
    state="$(jq -r '.instanceView.vmAgent.statuses[]?.code' <<< "$agent")"
    if grep -qx 'ProvisioningState/succeeded' <<< "$state"; then
      return 0
    fi
    printf 'Waiting for guest agent on %s: %s\n' "$name" "$state"
    sleep 15
  done
  printf 'ERROR: guest agent timeout on %s\n' "$name" >&2
  return 1
}
guest() {
  local name="$1" script="$2" label="$3" messages
  azlab vm run-command invoke -g "$RG" -n "$name" \
    --command-id RunShellScript --scripts "@$script" \
    > "$EVIDENCE/$label.json"
  messages="$(jq -r '.value[]?.message' "$EVIDENCE/$label.json")"
  printf '%s\n' "$messages" | tee "$EVIDENCE/$label.txt"
  jq -e '(.value | length) > 0 and
    all(.value[]; ((.code // "") | ascii_downcase | contains("failed") | not))' \
    "$EVIDENCE/$label.json" > /dev/null
  grep -qx 'MANUAL_CHECK=PASS' <<< "$messages"
}
```

If either helper returns nonzero, stop that case and inspect its saved output.
Do not suppress the error. A guest-agent timeout is ERROR, not a data-integrity
FAIL. Save additional diagnostics separately; never overwrite original evidence.

## MAN-01 - Subscription, enrollment, image and capacity

**Action**

```bash
az login --tenant "$TENANT" --use-device-code
az account set --subscription "$SUB"
azlab account show > "$EVIDENCE/account.json"
jq -e --arg sub "$SUB" --arg tenant "$TENANT" \
  '.id == $sub and .tenantId == $tenant' "$EVIDENCE/account.json"

for rp in Microsoft.Compute Microsoft.KeyVault Microsoft.ManagedIdentity Microsoft.Network; do
  azlab provider register --namespace "$rp" --wait
  azlab provider show --namespace "$rp" > "$EVIDENCE/provider-$rp.json"
  jq -e '.registrationState == "Registered"' "$EVIDENCE/provider-$rp.json"
done
azlab feature show --namespace Microsoft.Compute \
  --name ConfidentialVMDataDiskEncryptionPreview > "$EVIDENCE/cdde-feature.json"
jq -e '.properties.state == "Registered"' "$EVIDENCE/cdde-feature.json"
azlab vm list-skus --location "$LOCATION" --resource-type virtualMachines --all \
  > "$EVIDENCE/skus.json"
azlab vm list-usage --location "$LOCATION" > "$EVIDENCE/quota.json"
jq --arg size "$SIZE" '.[] | select(.name == $size) |
  {name, family, restrictions, capabilities}' "$EVIDENCE/skus.json"
jq '.[] | {name: .name, currentValue, limit}' "$EVIDENCE/quota.json"
azlab vm image show --location "$LOCATION" --urn "$IMAGE" > "$EVIDENCE/image.json"
```

**Expected / gate**

- The active subscription/tenant match. Providers and CDDE feature are Registered.
  CDDE enrollment is **not self-service**: stop and contact Microsoft if it is
  absent or not Registered; do not attempt to bypass the preview.
- Select an unrestricted **confidential DC/EC v6** SKU, not ordinary D/E v6
  or v5. Inspect `vCPUs`, memory, family and restrictions in the saved SKU.
  Leave sufficient quota in **both** the SKU family and total regional cores:
  one VM for baseline, **two concurrent VMs** for replacement recovery.
  Example: two 2-vCPU VMs need at least four remaining cores in both quotas.
- The confidential Ubuntu 22.04 image is available. Availability/quota do not
  guarantee actual capacity or CDDE compatibility.
- The operator can create resources, assign roles and register providers.
  VM Backup also requires custom-role management and tenant directory read
  access for its service-principal lookup.

For MAN-09 or MAN-11, also perform this subscription-level preview setup.
Current general CVM restore-point documentation lists v6 in UAE North and
Korea Central; verify the live support matrix before choosing another region.
This separate feature is self-service/auto-approved, unlike CDDE enrollment.

```bash
for rp in Microsoft.RecoveryServices Microsoft.DataProtection Microsoft.Storage; do
  azlab provider register --namespace "$rp" --wait
done
azlab feature show --namespace Microsoft.Compute \
  --name RestorePointSupportForConfidentialVMV2
# Only if not already Registered:
azlab feature register --namespace Microsoft.Compute \
  --name RestorePointSupportForConfidentialVMV2
```

Repeat `azlab feature show` every 30 seconds, for at most 30 minutes.
Stop with ERROR if registration is rejected or does not complete. Once it
reports Registered:

```bash
azlab provider register --namespace Microsoft.Compute --wait
azlab feature show --namespace Microsoft.Compute \
  --name RestorePointSupportForConfidentialVMV2 > "$EVIDENCE/restore-feature.json"
jq -e '.properties.state == "Registered"' "$EVIDENCE/restore-feature.json"
```

## MAN-02 - Key, identity, DES and roles

**Action** - Refuse to reuse an existing group, even if its name looks familiar.

```bash
test "$(azlab group exists -n "$RG" -o tsv)" = false
azlab group create -n "$RG" -l "$LOCATION" --tags "cdde-manual-run=$TOKEN" \
  > "$EVIDENCE/group.json"
azlab keyvault create -g "$RG" -n "$KV" -l "$LOCATION" --sku premium \
  --enable-rbac-authorization true --enable-purge-protection true \
  > "$EVIDENCE/vault.json"
KV_ID="$(jq -er '.id' "$EVIDENCE/vault.json")"
azlab role assignment create --assignee-object-id "$OPERATOR_OBJECT_ID" \
  --assignee-principal-type User --role "Key Vault Crypto Officer" --scope "$KV_ID" \
  > "$EVIDENCE/operator-role.json"
```

Allow up to 15 minutes for operator RBAC. Run the next command; retry only an
explicit `ForbiddenByRbac` after 20 seconds, within that limit. Stop on any other
error, and never create a substitute key without the release policy.

```bash
azlab keyvault key create --vault-name "$KV" -n "$KEY" --kty RSA-HSM \
  --size 3072 --ops wrapKey unwrapKey --exportable true \
  --policy ./DataDiskSKRPolicy.json > "$EVIDENCE/key-created.json"
azlab keyvault key show --vault-name "$KV" -n "$KEY" > "$EVIDENCE/key.json"
KEY_URL="$(jq -er '.key.kid' "$EVIDENCE/key.json")"
jq -e '.key.kty == "RSA-HSM" and (.key.n | length) == 512 and
  .attributes.exportable == true and .attributes.enabled == true and
  (.releasePolicy.encodedPolicy | type == "string" and length > 0) and
  (.key.keyOps | index("wrapKey") != null and index("unwrapKey") != null)' \
  "$EVIDENCE/key.json"
azlab identity create -g "$RG" -n "$UAMI" -l "$LOCATION" > "$EVIDENCE/identity.json"
UAMI_ID="$(jq -er '.id' "$EVIDENCE/identity.json")"
UAMI_PID="$(jq -er '.principalId' "$EVIDENCE/identity.json")"
azlab disk-encryption-set create -g "$RG" -n "$DES" -l "$LOCATION" \
  --source-vault "$KV_ID" --key-url "$KEY_URL" \
  --encryption-type ConfidentialVmEncryptedWithCustomerKey --mi-system-assigned \
  > "$EVIDENCE/des.json"
DES_ID="$(jq -er '.id' "$EVIDENCE/des.json")"
DES_PID="$(jq -er '.identity.principalId' "$EVIDENCE/des.json")"
azlab role assignment create --assignee-object-id "$DES_PID" \
  --assignee-principal-type ServicePrincipal \
  --role "Key Vault Crypto Service Encryption User" --scope "$KV_ID" \
  > "$EVIDENCE/des-encryption-role.json"
azlab role assignment create --assignee-object-id "$UAMI_PID" \
  --assignee-principal-type ServicePrincipal \
  --role "Key Vault Crypto Service Encryption User" --scope "$KV_ID" \
  > "$EVIDENCE/uami-encryption-role.json"
azlab role assignment create --assignee-object-id "$UAMI_PID" \
  --assignee-principal-type ServicePrincipal \
  --role "Key Vault Crypto Service Release User" --scope "$KV_ID" \
  > "$EVIDENCE/uami-release-role.json"
sleep 600
```

**Expected** - Premium/RBAC/purge-protected vault, enabled RSA-HSM 3072 key
with nonempty release policy, confidential DES referencing the exact key
version, and all three role assignments. The DES encryption identity and the
VM release identity are distinct principals. `exportable=true` allows the
SKR flow; this procedure never requests a plaintext key export.

## MAN-03 - Confidential VM and initial encryption

**Action** - Create the VM with SCSI so the documented Azure LUN path applies.
SSH ingress stays closed; Run Command uses the guest agent. Standard public IP
provides the lab's outbound connectivity and incurs charges.

```bash
ssh-keygen -q -t ed25519 -N "" -f "$EVIDENCE/deployment-key"
azlab vm create -g "$RG" -n "$VM" -l "$LOCATION" --size "$SIZE" \
  --image "$IMAGE" --admin-username cddeadmin \
  --ssh-key-values "$EVIDENCE/deployment-key.pub" --storage-sku Premium_LRS \
  --security-type ConfidentialVM --os-disk-security-encryption-type DiskWithVMGuestState \
  --enable-vtpm true --enable-secure-boot true --disk-controller-type SCSI \
  --os-disk-delete-option Detach --public-ip-sku Standard --nsg-rule NONE \
  --vnet-name cdde-network --subnet workloads --tags "cdde-manual-run=$TOKEN" \
  > "$EVIDENCE/vm-created.json"
wait_vm "$VM"
jq -n --arg id "$UAMI_ID" '{
  identity: {type:"UserAssigned", userAssignedIdentities:{($id):{}}},
  properties:{securityProfile:{
    securityType:"ConfidentialVM",
    uefiSettings:{secureBootEnabled:true,vTpmEnabled:true},
    confidentialDataDiskEncryptionIdentity:{userAssignedIdentityResourceId:$id}
  }}}' > "$EVIDENCE/vm-identity-body.json"
azlab rest --method patch --url "$VM_URL" \
  --body "@$EVIDENCE/vm-identity-body.json" > "$EVIDENCE/vm-identity-patch.json"
wait_vm "$VM"
jq -n --arg des "$DES_ID" '{properties:{storageProfile:{dataDisks:[{
  lun:0,name:"cdde-source-data",createOption:"Empty",deleteOption:"Detach",
  diskSizeGB:4,caching:"None",managedDisk:{
    storageAccountType:"Premium_LRS",securityProfile:{
      securityEncryptionType:"DataDiskEncryptedWithCustomerKey",
      diskEncryptionSet:{id:$des}
  }}}]}}}' > "$EVIDENCE/data-attach-body.json"
azlab rest --method patch --url "$VM_URL" \
  --body "@$EVIDENCE/data-attach-body.json" > "$EVIDENCE/data-attached.json"
wait_vm "$VM"
azlab rest --method get --url "$VM_URL" > "$EVIDENCE/source-vm.json"
SOURCE_DISK_ID="$(jq -er '.properties.storageProfile.dataDisks[] |
  select(.lun == 0) | .managedDisk.id' "$EVIDENCE/source-vm.json")"
printf '%s\n' "$SOURCE_DISK_ID" > "$EVIDENCE/source-disk-id.txt"
```

The following is the **only source-disk formatting step**. First confirm the
saved ARM disk ID is the newly created `cdde-source-data` in this lab. Do not
run this script on a retained, restored or previously encrypted disk.
It refuses any detectable filesystem or partition signature.

```bash
cat > "$EVIDENCE/format-new-source.sh" <<'GUEST'
set -eu
target=/dev/disk/azure/scsi1/lun0
test -b "$target"
test "$(lsblk -dn -o TYPE "$target")" = disk
test -z "$(wipefs -n "$target")"
test "$(lsblk -nr -o NAME "$target" | wc -l)" -eq 1
test -z "$(lsblk -nr -o MOUNTPOINT "$target" | tr -d '[:space:]')"
mkfs.ext4 "$target"
mkdir -p /cde-data
mount "$target" /cde-data
echo MANUAL_CHECK=PASS
GUEST
guest "$VM" "$EVIDENCE/format-new-source.sh" MAN-03-format
SEQ="$(cat /proc/sys/kernel/random/uuid)"
azlab vm extension set -g "$RG" --vm-name "$VM" --publisher "$PUBLISHER" \
  -n CDELinux --version 1.0 --settings "{\"sequenceVersion\":\"$SEQ\"}" \
  > "$EVIDENCE/extension-installed.json"
```

**Expected** - Azure accepts the CDDE identity and data-disk security profile.
The extension finishes successfully and MAN-04 proves guest encryption.
Do not treat `provisioningState=Succeeded` on the VM alone as proof.
If a PATCH conflicts with an in-progress write, wait for that operation first;
do not issue parallel VM writes or alter the payload to bypass a service error.

## MAN-04 - Conformance

**ARM, key and RBAC evidence**

```bash
azlab rest --method get --url "$VM_URL" > "$EVIDENCE/MAN-04-vm.json"
azlab disk show --ids "$SOURCE_DISK_ID" > "$EVIDENCE/MAN-04-disk.json"
azlab disk-encryption-set show -g "$RG" -n "$DES" > "$EVIDENCE/MAN-04-des.json"
azlab keyvault show -g "$RG" -n "$KV" > "$EVIDENCE/MAN-04-vault.json"
azlab keyvault key show --vault-name "$KV" -n "$KEY" > "$EVIDENCE/MAN-04-key.json"
azlab role assignment list --assignee "$DES_PID" --scope "$KV_ID" \
  --include-inherited > "$EVIDENCE/MAN-04-des-rbac.json"
azlab role assignment list --assignee "$UAMI_PID" --scope "$KV_ID" \
  --include-inherited > "$EVIDENCE/MAN-04-uami-rbac.json"
```

Inspect and record **all** these assertions, not just disk `encryption.type`
(server-side encryption is not proof of CDDE):

| Surface | Required value |
|---|---|
| VM security | `securityType=ConfidentialVM`; Secure Boot and vTPM true |
| VM OS disk | `managedDisk.securityProfile.securityEncryptionType=DiskWithVMGuestState` |
| VM identity | UAMI ID present in `identity.userAssignedIdentities` **and** `securityProfile.confidentialDataDiskEncryptionIdentity.userAssignedIdentityResourceId` |
| VM location/size | Exact selected region and confidential v6 size |
| LUN 0 | Exactly one disk; saved source disk ID; `DataDiskEncryptedWithCustomerKey`; exact DES ID |
| Managed disk | Succeeded, Attached, same region, exact saved ID |
| DES | Succeeded; `ConfidentialVmEncryptedWithCustomerKey`; nonempty identity principal; `activeKey.keyUrl` equals saved key version |
| Vault | Exact ID; Premium; RBAC and purge protection true |
| Key | Enabled, RSA-HSM 3072, wrap/unwrap operations, exportable, nonempty encoded release policy; not expired/not-before in future |
| DES roles | Key Vault Crypto Service Encryption User at vault or inherited scope |
| UAMI roles | Key Vault Crypto Service Encryption User **and** Key Vault Crypto Service Release User at vault or inherited scope |

### Read-only extension inspection

Use this before every recovery checkpoint too. It does **not** reinstall,
re-enable, or change `sequenceVersion`.

```bash
inspect_extension() {
  local name="$1" label="$2"
  azlab vm extension show -g "$RG" --vm-name "$name" -n CDELinux \
    --instance-view > "$EVIDENCE/$label-extension.json"
  jq -e --arg publisher "$PUBLISHER" '
    .publisher == $publisher and .typePropertiesType == "CDELinux" and
    (.settings.sequenceVersion | type == "string" and length > 0) and
    (.provisioningState | ascii_downcase) == "succeeded" and
    any(.instanceView.statuses[]?; (.code | ascii_downcase) == "provisioningstate/succeeded") and
    all((.instanceView.statuses[]?, .instanceView.substatuses[]?);
      ((.level // "" | ascii_downcase) != "error") and
      ((.code // "" | ascii_downcase | contains("failed")) | not))
  ' "$EVIDENCE/$label-extension.json"
}
inspect_extension "$VM" MAN-04
```

If it is still processing, poll the read every 30 seconds up to 30 minutes.
If it is Failed or invalid, stop and preserve the failure. Top-level success
with a failed/error component is still FAIL. CDE306 is not a manual-suite
bypass: any continued diagnostics must be recorded QUALIFIED, with the
original failure retained; no strict recovery case can PASS with it.

### Guest block-device proof

```bash
cat > "$EVIDENCE/check-encryption.sh" <<'GUEST'
set -eu
target=/dev/disk/azure/scsi1/lun0
test -b "$target"
findmnt -rn --mountpoint /cde-data
source="$(findmnt -n -o SOURCE --mountpoint /cde-data)"
resolved="$(readlink -f "$source")"
test "$(lsblk -dn -o TYPE "$resolved")" = crypt
cryptsetup luksDump "$target" | grep -Eq '^Version:[[:space:]]*2$'
lsblk -srnp -o NAME "$resolved" | grep -Fx "$(readlink -f "$target")"
echo MANUAL_CHECK=PASS
GUEST
guest "$VM" "$EVIDENCE/check-encryption.sh" MAN-04-encryption
```

Also inspect the handler's most recent status file. Its LUN 0 entry must
identify `/cde-data` as encrypted. Obtain it separately so verbose status/log
output cannot hide the encryption proof in truncated Run Command output:

```bash
azlab vm run-command invoke -g "$RG" -n "$VM" --command-id RunShellScript \
  --scripts 'find /var/lib/waagent/Microsoft.Azure.Security.ConfidentialDiskEncryption.CDELinux-*/status -maxdepth 1 -name "*.status" -type f -print -exec cat {} \;' \
  > "$EVIDENCE/MAN-04-handler-status.json"
```

**Expected** - Every table assertion, extension health, LUKS2, dm-crypt,
exact mounted LUN ancestry, and handler LUN status passes. If verbose output
is truncated, retrieve a narrower status/log excerpt; do not infer success
from omitted output.

## MAN-05 - Synthetic fixture and external baseline

Create the fixture **once**, after encryption is proven. Do not repeat this
case on recovered disks. It records hashes outside the VM so a restore cannot
rewind the expected values.

```bash
cat > "$EVIDENCE/prepare-fixture.sh" <<'GUEST'
set -eu
findmnt -rn --mountpoint /cde-data > /dev/null
test ! -e /cde-data/manual-suite
mkdir /cde-data/manual-suite
chmod 750 /cde-data/manual-suite
dd if=/dev/urandom of=/cde-data/manual-suite/payload.bin bs=1M count=16 conv=fsync 2>/dev/null
printf 'CDDE-MANUAL-BEFORE-CAPTURE\n' > /cde-data/manual-suite/checkpoint.txt
chown 1000:1000 /cde-data/manual-suite/payload.bin
chmod 640 /cde-data/manual-suite/payload.bin
chmod 600 /cde-data/manual-suite/checkpoint.txt
sync
echo "PAYLOAD_HASH=$(sha256sum /cde-data/manual-suite/payload.bin | cut -d ' ' -f1)"
echo "MARKER_HASH=$(sha256sum /cde-data/manual-suite/checkpoint.txt | cut -d ' ' -f1)"
echo MANUAL_CHECK=PASS
GUEST
guest "$VM" "$EVIDENCE/prepare-fixture.sh" MAN-05-fixture
PAYLOAD_HASH="$(sed -n 's/^PAYLOAD_HASH=//p' "$EVIDENCE/MAN-05-fixture.txt")"
MARKER_HASH="$(sed -n 's/^MARKER_HASH=//p' "$EVIDENCE/MAN-05-fixture.txt")"
[[ "$PAYLOAD_HASH" =~ ^[0-9a-f]{64}$ ]]
[[ "$MARKER_HASH" =~ ^[0-9a-f]{64}$ ]]
{
  printf 'set -eu\nexpected_payload=%q\nexpected_marker=%q\n' "$PAYLOAD_HASH" "$MARKER_HASH"
  sed '/^echo MANUAL_CHECK=PASS$/d' "$EVIDENCE/check-encryption.sh"
  cat <<'GUEST'
test "$(sha256sum /cde-data/manual-suite/payload.bin | cut -d ' ' -f1)" = "$expected_payload"
test "$(sha256sum /cde-data/manual-suite/checkpoint.txt | cut -d ' ' -f1)" = "$expected_marker"
test "$(stat -c '%u:%g:%a' /cde-data/manual-suite/payload.bin)" = "1000:1000:640"
test "$(stat -c '%u:%g:%a' /cde-data/manual-suite/checkpoint.txt)" = "0:0:600"
test "$(stat -c '%u:%g:%a' /cde-data/manual-suite)" = "0:0:750"
test ! -e /cde-data/manual-suite/after-capture.txt
probe="$(mktemp /cde-data/manual-suite/io.XXXXXX)"
printf 'recovered-volume-io\n' > "$probe"
sync
test "$(cat "$probe")" = recovered-volume-io
rm "$probe"
echo FIXTURE_CHECK=PASS
echo MANUAL_CHECK=PASS
GUEST
} > "$EVIDENCE/verify-fixture.sh"
guest "$VM" "$EVIDENCE/verify-fixture.sh" MAN-05-baseline
grep -qx FIXTURE_CHECK=PASS "$EVIDENCE/MAN-05-baseline.txt"
```

For all fixture verifications, require **both** `FIXTURE_CHECK=PASS` and
`MANUAL_CHECK=PASS`. The embedded encryption script's intermediate success
marker is removed, so success is emitted only after the complete verification.

**Expected** - Exact hashes, root directory/marker ownership, payload
ownership, permissions and encrypted-volume I/O pass. Save the local scripts
and hashes; they are the immutable recovery baseline.

## MAN-06 - Optional disruptive lifecycle

Run each operation separately. After each, execute the three verification
commands with a different label (`restart`, `deallocate-start`, `reapply`).

```bash
azlab vm restart -g "$RG" -n "$VM" > "$EVIDENCE/MAN-06-restart.json"
# Verify before moving to the next operation.
```

```bash
azlab vm deallocate -g "$RG" -n "$VM" > "$EVIDENCE/MAN-06-deallocate.json"
azlab vm start -g "$RG" -n "$VM" > "$EVIDENCE/MAN-06-start.json"
# Verify before moving to the next operation.
```

```bash
SEQ="$(cat /proc/sys/kernel/random/uuid)"
azlab vm extension set -g "$RG" --vm-name "$VM" --publisher "$PUBLISHER" \
  -n CDELinux --version 1.0 --settings "{\"sequenceVersion\":\"$SEQ\"}" \
  > "$EVIDENCE/MAN-06-reapply.json"
```

For each operation:

```bash
CHECKPOINT="<restart-or-deallocate-start-or-reapply>"
wait_vm "$VM"
inspect_extension "$VM" "MAN-06-$CHECKPOINT"
guest "$VM" "$EVIDENCE/verify-fixture.sh" "MAN-06-$CHECKPOINT"
grep -qx FIXTURE_CHECK=PASS "$EVIDENCE/MAN-06-$CHECKPOINT.txt"
```

**Expected** - Encryption, mount, exact LUN ancestry, all hashes/permissions
and fresh I/O survive each operation. Reapplication is intentional **only
here and in MAN-07 recovery**. Do not use it to repair restore tests.

## MAN-07 - Optional first-time SKR denial

This case does **not** prove emergency revocation of an already unlocked
disk or guaranteed key-cache eviction. It tests first-time encryption of a
new temporary disk while release authorization is absent.

**Preconditions** - Source conformance/fixture passed; LUN 1 is unused; UAMI
has exactly one direct, unconditional release assignment at this vault and
no inherited/group/custom role granting key release. Check group/custom
permissions with your identity administrator; role-name filtering alone
cannot prove absence of equivalent custom permissions. Skip with ERROR if
safe isolation cannot be established.

```bash
azlab role assignment list --assignee "$UAMI_PID" --scope "$KV_ID" \
  --include-inherited > "$EVIDENCE/MAN-07-roles.json"
jq --arg pid "$UAMI_PID" --arg scope "$KV_ID" \
  '[.[] | select(.principalId == $pid and .scope == $scope and
    .roleDefinitionName == "Key Vault Crypto Service Release User" and .condition == null)]' \
  "$EVIDENCE/MAN-07-roles.json" > "$EVIDENCE/MAN-07-release.json"
jq -e 'length == 1' "$EVIDENCE/MAN-07-release.json"
RELEASE_ID="$(jq -er '.[0].id' "$EVIDENCE/MAN-07-release.json")"
RELEASE_NAME="$(jq -er '.[0].name' "$EVIDENCE/MAN-07-release.json")"
RELEASE_ROLE="$(jq -er '.[0].roleDefinitionId' "$EVIDENCE/MAN-07-release.json")"
azlab rest --method get --url "$VM_URL" > "$EVIDENCE/MAN-07-vm-before.json"
jq -e '.properties.storageProfile.dataDisks | length == 1 and .[0].lun == 0' \
  "$EVIDENCE/MAN-07-vm-before.json"
jq --arg des "$DES_ID" '{properties:{storageProfile:{dataDisks:
  [.properties.storageProfile.dataDisks[] |
    {lun,name,createOption:"Attach",deleteOption:"Detach",caching,managedDisk}] +
  [{lun:1,name:"cdde-denial-data",createOption:"Empty",deleteOption:"Detach",
    diskSizeGB:4,caching:"None",managedDisk:{storageAccountType:"Premium_LRS",
      securityProfile:{securityEncryptionType:"DataDiskEncryptedWithCustomerKey",
        diskEncryptionSet:{id:$des}}}}]}}}' \
  "$EVIDENCE/MAN-07-vm-before.json" > "$EVIDENCE/MAN-07-attach-body.json"
azlab rest --method patch --url "$VM_URL" --body "@$EVIDENCE/MAN-07-attach-body.json" \
  > "$EVIDENCE/MAN-07-attached.json"
wait_vm "$VM"
DENIAL_DISK_ID="$RG_ID/providers/Microsoft.Compute/disks/cdde-denial-data"
azlab disk show --ids "$DENIAL_DISK_ID" > "$EVIDENCE/MAN-07-disk.json"
jq -e '.provisioningState == "Succeeded" and .diskState == "Attached"' \
  "$EVIDENCE/MAN-07-disk.json"
```

Before deleting anything, save this exact restoration command in your private
operator notes. If **any** subsequent step fails, run it immediately and wait
for propagation. Role restoration is mandatory even if the delete response
is lost. Do not deallocate the source while its release role is absent.

```bash
restore_release() {
  azlab role assignment create --name "$RELEASE_NAME" \
    --assignee-object-id "$UAMI_PID" --assignee-principal-type ServicePrincipal \
    --role "$RELEASE_ROLE" --scope "$KV_ID"
}
azlab role assignment delete --ids "$RELEASE_ID"
date -u +%FT%TZ > "$EVIDENCE/MAN-07-role-deleted-at.txt"
sleep 600
```

Format **only the newly created temporary LUN 1**, with the monitor stopped
so first-time encryption does not race fixture creation. On a failure after
stopping the service, restore the role and restart the service manually.

```bash
cat > "$EVIDENCE/denial-setup.sh" <<'GUEST'
set -eu
target=/dev/disk/azure/scsi1/lun1
test -b "$target"
test -z "$(wipefs -n "$target")"
test "$(lsblk -nr -o NAME "$target" | wc -l)" -eq 1
test -z "$(lsblk -nr -o MOUNTPOINT "$target" | tr -d '[:space:]')"
systemctl stop azure-cde-mount-monitor.service
mkfs.ext4 "$target"
mkdir -p /cdde-failclosed
mount "$target" /cdde-failclosed
dd if=/dev/urandom of=/cdde-failclosed/denial.bin bs=1M count=16 conv=fsync 2>/dev/null
echo "DENIAL_HASH=$(sha256sum /cdde-failclosed/denial.bin | cut -d ' ' -f1)"
echo "DENIAL_TIME=$(date -u +%Y-%m-%dT%H:%M:%S)"
systemctl start azure-cde-mount-monitor.service
echo MANUAL_CHECK=PASS
GUEST
guest "$VM" "$EVIDENCE/denial-setup.sh" MAN-07-setup
DENIAL_HASH="$(sed -n 's/^DENIAL_HASH=//p' "$EVIDENCE/MAN-07-setup.txt")"
DENIAL_TIME="$(sed -n 's/^DENIAL_TIME=//p' "$EVIDENCE/MAN-07-setup.txt")"
[[ "$DENIAL_HASH" =~ ^[0-9a-f]{64}$ ]]
[[ "$DENIAL_TIME" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]]
sleep 120
{
  printf 'set -eu\ncutoff=%q\n' "$DENIAL_TIME"
  cat <<'GUEST'
findmnt -rn --mountpoint /cdde-failclosed
source="$(findmnt -n -o SOURCE --mountpoint /cdde-failclosed)"
test "$(lsblk -dn -o TYPE "$(readlink -f "$source")")" != crypt
diagnostics="$(awk -v cutoff="$cutoff" '$1 >= cutoff' /var/log/azure/Microsoft.Azure.Security.ConfidentialDiskEncryption.CDELinux/*.log |
  grep -Ehi 'release.*denied|AzureAttestSKR.*(exit code[ :]*4|failed|error|denied)|CDE800|failed to retrieve key|authorization.*(failed|denied)')"
test -n "$diagnostics"
printf '%s\n' "$diagnostics" | tail -n 10
echo MANUAL_CHECK=PASS
GUEST
} > "$EVIDENCE/check-denial.sh"
guest "$VM" "$EVIDENCE/check-denial.sh" MAN-07-denial
```

**Expected denial** - The temporary mounted disk is not dm-crypt **and**
new, timestamp-correlated SKR authorization/release failure diagnostics are
present. A timeout or missing logs is not a PASS. Manually confirm the log
refers to this attempt rather than an unrelated old failure.

Whether denial passed or failed, restore authorization now:

```bash
restore_release > "$EVIDENCE/MAN-07-role-restored.json"
sleep 180
azlab role assignment list --assignee "$UAMI_PID" --scope "$KV_ID" \
  > "$EVIDENCE/MAN-07-roles-restored.json"
jq -e --arg id "$RELEASE_ID" 'any(.[]; .id == $id)' "$EVIDENCE/MAN-07-roles-restored.json"
SEQ="$(cat /proc/sys/kernel/random/uuid)"
azlab vm extension set -g "$RG" --vm-name "$VM" --publisher "$PUBLISHER" \
  -n CDELinux --version 1.0 --settings "{\"sequenceVersion\":\"$SEQ\"}" \
  > "$EVIDENCE/MAN-07-reapply.json"
{
  printf 'set -eu\nexpected=%q\n' "$DENIAL_HASH"
  cat <<'GUEST'
target=/dev/disk/azure/scsi1/lun1
findmnt -rn --mountpoint /cdde-failclosed
source="$(findmnt -n -o SOURCE --mountpoint /cdde-failclosed)"
test "$(lsblk -dn -o TYPE "$(readlink -f "$source")")" = crypt
cryptsetup luksDump "$target" | grep -Eq '^Version:[[:space:]]*2$'
lsblk -srnp -o NAME "$(readlink -f "$source")" | grep -Fx "$(readlink -f "$target")"
test "$(sha256sum /cdde-failclosed/denial.bin | cut -d ' ' -f1)" = "$expected"
echo MANUAL_CHECK=PASS
GUEST
} > "$EVIDENCE/check-denial-recovery.sh"
guest "$VM" "$EVIDENCE/check-denial-recovery.sh" MAN-07-recovery
inspect_extension "$VM" MAN-07-recovery
guest "$VM" "$EVIDENCE/verify-fixture.sh" MAN-07-source-health
grep -qx FIXTURE_CHECK=PASS "$EVIDENCE/MAN-07-source-health.txt"
```

**Expected recovery** - LUN 1 becomes LUKS2/dm-crypt without data loss, the
original release assignment is restored, and source LUN 0 stays healthy.
Allow bounded propagation/handler settling, at most 30 minutes; preserve
an error if it still fails, rather than repeatedly reapplying the extension.

Before backup captures, unmount and remove the temporary disk only:

```bash
cat > "$EVIDENCE/unmount-denial.sh" <<'GUEST'
set -eu
umount /cdde-failclosed
echo MANUAL_CHECK=PASS
GUEST
guest "$VM" "$EVIDENCE/unmount-denial.sh" MAN-07-unmount
azlab vm deallocate -g "$RG" -n "$VM"
azlab vm disk detach -g "$RG" --vm-name "$VM" -n cdde-denial-data
azlab disk show --ids "$DENIAL_DISK_ID" > "$EVIDENCE/MAN-07-detached.json"
jq -e '.diskState == "Unattached" and .managedBy == null' "$EVIDENCE/MAN-07-detached.json"
azlab disk delete --ids "$DENIAL_DISK_ID" --yes
azlab vm start -g "$RG" -n "$VM"
wait_vm "$VM"
```

Do not delete or close an arbitrary mapper by name. If guest cleanup is blocked,
retain the lab for diagnosis rather than touching LUN 0.

## Capture rules for MAN-08 through MAN-11

1. Run MAN-04 and MAN-05 successfully first; complete optional disruptive cases
   before capturing.
2. Keep the fixture unchanged until **all selected capture jobs complete**.
   No applications or other operators may write to this volume.
3. Verify the original fixture before each capture:
   `guest "$VM" "$EVIDENCE/verify-fixture.sh" "<unique-label>"`, followed by
   `grep -qx FIXTURE_CHECK=PASS "$EVIDENCE/<unique-label>.txt"`.
4. Save exact capture/recovery-point IDs and UTC request/completion times.
   Select only points belonging to this source, created after fixture
   preparation and after the corresponding request. Do not pick an old point
   simply because it is the newest item in a list.
5. Poll service jobs every 30 seconds, up to two hours per operation. Record
   service errors and final status; a timeout is ERROR, never implied success.
6. Do not run MAN-12 until all selected successful captures are complete.

## MAN-08 - Direct full snapshot

```bash
azlab vm deallocate -g "$RG" -n "$VM"
date -u +%FT%TZ > "$EVIDENCE/MAN-08-requested-at.txt"
azlab snapshot create -g "$RG" -n manual-full-snapshot -l "$LOCATION" \
  --source "$SOURCE_DISK_ID" --incremental false > "$EVIDENCE/MAN-08-snapshot.json"
SNAPSHOT_ID="$(jq -er '.id' "$EVIDENCE/MAN-08-snapshot.json")"
jq -e '.provisioningState == "Succeeded" and .incremental == false' \
  "$EVIDENCE/MAN-08-snapshot.json"
date -u +%FT%TZ > "$EVIDENCE/MAN-08-completed-at.txt"
azlab vm start -g "$RG" -n "$VM"
wait_vm "$VM"
```

Start the source again even if snapshot creation fails. **Expected** - Full
snapshot succeeds. CDDE support remains exploratory until both restore cases
and their guest checkpoints pass; snapshot creation alone proves neither.

## MAN-09 - VM restore point

```bash
date -u +%FT%TZ > "$EVIDENCE/MAN-09-requested-at.txt"
azlab restore-point collection create -g "$RG" --collection-name manual-rpc \
  -l "$LOCATION" --source-id "$VM_ID" > "$EVIDENCE/MAN-09-collection.json"
azlab restore-point create -g "$RG" --collection-name manual-rpc \
  -n manual-point > "$EVIDENCE/MAN-09-request.json"
azlab restore-point show -g "$RG" --collection-name manual-rpc \
  -n manual-point > "$EVIDENCE/MAN-09-point.json"
```

Poll `restore-point show` until `provisioningState` (or
`properties.provisioningState`) is Succeeded. Stop on Failed/Canceled or the
two-hour deadline. The request intentionally omits explicit consistency mode,
matching the automated lab's default-capture comparison.

```bash
jq -e '(.properties // .).provisioningState == "Succeeded"' "$EVIDENCE/MAN-09-point.json"
jq '(.properties // .) | {consistencyMode, sourceMetadata}' "$EVIDENCE/MAN-09-point.json"
RP_ID="$(jq -er '.id' "$EVIDENCE/MAN-09-point.json")"
DATA_RP_ID="$(jq -er --arg id "$SOURCE_DISK_ID" '
  [(.properties // .).sourceMetadata.storageProfile.dataDisks[] |
    select((.managedDisk.id | ascii_downcase) == ($id | ascii_downcase))] |
  if length == 1 then .[0].diskRestorePoint.id else error("source disk not unique") end' \
  "$EVIDENCE/MAN-09-point.json")"
OS_RP_ID="$(jq -er '(.properties // .).sourceMetadata.storageProfile.osDisk.diskRestorePoint.id' \
  "$EVIDENCE/MAN-09-point.json")"
date -u +%FT%TZ > "$EVIDENCE/MAN-09-completed-at.txt"
```

**Expected** - Point succeeds and uniquely references the **exact source
managed disk ID**, not just LUN metadata (which can be absent). Save Azure's
actual `consistencyMode`. `FileSystemConsistent` is not proof of
application-consistent database recovery.

## MAN-10 - Azure Disk Backup

**Setup** - This creates an Always-On soft-delete vault. Accept retained
backup data and possible charges before proceeding.

```bash
# Local CLI operation: install only if absent.
az extension show -n dataprotection
# If the preceding command reports ExtensionNotInstalled:
# az extension add -n dataprotection
azlab dataprotection backup-vault create -g "$RG" --vault-name cdde-bv \
  -l "$LOCATION" --mi-system-assigned true --soft-delete-state AlwaysOn \
  --soft-delete-retention 14 \
  --storage-settings datastore-type=VaultStore type=LocallyRedundant \
  > "$EVIDENCE/MAN-10-vault.json"
BV_PID="$(jq -er '.identity.principalId' "$EVIDENCE/MAN-10-vault.json")"
azlab role assignment create --assignee-object-id "$BV_PID" \
  --assignee-principal-type ServicePrincipal --role "Disk Backup Reader" \
  --scope "$SOURCE_DISK_ID" > "$EVIDENCE/MAN-10-reader-role.json"
azlab role assignment create --assignee-object-id "$BV_PID" \
  --assignee-principal-type ServicePrincipal --role "Disk Snapshot Contributor" \
  --scope "$RG_ID" > "$EVIDENCE/MAN-10-snapshot-role.json"
azlab role assignment create --assignee-object-id "$BV_PID" \
  --assignee-principal-type ServicePrincipal --role "Disk Restore Operator" \
  --scope "$RG_ID" > "$EVIDENCE/MAN-10-restore-role.json"
azlab dataprotection backup-policy get-default-policy-template --datasource-type AzureDisk \
  > "$EVIDENCE/disk-policy.json"
azlab dataprotection backup-policy create -g "$RG" --vault-name cdde-bv \
  -n manual-disk-policy --policy "$EVIDENCE/disk-policy.json" > "$EVIDENCE/MAN-10-policy.json"
DISK_POLICY_ID="$(jq -er '.id' "$EVIDENCE/MAN-10-policy.json")"
DISK_RULE="$(jq -er '[.properties.policyRules[] | select(.objectType == "AzureBackupRule")] |
  if length == 1 then .[0].name else error("backup rule not unique") end' \
  "$EVIDENCE/MAN-10-policy.json")"
azlab dataprotection backup-instance initialize --datasource-type AzureDisk \
  -l "$LOCATION" --policy-id "$DISK_POLICY_ID" --datasource-id "$SOURCE_DISK_ID" \
  > "$EVIDENCE/disk-instance-template.json"
jq --arg rg "$RG_ID" '
  .properties.policy_info.policy_parameters.data_store_parameters_list |=
  map(if .data_store_type == "OperationalStore" then .resource_group_id = $rg else . end)' \
  "$EVIDENCE/disk-instance-template.json" > "$EVIDENCE/disk-instance.json"
jq -e --arg rg "$RG_ID" '
  any(.properties.policy_info.policy_parameters.data_store_parameters_list[];
    .data_store_type == "OperationalStore" and .resource_group_id == $rg)' \
  "$EVIDENCE/disk-instance.json"
sleep 600
azlab dataprotection backup-instance create -g "$RG" --vault-name cdde-bv \
  --backup-instance "$EVIDENCE/disk-instance.json" > "$EVIDENCE/MAN-10-instance.json"
DISK_INSTANCE="$(jq -er '.name' "$EVIDENCE/MAN-10-instance.json")"
```

The initialize command's payload uses snake_case; the service response uses
camelCase. If your extension emits another schema, stop and inspect it using
that extension's help rather than silently adding an unused property.

**Capture**

```bash
azlab dataprotection job list -g "$RG" --vault-name cdde-bv \
  > "$EVIDENCE/MAN-10-jobs-before.json"
date -u +%FT%TZ > "$EVIDENCE/MAN-10-requested-at.txt"
azlab dataprotection backup-instance adhoc-backup -g "$RG" --vault-name cdde-bv \
  -n "$DISK_INSTANCE" --rule-name "$DISK_RULE" > "$EVIDENCE/MAN-10-backup-request.json"
azlab dataprotection job list -g "$RG" --vault-name cdde-bv \
  > "$EVIDENCE/MAN-10-jobs.json"
```

Identify the new **Backup** job for this exact backup instance by comparing
the job lists, request time and datasource. Save its name as `DISK_JOB`.
Poll the following until Completed; Failed/Cancelled or timeout is ERROR.

```bash
DISK_JOB="<exact-new-backup-job-name>"
azlab dataprotection job show -g "$RG" --vault-name cdde-bv \
  --job-id "$DISK_JOB" > "$EVIDENCE/MAN-10-job.json"
azlab dataprotection recovery-point list -g "$RG" --vault-name cdde-bv \
  --backup-instance-name "$DISK_INSTANCE" > "$EVIDENCE/MAN-10-points.json"
```

Inspect the point time and datasource. Save the exact new point's name and ID:

```bash
DISK_POINT="<exact-new-recovery-point-name>"
jq -e --arg name "$DISK_POINT" '[.[] | select(.name == $name)] | length == 1' \
  "$EVIDENCE/MAN-10-points.json"
date -u +%FT%TZ > "$EVIDENCE/MAN-10-completed-at.txt"
```

**Expected** - Completed job and a new point for the source disk, after
fixture preparation/request. No claim of application-consistent recovery.

## MAN-11 - Azure VM Backup

### Vault, Enhanced policy and key-backup permissions

```bash
azlab backup vault create -g "$RG" -n cdde-rsv -l "$LOCATION" > "$EVIDENCE/MAN-11-vault.json"
azlab backup vault backup-properties set -g "$RG" -n cdde-rsv \
  --backup-storage-redundancy LocallyRedundant
SCHEDULE="$(date -u +%Y-%m-%dT02:00:00+00:00)"
jq -n --arg schedule "$SCHEDULE" '{properties:{
  backupManagementType:"AzureIaasVM",policyType:"V2",timeZone:"UTC",
  instantRpRetentionRangeInDays:2,
  schedulePolicy:{schedulePolicyType:"SimpleSchedulePolicyV2",scheduleRunFrequency:"Daily",
    dailySchedule:{scheduleRunTimes:[$schedule]}},
  retentionPolicy:{retentionPolicyType:"LongTermRetentionPolicy",
    dailySchedule:{retentionTimes:[$schedule],retentionDuration:{count:7,durationType:"Days"}}}
}}' > "$EVIDENCE/vm-policy.json"
azlab backup policy create -g "$RG" --vault-name cdde-rsv -n manual-enhanced \
  --backup-management-type AzureIaasVM --policy "@$EVIDENCE/vm-policy.json" \
  > "$EVIDENCE/MAN-11-policy.json"
azlab rest --method get --resource https://graph.microsoft.com/ \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals?%24filter=appId%20eq%20%27262044b1-e2ce-469f-a196-69ab7ada62d3%27&%24select=id" \
  > "$EVIDENCE/MAN-11-backup-service.json"
BACKUP_SERVICE_PID="$(jq -er '.value |
  if length == 1 then .[0].id else error("backup service principal not unique") end' \
  "$EVIDENCE/MAN-11-backup-service.json")"
jq -n --arg name "cdde-manual-backup-$TOKEN" --arg rg "$RG_ID" '{
  Name:$name,IsCustom:true,Description:"Disposable CDDE lab key read and backup only",
  Actions:[],DataActions:["Microsoft.KeyVault/vaults/keys/read",
    "Microsoft.KeyVault/vaults/keys/backup/action"],AssignableScopes:[$rg]
}' > "$EVIDENCE/backup-key-role.json"
azlab role definition create --role-definition "$EVIDENCE/backup-key-role.json" \
  > "$EVIDENCE/MAN-11-key-role.json"
BACKUP_ROLE_ID="$(jq -er '.id' "$EVIDENCE/MAN-11-key-role.json")"
azlab role assignment create --assignee-object-id "$BACKUP_SERVICE_PID" \
  --assignee-principal-type ServicePrincipal --role "$BACKUP_ROLE_ID" --scope "$KV_ID" \
  > "$EVIDENCE/MAN-11-key-assignment.json"
```

Key backup/read permission belongs to the tenant's Backup Management Service
principal. It is separate from the VM UAMI's SKR roles. Do not grant the
service a broad key-administrator role to work around an error.

### Restore authorization and staging

```bash
azlab backup vault identity assign -g "$RG" -n cdde-rsv --system-assigned \
  > "$EVIDENCE/MAN-11-vault-identity.json"
azlab backup vault show -g "$RG" -n cdde-rsv > "$EVIDENCE/MAN-11-vault-with-identity.json"
RSV_PID="$(jq -er '.identity.principalId' "$EVIDENCE/MAN-11-vault-with-identity.json")"
azlab role assignment create --assignee-object-id "$RSV_PID" \
  --assignee-principal-type ServicePrincipal \
  --role dfce8971-25e3-42e3-ba33-6055438e3080 --scope "$RG_ID" \
  > "$EVIDENCE/MAN-11-vm-restore-role.json"
azlab role assignment create --assignee-object-id "$RSV_PID" \
  --assignee-principal-type ServicePrincipal \
  --role f1a07417-d97a-45cb-824c-7a7467783830 --scope "$UAMI_ID" \
  > "$EVIDENCE/MAN-11-identity-operator-role.json"
azlab role assignment create --assignee-object-id "$RSV_PID" \
  --assignee-principal-type ServicePrincipal \
  --role acdd72a7-3385-48ef-bd42-f606fba81ae7 --scope "$DES_ID" \
  > "$EVIDENCE/MAN-11-des-reader-role.json"
STAGING="cddem${TOKEN}st"
azlab storage account create -g "$RG" -n "$STAGING" -l "$LOCATION" \
  --sku Standard_LRS --kind StorageV2 --allow-blob-public-access false \
  > "$EVIDENCE/MAN-11-staging.json"
sleep 600
azlab backup protection enable-for-vm -g "$RG" --vault-name cdde-rsv \
  --vm "$VM" --policy-name manual-enhanced > "$EVIDENCE/MAN-11-protection.json"
azlab backup item list -g "$RG" --vault-name cdde-rsv \
  --backup-management-type AzureIaasVM --workload-type VM > "$EVIDENCE/MAN-11-items.json"
```

The role IDs above are Virtual Machine Restore Operator, Managed Identity
Operator, and Reader, scoped to this RG, UAMI and DES respectively.
Verify assignments are present and unconditional before recovery.

Select exactly one item whose `properties.virtualMachineId` equals `VM_ID`.
Poll registration until Protected or IRPending with a policy ID. Stop if
SoftDeleted, scheduled for deferred deletion, ProtectionStopped or
ProtectionError; do not silently undelete or switch policy.

```bash
jq --arg id "$VM_ID" '[.[] | select(
  (.properties.virtualMachineId | ascii_downcase) == ($id | ascii_downcase))] |
  if length == 1 then .[0] else error("protected item not unique") end' \
  "$EVIDENCE/MAN-11-items.json" > "$EVIDENCE/MAN-11-item.json"
VM_ITEM="$(jq -er '.name' "$EVIDENCE/MAN-11-item.json")"
VM_CONTAINER="$(jq -er '.id | split("/protectionContainers/")[1] | split("/")[0]' \
  "$EVIDENCE/MAN-11-item.json")"
```

### Capture

Check `backup job list` for this VM and wait for existing backup jobs to
finish before starting another, including scheduled backups.

```bash
azlab backup job list -g "$RG" --vault-name cdde-rsv > "$EVIDENCE/MAN-11-jobs-before.json"
date -u +%FT%TZ > "$EVIDENCE/MAN-11-requested-at.txt"
azlab backup protection backup-now -g "$RG" --vault-name cdde-rsv \
  --container-name "$VM_CONTAINER" --item-name "$VM_ITEM" \
  --backup-management-type AzureIaasVM --retain-until "$(date -u -d '+7 days' +%d-%m-%Y)" \
  > "$EVIDENCE/MAN-11-backup-request.json"
VM_BACKUP_JOB="$(jq -er '.name' "$EVIDENCE/MAN-11-backup-request.json")"
azlab backup job wait -g "$RG" --vault-name cdde-rsv --name "$VM_BACKUP_JOB" --timeout 7200
azlab backup job show -g "$RG" --vault-name cdde-rsv --name "$VM_BACKUP_JOB" \
  > "$EVIDENCE/MAN-11-job.json"
jq -e '.properties.status == "Completed"' "$EVIDENCE/MAN-11-job.json"
azlab backup recoverypoint list -g "$RG" --vault-name cdde-rsv \
  --container-name "$VM_CONTAINER" --item-name "$VM_ITEM" \
  --backup-management-type AzureIaasVM > "$EVIDENCE/MAN-11-points.json"
```

Choose the new point for this exact item after the request/fixture time;
inspect its recovery-point tier and timestamp, not just list ordering.

```bash
VM_POINT="<exact-new-vm-recovery-point-name>"
jq -e --arg name "$VM_POINT" '[.[] | select(.name == $name)] | length == 1' \
  "$EVIDENCE/MAN-11-points.json"
date -u +%FT%TZ > "$EVIDENCE/MAN-11-completed-at.txt"
```

**Expected** - Completed job and usable new point. A completed backup with a
later failed restore is not a recovery PASS. Do not recapture after mutation
and then compare it with this earlier baseline.

## MAN-12 - Mutation and mandatory replay fence

Run **once**, only after all selected captures have completed. This distinguishes
point-in-time recovery from accidentally reading the original disk.

```bash
cat > "$EVIDENCE/mutate-source.sh" <<'GUEST'
set -eu
findmnt -rn --mountpoint /cde-data > /dev/null
printf 'CDDE-MANUAL-AFTER-CAPTURE\n' > /cde-data/manual-suite/checkpoint.txt
printf 'must-not-exist-in-restored-point\n' > /cde-data/manual-suite/after-capture.txt
sync
echo MANUAL_CHECK=PASS
GUEST
guest "$VM" "$EVIDENCE/mutate-source.sh" MAN-12-mutation
cat > "$EVIDENCE/read-only-fence.sh" <<'GUEST'
set -eu
echo MANUAL_CHECK=PASS
GUEST
guest "$VM" "$EVIDENCE/read-only-fence.sh" MAN-12-fence
date -u +%FT%TZ > "$EVIDENCE/MAN-12-fenced-at.txt"
```

**Expected** - Mutation completes and the next Run Command is the completed,
read-only fence. OS-disk rollback can rewind guest-agent state and replay its
active Run Command. Never leave a mutation/formatting payload as the active
command when restoring an OS disk. All later guest commands must be read-only
or idempotent verification with only temporary I/O probes.

## MAN-13 - Restore one path/target

Run sequentially; no concurrent controller or other operator.
For each matrix cell choose a unique `CASE` and new disk/VM names.
Record capture ID, source disk ID, expected restored disk ID, target VM ID,
UTC times, service job ID and actual consistency mode in that case's evidence.

```bash
PATH_NAME="<snapshot-or-restore-point-or-disk-backup-or-vm-backup>"
TARGET="<original-or-replacement>"
CASE="$PATH_NAME-$TARGET"
RESTORED_DISK_NAME="r-$CASE-data"
RESTORED_VM="r-$PATH_NAME"
date -u +%FT%TZ > "$EVIDENCE/$CASE-restore-requested-at.txt"
```

### A. Construct a new disk: snapshot

For `PATH_NAME=snapshot`:

```bash
azlab disk create -g "$RG" -n "$RESTORED_DISK_NAME" -l "$LOCATION" \
  --source "$SNAPSHOT_ID" --sku Premium_LRS > "$EVIDENCE/$CASE-new-disk.json"
RESTORED_DISK_ID="$(jq -er '.id' "$EVIDENCE/$CASE-new-disk.json")"
```

### B. Construct a new disk: restore point

For `PATH_NAME=restore-point`:

```bash
azlab disk create -g "$RG" -n "$RESTORED_DISK_NAME" \
  --source "$DATA_RP_ID" --sku Premium_LRS > "$EVIDENCE/$CASE-new-disk.json"
RESTORED_DISK_ID="$(jq -er '.id' "$EVIDENCE/$CASE-new-disk.json")"
```

Only for the **replacement** restore-point target, also restore the OS disk:

```bash
azlab disk create -g "$RG" -n "$RESTORED_VM-os" --source "$OS_RP_ID" \
  --sku Premium_LRS > "$EVIDENCE/$CASE-os-disk.json"
RESTORED_OS_ID="$(jq -er '.id' "$EVIDENCE/$CASE-os-disk.json")"
```

### C. Construct a new disk: Disk Backup

For `PATH_NAME=disk-backup`:

```bash
RESTORED_DISK_ID="$RG_ID/providers/Microsoft.Compute/disks/$RESTORED_DISK_NAME"
azlab dataprotection backup-instance restore initialize-for-data-recovery \
  --datasource-type AzureDisk --restore-location "$LOCATION" \
  --source-datastore OperationalStore --recovery-point-id "$DISK_POINT" \
  --target-resource-id "$RESTORED_DISK_ID" > "$EVIDENCE/$CASE-restore-body.json"
azlab dataprotection job list -g "$RG" --vault-name cdde-bv \
  > "$EVIDENCE/$CASE-jobs-before.json"
azlab dataprotection backup-instance restore trigger -g "$RG" --vault-name cdde-bv \
  --backup-instance-name "$DISK_INSTANCE" \
  --restore-request-object "$EVIDENCE/$CASE-restore-body.json" \
  > "$EVIDENCE/$CASE-restore-request.json"
azlab dataprotection job list -g "$RG" --vault-name cdde-bv \
  > "$EVIDENCE/$CASE-jobs.json"
```

Identify the new Restore job for this instance/request/target disk. Poll
`azlab dataprotection job show` with its exact `--job-id` every 30 seconds
until Completed, for at most two hours. Save the final job JSON. Stop on
Failed/Cancelled/timeout. Confirm the target managed disk exists:

```bash
azlab disk show --ids "$RESTORED_DISK_ID" > "$EVIDENCE/$CASE-new-disk.json"
jq -e '.provisioningState == "Succeeded"' "$EVIDENCE/$CASE-new-disk.json"
```

### D. Attach disks from A, B or C

For the **original** target, deallocate and replace LUN 0 with the recovered
disk. The original source disk remains detached for rollback.

```bash
TARGET_VM="$VM"
azlab vm deallocate -g "$RG" -n "$TARGET_VM"
```

For a **replacement** target, create a new confidential VM. Use exactly one
of these creation commands:

```bash
# snapshot or disk-backup replacement: fresh confidential OS
azlab vm create -g "$RG" -n "$RESTORED_VM" -l "$LOCATION" --size "$SIZE" \
  --image "$IMAGE" --admin-username cddeadmin \
  --ssh-key-values "$EVIDENCE/deployment-key.pub" --storage-sku Premium_LRS \
  --security-type ConfidentialVM --os-disk-security-encryption-type DiskWithVMGuestState \
  --enable-vtpm true --enable-secure-boot true --disk-controller-type SCSI \
  --os-disk-delete-option Detach --public-ip-sku Standard --nsg-rule NONE \
  --vnet-name cdde-network --subnet workloads --tags "cdde-manual-run=$TOKEN" \
  > "$EVIDENCE/$CASE-vm-created.json"
```

```bash
# restore-point replacement: recovered confidential OS, not a fresh image
azlab vm create -g "$RG" -n "$RESTORED_VM" -l "$LOCATION" --size "$SIZE" \
  --attach-os-disk "$RESTORED_OS_ID" --os-type Linux \
  --security-type ConfidentialVM --os-disk-security-encryption-type DiskWithVMGuestState \
  --enable-vtpm true --enable-secure-boot true --disk-controller-type SCSI \
  --os-disk-delete-option Detach --public-ip-sku Standard --nsg-rule NONE \
  --vnet-name cdde-network --subnet workloads --tags "cdde-manual-run=$TOKEN" \
  > "$EVIDENCE/$CASE-vm-created.json"
```

For replacement only, attach the CDDE UAMI/profile **before** attaching data:

```bash
TARGET_VM="$RESTORED_VM"
TARGET_URL="https://management.azure.com$RG_ID/providers/Microsoft.Compute/virtualMachines/$TARGET_VM?api-version=$API"
wait_vm "$TARGET_VM"
azlab rest --method patch --url "$TARGET_URL" --body "@$EVIDENCE/vm-identity-body.json" \
  > "$EVIDENCE/$CASE-identity-patch.json"
wait_vm "$TARGET_VM"
azlab vm deallocate -g "$RG" -n "$TARGET_VM"
```

For **both** targets from A/B/C:

```bash
TARGET_URL="https://management.azure.com$RG_ID/providers/Microsoft.Compute/virtualMachines/$TARGET_VM?api-version=$API"
azlab rest --method get --url "$TARGET_URL" > "$EVIDENCE/$CASE-before-attach.json"
# Dedicated lab only: refuse to drop any unexpected additional data disk.
jq -e 'all(.properties.storageProfile.dataDisks[]?; .lun == 0)' \
  "$EVIDENCE/$CASE-before-attach.json"
jq -n --arg id "$RESTORED_DISK_ID" --arg name "$RESTORED_DISK_NAME" --arg des "$DES_ID" \
  '{properties:{storageProfile:{dataDisks:[{
    lun:0,name:$name,createOption:"Attach",deleteOption:"Detach",caching:"None",
    managedDisk:{id:$id,storageAccountType:"Premium_LRS",securityProfile:{
      securityEncryptionType:"DataDiskEncryptedWithCustomerKey",diskEncryptionSet:{id:$des}
  }}}]}}}' > "$EVIDENCE/$CASE-attach-body.json"
azlab rest --method patch --url "$TARGET_URL" --body "@$EVIDENCE/$CASE-attach-body.json" \
  > "$EVIDENCE/$CASE-attached.json"
azlab vm wait -g "$RG" -n "$TARGET_VM" --updated --timeout 1800
azlab vm start -g "$RG" -n "$TARGET_VM"
wait_vm "$TARGET_VM"
```

### E. VM Backup service recovery (instead of A-D)

Recheck the Recovery Services vault identity and its three MAN-11 restore
role assignments before source changes. Keep the original disk ID saved.
Do not replace service original/alternate-location restore with manual
disk attachment or a fresh OS.

For the **original** target:

```bash
TARGET_VM="$VM"
azlab vm deallocate -g "$RG" -n "$VM"
azlab backup restore restore-disks -g "$RG" --vault-name cdde-rsv \
  --container-name "$VM_CONTAINER" --item-name "$VM_ITEM" --rp-name "$VM_POINT" \
  --storage-account "$STAGING" --mi-system-assigned --restore-mode OriginalLocation \
  > "$EVIDENCE/$CASE-restore-request.json"
```

For the **replacement** target:

```bash
TARGET_VM="$RESTORED_VM"
azlab backup restore restore-disks -g "$RG" --vault-name cdde-rsv \
  --container-name "$VM_CONTAINER" --item-name "$VM_ITEM" --rp-name "$VM_POINT" \
  --storage-account "$STAGING" --mi-system-assigned --restore-mode AlternateLocation \
  --target-resource-group "$RG" --target-vm-name "$TARGET_VM" \
  --target-vnet-name cdde-network --target-vnet-resource-group "$RG" \
  --target-subnet-name workloads > "$EVIDENCE/$CASE-restore-request.json"
```

For either service target:

```bash
RESTORE_JOB="$(jq -er '.name' "$EVIDENCE/$CASE-restore-request.json")"
azlab backup job wait -g "$RG" --vault-name cdde-rsv --name "$RESTORE_JOB" --timeout 7200
azlab backup job show -g "$RG" --vault-name cdde-rsv --name "$RESTORE_JOB" \
  > "$EVIDENCE/$CASE-job.json"
jq -e '.properties.status == "Completed"' "$EVIDENCE/$CASE-job.json"
azlab vm start -g "$RG" -n "$TARGET_VM"
wait_vm "$TARGET_VM"
TARGET_URL="https://management.azure.com$RG_ID/providers/Microsoft.Compute/virtualMachines/$TARGET_VM?api-version=$API"
azlab rest --method get --url "$TARGET_URL" > "$EVIDENCE/$CASE-service-restored-vm.json"
RESTORED_DISK_ID="$(jq -er '[.properties.storageProfile.dataDisks[] | select(.lun == 0)] |
  if length == 1 then .[0].managedDisk.id else error("restored LUN not unique") end' \
  "$EVIDENCE/$CASE-service-restored-vm.json")"
```

Inspect the restore job's tasks/properties and actual restored disk IDs and
creation metadata. Correlate the new disk with the job/recovery point, target
VM and request time. Do not accept simply discovering an arbitrary LUN 0.

## MAN-14 - Recovery acceptance and rollback

### 1. Prove the restored resource and inspect extension before changes

For **every** path/target:

```bash
test "$RESTORED_DISK_ID" != "$SOURCE_DISK_ID"
azlab rest --method get --url "$TARGET_URL" > "$EVIDENCE/$CASE-restored-vm.json"
azlab disk show --ids "$RESTORED_DISK_ID" > "$EVIDENCE/$CASE-restored-disk.json"
jq -e --arg disk "$RESTORED_DISK_ID" --arg des "$DES_ID" --arg uami "$UAMI_ID" '
  .properties.securityProfile.securityType == "ConfidentialVM" and
  .properties.securityProfile.uefiSettings.secureBootEnabled == true and
  .properties.securityProfile.uefiSettings.vTpmEnabled == true and
  .properties.securityProfile.confidentialDataDiskEncryptionIdentity.userAssignedIdentityResourceId == $uami and
  (.identity.userAssignedIdentities | has($uami)) and
  .properties.storageProfile.osDisk.managedDisk.securityProfile.securityEncryptionType == "DiskWithVMGuestState" and
  ([.properties.storageProfile.dataDisks[] | select(.lun == 0)] |
    length == 1 and .[0].managedDisk.id == $disk and
    .[0].managedDisk.securityProfile.securityEncryptionType == "DataDiskEncryptedWithCustomerKey" and
    .[0].managedDisk.securityProfile.diskEncryptionSet.id == $des)
  ' "$EVIDENCE/$CASE-restored-vm.json"
azlab vm extension list -g "$RG" --vm-name "$TARGET_VM" \
  > "$EVIDENCE/$CASE-extension-inventory.json"
```

Compare location/size, restored disk `managedBy`, creation source, provisioning
state and capture/job IDs with your case notes. Recheck the key, DES, vault
and their roles using MAN-04; source-key availability is part of recovery.
Resource IDs are case-insensitive: if Azure returns different casing, compare
normalized IDs explicitly rather than changing which resource is expected.

**Check-first extension policy**

- Existing healthy CDELinux: run `inspect_extension`; leave settings unchanged.
- Existing in-progress CDELinux: poll read-only for at most 30 minutes.
- Existing failed/invalid CDELinux: preserve and stop the strict case. Do not
  repair, reinstall or change its sequence. Record the failure stage.
- Only if the **initial** inventory proves CDELinux absent, install it once:

```bash
# Execute only after manually confirming initial inventory contains no CDELinux.
SEQ="$(cat /proc/sys/kernel/random/uuid)"
azlab vm extension set -g "$RG" --vm-name "$TARGET_VM" --publisher "$PUBLISHER" \
  -n CDELinux --version 1.0 --settings "{\"sequenceVersion\":\"$SEQ\"}" \
  > "$EVIDENCE/$CASE-initial-install-intervention.json"
```

Record that necessary installation as an intervention, not a restore-only
reproduction. A restored OS can contain cached handler files without an ARM
extension resource. After this initial decision, a disappearing extension at
any checkpoint is FAIL, not permission to reinstall.

```bash
inspect_extension "$TARGET_VM" "$CASE-initial"
```

### 2. Optional initial mount of an existing decrypted mapper

Never run `mkfs`, `luksFormat`, manual key export or plaintext recovery.
If `/cde-data` is not mounted but an existing unlocked LUN-0 mapper is present,
an initial mount is allowed. First inspect the devices:

```bash
azlab vm run-command invoke -g "$RG" -n "$TARGET_VM" --command-id RunShellScript \
  --scripts 'lsblk -p -o NAME,TYPE,FSTYPE,MOUNTPOINTS; findmnt --mountpoint /cde-data' \
  > "$EVIDENCE/$CASE-initial-mount-inspection.json"
```

If needed, replace the placeholder with the **existing** crypt mapper and
run once, recording this initial mount intervention:

```bash
cat > "$EVIDENCE/$CASE-initial-mount.sh" <<'GUEST'
set -eu
mapper="<existing-/dev/mapper/path-for-restored-LUN-0>"
test "$(lsblk -dn -o TYPE "$mapper")" = crypt
lsblk -srnp -o NAME "$mapper" | grep -Fx "$(readlink -f /dev/disk/azure/scsi1/lun0)"
mkdir -p /cde-data
mount "$mapper" /cde-data
echo MANUAL_CHECK=PASS
GUEST
guest "$TARGET_VM" "$EVIDENCE/$CASE-initial-mount.sh" "$CASE-initial-mount"
```

If the original LUKS data cannot be unlocked by the platform/extension, fail
the case; do not create a new filesystem. Later lifecycle checkpoints must
remount normally without manual intervention.

### 3. Three mandatory checkpoints on the same recovered disk

Initial:

```bash
guest "$TARGET_VM" "$EVIDENCE/verify-fixture.sh" "$CASE-initial"
grep -qx FIXTURE_CHECK=PASS "$EVIDENCE/$CASE-initial.txt"
```

Restart:

```bash
azlab vm restart -g "$RG" -n "$TARGET_VM"
wait_vm "$TARGET_VM"
inspect_extension "$TARGET_VM" "$CASE-restart"
guest "$TARGET_VM" "$EVIDENCE/verify-fixture.sh" "$CASE-restart"
grep -qx FIXTURE_CHECK=PASS "$EVIDENCE/$CASE-restart.txt"
```

Deallocate/start:

```bash
azlab vm deallocate -g "$RG" -n "$TARGET_VM"
azlab vm start -g "$RG" -n "$TARGET_VM"
wait_vm "$TARGET_VM"
inspect_extension "$TARGET_VM" "$CASE-deallocate-start"
guest "$TARGET_VM" "$EVIDENCE/verify-fixture.sh" "$CASE-deallocate-start"
grep -qx FIXTURE_CHECK=PASS "$EVIDENCE/$CASE-deallocate-start.txt"
azlab rest --method get --url "$TARGET_URL" > "$EVIDENCE/$CASE-final-vm.json"
jq -e --arg id "$RESTORED_DISK_ID" '[.properties.storageProfile.dataDisks[] |
  select(.lun == 0 and .managedDisk.id == $id)] | length == 1' \
  "$EVIDENCE/$CASE-final-vm.json"
date -u +%FT%TZ > "$EVIDENCE/$CASE-restore-verified-at.txt"
```

**Expected** - Every checkpoint preserves exact recovered resource identity,
confidential settings, LUKS2/dm-crypt and LUN ancestry, original payload and
pre-capture marker hashes, directory/file ownership and permissions, absence
of post-capture files, fresh volume I/O and healthy extension. Repeat the
MAN-04 ARM/key/RBAC assertions against this target, without mutation.

If any checkpoint fails, the whole matrix cell is FAIL/ERROR as appropriate.
Do not reuse the same label to hide a failure. Do not record a final PASS
until rollback and source-health checks below have also completed.

### 4. Roll back the original data disk / release replacement cores

For **original** target cases, restore the saved original source disk to LUN 0
using MAN-13 D's attachment payload, with the following values. Do **not**
recapture or overwrite the external baseline.

```bash
TARGET_VM="$VM"
RESTORED_DISK_ID="$SOURCE_DISK_ID"
RESTORED_DISK_NAME="cdde-source-data"
```

Deallocate the source first, then run the shared attachment commands in
MAN-13 D starting at `TARGET_URL=...`, through start/readiness. This is a
data-disk rollback only: VM Backup original-location restore may have
replaced the OS disk; this procedure does not restore its pre-test OS.
Azure may also create a preservation backup during original-location restore.

For **replacement** target cases, retain evidence and deallocate that VM
before creating the next replacement so the quota assumption stays valid:

```bash
azlab vm deallocate -g "$RG" -n "$TARGET_VM"
```

After each case verify the source's MAN-04 encryption/identity/extension
health, original source disk ID and **post-capture** data. The source was
intentionally mutated, so do not expect the pre-capture fixture script to
pass against the original disk:

```bash
guest "$VM" "$EVIDENCE/check-encryption.sh" "$CASE-source-encryption"
inspect_extension "$VM" "$CASE-source-health"
{
  printf 'set -eu\nexpected_payload=%q\n' "$PAYLOAD_HASH"
  cat <<'GUEST'
test "$(sha256sum /cde-data/manual-suite/payload.bin | cut -d ' ' -f1)" = "$expected_payload"
test "$(stat -c '%u:%g:%a' /cde-data/manual-suite/payload.bin)" = "1000:1000:640"
test "$(stat -c '%u:%g:%a' /cde-data/manual-suite/checkpoint.txt)" = "0:0:600"
test "$(stat -c '%u:%g:%a' /cde-data/manual-suite)" = "0:0:750"
test "$(cat /cde-data/manual-suite/checkpoint.txt)" = CDDE-MANUAL-AFTER-CAPTURE
test "$(cat /cde-data/manual-suite/after-capture.txt)" = must-not-exist-in-restored-point
echo MANUAL_CHECK=PASS
GUEST
} > "$EVIDENCE/check-source-after-capture.sh"
guest "$VM" "$EVIDENCE/check-source-after-capture.sh" "$CASE-source-mutation"
```

Use a fresh read-only fence before another OS restore. If rollback/source
health fails, stop further matrix cells and retain the lab for investigation.
Only after capture/job evidence, restore provenance, all three checkpoints
and source rollback/health have passed:

```bash
printf 'MAN-14,%s,%s,all,PASS,%s,exploratory; initial extension/mount interventions recorded separately\n' \
  "$PATH_NAME" "$TARGET" "$CASE" >> "$EVIDENCE/results.csv"
```

## MAN-15 - Final evidence, diagnostics and cleanup

### Acceptance and handoff

Record every MAN case selected, all eight recovery matrix cells and all three
checkpoints per attempted cell. Mark omitted cells NOT_EVALUATED explicitly.
Include source/target resource IDs, point/job IDs, timestamps, consistency
mode, CLI version, extension state before/after each boot, interventions,
errors and rollback status. Do not describe general service documentation as
proof of CDDE support.

This manual suite mirrors the major automated scenarios, not the automated
39-check/JUnit report format. The customer's signed case sheet and saved CLI/
guest evidence are its deliverable. Do not claim application-consistent
database recovery, cross-region/tenant recovery, all restore tiers,
replacement-key recovery, emergency revocation or an independent VMGS
attestation audit.

Create a checksum manifest after recording the final results. Exclude the
temporary deployment private key and the checksum file itself:

```bash
rm "$EVIDENCE/deployment-key"
(cd "$EVIDENCE" &&
  find . -type f ! -name SHA256SUMS -print0 | sort -z |
  xargs -0 -r sha256sum > SHA256SUMS)
(cd "$EVIDENCE" && sha256sum -c SHA256SUMS)
```

Keep evidence access-controlled; IDs, guest output and service diagnostics
can contain customer-sensitive information. Review/redact a separate copy
before sharing. Do not include access tokens, SAS URLs or key material.
If you add cleanup evidence later, regenerate the manifest.

For failures, collect narrow guest log excerpts from
`/var/log/azure/Microsoft.Azure.Security.ConfidentialDiskEncryption.CDELinux/`,
the handler status and the failed service job. Record when failure first
appeared (before extension writes, after necessary initial installation,
restart or deallocate/start). Do not infer a root cause from CDE306 alone.
The optional [diagnostic collector](collect-cdde-logs.py) is a separate
tool, not required to execute this manual suite.

### Retain

Deallocate source and replacement VMs if investigation does not require them
running, **after restoring any removed release role**. Record remaining
resources and expected charges. Retention is not cleanup.

### Destroy (explicit operator approval required)

Do not execute deletion until the customer approves destruction of the
disposable lab and evidence has been saved locally.

1. Verify the exact subscription, group ID and ownership tag:

```bash
azlab group show -n "$RG" > "$EVIDENCE/cleanup-group.json"
jq -e --arg id "$RG_ID" --arg token "$TOKEN" \
  '.id == $id and .tags["cdde-manual-run"] == $token' "$EVIDENCE/cleanup-group.json"
azlab resource list -g "$RG" > "$EVIDENCE/cleanup-inventory.json"
```

2. If MAN-11 created protection, stop protection and request deletion of its
   backup data. Use the saved exact item/container, not a wildcard:

```bash
azlab backup protection disable -g "$RG" --vault-name cdde-rsv \
  --container-name "$VM_CONTAINER" --item-name "$VM_ITEM" \
  --backup-management-type AzureIaasVM --delete-backup-data true --yes
```

3. If MAN-10 created a backup instance, request its deletion:

```bash
azlab dataprotection backup-instance delete -g "$RG" --vault-name cdde-bv \
  --backup-instance-name "$DISK_INSTANCE" --yes
```

4. Review active jobs, retained/soft-deleted items, vault dependencies and any
   backup-created resource groups or preserved disks outside this group.
   Always-On soft delete **cannot be disabled**. Follow service retention and
   approved vault-deletion procedures. If retained data prevents group deletion,
   report cleanup BLOCKED with exact resources and a follow-up date; do not
   weaken protection, purge keys or downgrade APIs.
5. When service dependencies allow deletion, delete only this owned group:

```bash
azlab group delete -n "$RG" --yes
azlab group exists -n "$RG" -o tsv
# Expected: false. If not false or deletion fails, cleanup is incomplete.
```

6. After its scoped role assignment is gone, remove only the custom role
   created in MAN-11 (skip if never created):

```bash
azlab role definition delete --name "${BACKUP_ROLE_ID##*/}"
```

7. Save final inventory/deletion results and regenerate evidence checksums.
   Verify any backup-generated resources separately using their saved IDs.
   Key Vault purge protection and retained backup data can continue beyond
   group deletion. Subscription provider/feature registrations remain and
   are intentionally not unregistered.

## Official references

Preview behavior can change; verify these before a customer execution:

- [Azure CLI installation](https://learn.microsoft.com/cli/azure/install-azure-cli-linux)
- [Confidential VM overview](https://learn.microsoft.com/azure/confidential-computing/confidential-vm-overview)
- [VM restore-point support matrix and confidential VM preview](https://learn.microsoft.com/azure/virtual-machines/concepts-restore-points)
- [Azure Disk Backup using CLI](https://learn.microsoft.com/azure/backup/backup-managed-disks-cli)
- [Restore Azure Managed Disks using CLI](https://learn.microsoft.com/azure/backup/restore-managed-disks-cli)
- [Azure VM restore using CLI](https://learn.microsoft.com/azure/backup/backup-azure-arm-restore-vms)
- [Azure CLI backup restore reference](https://learn.microsoft.com/cli/azure/backup/restore)
- [Azure CLI Data Protection reference](https://learn.microsoft.com/cli/azure/dataprotection)
- [Azure Backup soft delete](https://learn.microsoft.com/azure/backup/backup-azure-security-feature-cloud)
