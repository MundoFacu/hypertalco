# Verification and disposable integration lab

Current evidence includes Python unit/API tests, a simulated local browser preview,
and real engine/guest tests inside a disposable nested Ubuntu VM. No bare-metal
installation was tested. The --plan wizard exited without mutations. The preview's
guests and catalogs are simulated.

## Automated local checks

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q hypertalco scripts
bash -n hypertalco-installer.sh install.sh
node --check hypertalco/static/app.js
node --input-type=module --check < hypertalco/static/console.js
python3 scripts/package_release.py
```

Some managed sandboxes reject SO_PEERCRED or virtualize root ownership. Run the
Linux peer-credential/ownership tests in an ordinary unprivileged Linux process;
do not skip them to claim a pass. Tests use temporary files/mocks; no real engine
is connected. CI is prepared, not run on GitHub. Unit success is not evidence of
systemd, package compatibility or working guests.

## Stage 1: nested virtualization, not a physical host

Use a disposable VM on an explicitly authorized lab hypervisor. Give it a CPU exposing virtualization extensions,
nested KVM, 4–8 vCPU, 8–16 GiB RAM, a ~32 GiB system disk and a second ~64 GiB
virtual data disk. These are test sizing suggestions, not measured requirements.
Inside the target verify `/dev/kvm` is present and usable. Without nested KVM,
Docker/LXC can be tested but the QEMU/KVM path is not accepted.

For a read-only check on either CPU family, skip absent module paths rather than
treating grep's missing-file status as disabled nesting:

```bash
for m in kvm_intel kvm_amd; do p="/sys/module/$m/parameters/nested"; if [ -r "$p" ]; then printf '%s: ' "$m"; cat "$p"; fi; done
```

Y/1 means enabled; N/0 means disabled. This does not establish guest-side KVM
availability: pass the host CPU virtualization features to the test VM and check
`/dev/kvm` there separately.

Use a dedicated virtual lab segment with outbound internet for apt/templates,
not a production LAN bridge. Start with Debian 13 and Ubuntu 24.04; then run the
installer matrix for every declared OS/architecture before declaring support.
The current code admits Debian 12/13, Ubuntu 22.04/24.04/26.04 and x86_64/aarch64;
these are targets, not a certified matrix. ARM requires an appropriate ARM host.

Take a powered-off clean snapshot before installation. Keep the hypervisor console
available. For each test record installer source hash, OS/kernel, package versions,
answers, install receipt, redacted logs and pass/fail. Never record passwords or
registry tokens. Full rollback is restoring the VM snapshot.

## Acceptance gates

1. **Preflight/wizard:** defaults and custom mounted paths; subnet conflict, occupied
   ports, invalid/symlink paths and missing KVM fail before package changes.
2. **Install:** talcoadmin exists, service account has no login/sudo/Docker group;
   services have the declared identities, only the expected listeners are exposed.
   Test clean network default and existing bridge in separate snapshots.
3. **Docker:** anonymous Hub search/pull, cached offline image, optional private
   registry, CPU/RAM/ports/volume, stop/start/restart, logs, resize and deletion.
   Ensure named volumes remain. Verify local API version negotiation.
4. **LXC:** Debian/Ubuntu official templates, custom template cache, mapped UID/GIDs,
   DHCP, SSH key as talco, CPU/RAM cgroup limits, lifecycle, logs and autostart.
   Isolated CT provisioning must reject without creating a partial container.
5. **QEMU/KVM:** ISO from HTTPS and a mounted path, expected SHA256, BIOS/UEFI,
   disk location, VNC through HTTPS, guest install, nested acceleration, shutdown,
   resource editing and deletion only after stopped. Different architecture ISOs
   are not promised; guest OS must support the selected virtual hardware.
6. **Network preservation:** compare host IP/default route before/after, guest NAT
   egress, isolated guest no egress, DHCP and additional-network deletion guards.
   Check Docker/libvirt after reboot and after Docker daemon restart.
7. **Failures/recovery:** interrupted downloads, checksum mismatch, limited virtual
   filesystem, agent/worker restart and partial guest creation. No automatic replay
   of running jobs. Check error state and inspect retained data, not just job status.
8. **Upgrade:** snapshot with real test guests/data; run --upgrade, verify settings,
   credentials and guest data persist. Exercise a deliberate setup failure and
   inspect partial rollback. Restore snapshot for the next case.
9. **Security:** no unauthenticated API reads/mutations, CSRF/Origin rejection,
   socket denied to another OS user, foreign guests cannot be changed, VNC tickets
   expire, passwords/tokens absent from argv/journals/API job payloads.

Repeat from the clean snapshot, not merely an already configured machine.

## Stage 2: hardware-specific acceptance

Only after the lab gates pass: an explicitly authorized spare physical machine or
spare boot disk with an independent restore image and console access. Validate
firmware virtualization/IOMMU where applicable, NIC behaviour, storage permissions,
AppArmor, cold boot and resource pressure. Nested virtualization cannot prove
hardware compatibility, physical network safety or crash recovery. GPU/passthrough,
cluster/HA, migration, backups/restores and storage pool management are not
implemented features of this version.
