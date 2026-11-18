# Installation and local preparation

The 1.0.0 installer passed clean interactive installs on physical Ubuntu
Server 24.04.5 x86_64 and was also exercised in nested Ubuntu VMs. The public
GitHub bootstrap requires a published release. See [test coverage](TESTING.md)
and [security](SECURITY.md).

## Minimum requirements

- Debian 12/13 or Ubuntu 22.04/24.04/26.04; x86_64 or aarch64 are accepted
  by preflight. Ubuntu 24.04.4 and 24.04.5 x86_64 in nested VMs were tested.
- systemd, cgroup v2, `/dev/kvm`, CPU virtualization enabled, root access for
  installation, working network and at least 10 GiB free under `/var/lib`.
- Lab sizing used successfully: 4 CPU threads, 8 GiB RAM, 32 GiB OS disk and a
  separate 64 GiB virtual disk for guests. These are observed lab resources,
  not an established minimum; size guest storage and RAM for actual workloads.
- Bare metal is the intended target; a VM with nested KVM is suitable for lab
  testing. Running the installer inside an OS container is rejected.

## Inspect without installation

Requires Python 3.10+, Bash and the host's `ip` tool. From the source tree:

```bash
bash hypertalco-installer.sh --plan --source "$PWD"
```

The interactive plan displays interfaces/default routes and asks for:

- VM/LXC network: NAT + DHCP, an existing host bridge, or isolated + DHCP.
- Docker network: NAT or isolated; private IPv4 /24 subnets.
- VM/LXC guest directory, default ISO directory, LXC template-cache directory.
- Docker image/volume directory on a new Engine; an existing data-root is retained.
- Web IPv4 listener and HTTPS port (default 8443).

`--plan` stops after displaying choices. It does not ask for a password, install
packages or write configuration. `--check` runs read-only target preflight using
CLI defaults/options. Target checks include supported OS/architecture, systemd,
cgroup v2, KVM, route overlaps, free space and occupied ports. Containers are
rejected; VMs with working nested KVM are valid lab targets.

The installer checks the KVM API as root, reports limited CPU/RAM and missing
default route as warnings, and warns that apt mirror access is not verified until
apt runs. It recommends a verified host backup or snapshot and recovery console.
An LVM root-only snapshot does not cover separate `/boot` or EFI filesystems.
Package scripts can modify them; the normal installer does not protect them.

## Actual installation on an authorized test host

Run this only on an explicitly selected test host.
The operator reviews the plan and types `INSTALL` before any package/config change.
The password is entered twice without echo and kept out of shell history and argv.
Only a scrypt hash reaches the application database. No default production password.

On the target host, from a reviewed copy of the source tree, run as root:

```bash
bash hypertalco-installer.sh --source "$PWD"
```

If operating as a user with sudo, use `sudo bash hypertalco-installer.sh --source
"$PWD"` instead. `install.sh` is a compatibility wrapper for the same entry point.
The first lab install invoked the Python coordinator directly with custom storage
arguments. `bash install.sh --source "$PWD" --upgrade` was subsequently run
successfully on the existing lab host. A fresh `install.sh --source` installation
was also verified in a separate clean VM. The remote one-liner remains unverified.

### Example: defaults used on the physical test host

The physical-host test accepted all ten defaults listed below. Choose
non-overlapping subnets and paths appropriate for your own host.

| Prompt | Lab answer | Meaning |
|---|---|---|
| VM / LXC network mode | `1` | NAT and DHCP; host management interface preserved |
| VM / LXC private subnet | `10.77.0.0/24` | Private guest network |
| Docker network mode | `1` | NAT |
| Docker private subnet | `10.78.0.0/24` | Separate Docker network |
| VM / LXC guest directory | `/var/lib/hypertalco-guests` | QEMU and LXC data |
| Default ISO library directory | `/var/lib/libvirt/images/hypertalco/iso` | Imported media |
| Default LXC template cache | `/var/cache/lxc` | Container templates |
| Docker image / volume data-root | `/var/lib/docker` | New Docker installation |
| Web listener IPv4 | `0.0.0.0` | All IPv4 interfaces |
| Web HTTPS port | `8443` | Management HTTPS |
| Confirmation | `INSTALL` | Apply the displayed plan |
| `talcoadmin` password | At least 12 characters, entered twice | Not recorded in this guide |

For separate guest storage, mount the filesystem before running the wizard and
enter its paths at the storage prompts. The public web
account is independent from the OS login. The HTTPS certificate is self-signed.
Review firewall exposure and connect to `https://HOST:8443/` as `talcoadmin`.

The installer then installs all engines and dependencies from distro repositories:
Docker Engine, native LXC, libvirt/QEMU/KVM, firmware, noVNC/websockify, nginx and
Gunicorn. Python application dependencies use the standard library. A dedicated
`hypertalco` system account has no login shell, sudo grants or Docker-group access.
The default web administrator is **talcoadmin**, independently of OS users.
See [privilege boundaries](SECURITY.md).

The pinned GitHub installer downloads the release archive and its SHA256 file,
checks the digest and rejects unsafe archive members before running the wizard.

```bash
curl -fsSL https://raw.githubusercontent.com/MundoFacu/hypertalco/v1.0.1/hypertalco-installer.sh | sudo bash -s -- --repo MundoFacu/hypertalco --version 1.0.1
```

## Paths and services

| Path | Owner/use |
|---|---|
| `/opt/hypertalco/releases/`, `current` | Root-owned, version/hash-specific application source |
| `/etc/hypertalco/config.json` | Root-owned web configuration, service group can read |
| `/etc/hypertalco/agent.json` | Root-only privileged configuration |
| `/var/lib/hypertalco` | Service-owned auth, sessions, jobs and audit database |
| `/var/lib/hypertalco-agent` | Root-only guest/media registry and registry tokens |
| `/run/hypertalco-agent` | Root/service-group Unix socket and short-lived VNC tickets |
| `/var/lib/hypertalco-guests/{qemu,lxc}` | Default VM disks and native LXC containers; configurable |
| `/var/lib/libvirt/images/hypertalco/iso` | Default imported ISO library; configurable |
| `/var/cache/lxc` | Default native CT template cache; configurable if helper supports it |
| `/var/lib/docker` | Default Docker images/volumes; configurable only on a fresh Engine |
| `/var/backups/hypertalco` | Root-only installer configuration/upgrade database backups |

Storage directories must be absolute, root-owned and outside service-writable or
system directories. Symlink ancestors, overlapping locations and writable parent
directories are rejected. Mount storage before installation; the installer creates
directories and never partitions/formats devices. CT rootfs storage needs Linux
ownership/idmapping semantics; SMB is an ISO source, not a validated CT rootfs.

Production exposes nginx HTTPS on 8443 by default, with a self-signed certificate.
Trust/replace it as the operator; automated browser tests do not bypass certificate
warnings. Gunicorn and websockify listen only on loopback. The installer records
initial hostnames/IPs; add new DNS names/IPs to `allowed_hosts` explicitly if needed.
Distro nginx may retain its packaged default site on port 80; inspect this during
lab acceptance. Firewall admission for the management port remains operator-owned.

## Upgrades and recovery

`--upgrade` retains existing network/storage settings and stops application services
while backing up SQLite. It preserves guests. Source releases and previous config
are retained. On an exception in configuration, the installer attempts to restore
managed system files and the previous source pointer. This is **partial rollback**:
installed packages, created networks/directories, account and sysctl runtime state
remain. Failure after configuration (admin setup/service start) requires operator
inspection. Use the lab snapshot for full rollback; do not claim transactional OS
installation. Full uninstall/data migration is not implemented.

Inspect the root-only receipt and backup path, compare config with the backup,
check `systemctl status hypertalco-{agent,web,worker,console,network,lxc}` and the
corresponding journal. Never remove Docker/libvirt networks or guest directories
as a generic recovery action. Interrupted jobs are marked for inspection rather
than automatically replayed. A partly created guest may require root-side repair;
its registry record is retained so it is not silently lost.

**cooked in [vibetool.cloud](https://vibetool.cloud) sauce**
