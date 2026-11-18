# 🖥️ HyperTalco

**A self-hosted virtualization dashboard for the Debian or Ubuntu server you already run.**

Picture a mini PC under your desk. You want to run a web app from Docker Hub, give a build job its own Debian environment, and boot an ISO to try another operating system. On a stock Linux host, those jobs send you to three different sets of tools. Even figuring out what is running and how much memory is left takes a few trips to the terminal.

HyperTalco installs **Docker Engine, native unprivileged LXC, and QEMU/KVM** and puts their everyday controls in one small, CDE-inspired web interface. Pull an image, create a container, or watch a VM boot through noVNC. Your host keeps its distribution, management address, and normal package repositories. You update the engines with APT and upgrade HyperTalco separately. The project is MIT-licensed, with no subscription or cloud account required.

**[Get started](#-quick-start)** · **[Installation guide](docs/INSTALL.md)** · **[Releases](https://github.com/MundoFacu/hypertalco/releases)**

![HyperTalco dashboard showing host resources, all three engines, and a sample guest inventory](docs/overview.png)

*The demo node has an Nginx container, a Debian system container, and a stopped build VM. Their status and allocations share one inventory.*

## 🤔 Why use this instead of Proxmox VE?

**Choose HyperTalco** if you have one compatible Debian or Ubuntu host, want to keep administering that OS, and regularly work with Docker images alongside system containers and full VMs. A typical example is a home server where you pull an application from Docker Hub today and install a guest from an ISO tomorrow.

**Choose Proxmox VE** if you want an integrated virtualization platform for KVM and LXC, especially if your plans include multiple nodes, high availability, live migration, or integrated storage and backup management. Those are concrete reasons to start with Proxmox. Both projects are open source. [Proxmox VE feature overview](https://www.proxmox.com/en/products/proxmox-virtual-environment/overview)

## 🚀 Quick start

1. **Check the host.** You need systemd, cgroup v2, working KVM, root access, package repository access, and at least **10 GiB free on the filesystem containing `/var/lib`**. Enable CPU virtualization in firmware. Preflight accepts Debian 12/13 and Ubuntu 22.04/24.04/26.04 on x86_64 or aarch64. Clean bare-metal installs were tested on **Ubuntu Server 24.04.5 x86_64**.
2. **Size your lab and take a recoverable backup.** A starting point is 4 CPU threads, 8 GiB RAM, a 32 GiB system disk, and separate capacity for guests. An LVM root snapshot excludes separate boot and EFI partitions.
3. **Run the interactive installer** in a terminal on the target host:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/MundoFacu/hypertalco/v1.0.1/hypertalco-installer.sh | sudo bash -s -- --repo MundoFacu/hypertalco --version 1.0.1
   ```

4. Press **Enter** to accept each suggested network, storage path, and HTTPS listener. Check that the proposed subnets fit your LAN. Review the plan, type **INSTALL**, then choose a web password of at least 12 characters.
5. Open **`https://YOUR-SERVER-IP:8443/`** on your management network and sign in as **talcoadmin**. The initial installation generates a self-signed certificate.

> Want to see every question first? From a source checkout, run `bash hypertalco-installer.sh --plan` for an interactive preview. The [installation guide](docs/INSTALL.md) explains the defaults, preflight checks, services, and recovery limits.

## 🧰 Pick your first guest

| I want to… | Start here |
|---|---|
| 🐳 **Run an application** | Open **Docker images**, search Docker Hub or pull by name and tag, then create a container. Set published ports, environment variables, and a persistent volume as needed. |
| 📦 **Get a Linux environment with its own userspace** | Open **CT templates** and choose an official template or upload a Debian/Ubuntu rootfs archive (`.tar.xz`, `.tar.gz`, or `.tar.zst`). Supply your SSH public key when creating the unprivileged container. |
| 💿 **Install a guest OS** | In **Library → ISO media**, upload an ISO from your browser or import it from a URL or mounted host path. Select **Create VM** on the ISO card, allocate CPU, RAM, and disk, then use **Open console** to finish the OS installation. |

## What you can manage

Start and stop guests, resize CPU and memory while a guest is stopped, inspect metrics and logs, and review jobs and audit events. Configure NAT, isolated networks, or an existing bridge where supported. Mount network shares on Linux before importing their ISOs. The web service uses an unprivileged account and asks a local root agent to perform specific operations. Normal dashboard use requires no sudo prompts.

**Scope:** HyperTalco manages a single host. Clustering, HA, live migration, scheduled backups, storage pool administration, and host VLAN/bond configuration are outside this release. Guests created by other tools appear read-only. Installer rollback is partial and can leave packages, network configuration, and guest data behind.

## 🎛️ Try the dashboard locally

With Python 3.10+ and an ordinary user account, run this from the checkout:

```bash
python3 -m hypertalco dev --port 8768 --data-dir /tmp/hypertalco-preview
```

Visit `http://127.0.0.1:8768/` and sign in with the demo credentials `talcoadmin` / `hypertalco-preview-only`. The preview simulates guests and reads local host metrics.

[Networking](docs/NETWORKING.md) · [Security](docs/SECURITY.md) · [Architecture](docs/ARCHITECTURE.md) · [Testing](docs/TESTING.md) · [MIT license](LICENSE)

🍳 **cooked in [vibetool.cloud](https://vibetool.cloud) sauce**
