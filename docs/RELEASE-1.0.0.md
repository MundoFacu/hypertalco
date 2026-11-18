# HyperTalco 1.0.0

The first release brings Docker applications, unprivileged LXC containers, and QEMU/KVM virtual machines together on an existing Debian or Ubuntu host.

- Configure guest networks, storage, and HTTPS through the interactive installer.
- Upload ISOs and container templates from a browser, or pull application images from Docker Hub.
- Install guest operating systems through noVNC and monitor all three engines on one dashboard.

Clean installs were tested on physical Ubuntu Server 24.04.5 x86_64, including an Alpine UEFI guest that booted from its virtual disk after the ISO was removed.

To verify the release archive, download the tarball and its checksum to the same directory and run `sha256sum -c hypertalco-1.0.0.tar.gz.sha256`.

[Dashboard and getting started](https://github.com/MundoFacu/hypertalco#readme) · [Installation guide](https://github.com/MundoFacu/hypertalco/blob/main/docs/INSTALL.md)

🍳 **cooked in [vibetool.cloud](https://vibetool.cloud) sauce**
