# Architecture

The HTTPS WSGI web application runs as the dedicated `hypertalco` user under
Gunicorn. It owns authentication, hashed sessions, CSRF validation and its local
SQLite job/audit database. A separate worker claims jobs transactionally.

The root agent accepts bounded JSON over a Unix socket. Linux SO_PEERCRED limits
access to the configured service UID and root. Every privileged request is
validated again. No generic shell, arbitrary command API, host bind mount API, or
Docker socket is exposed to the browser/web process. Existing resources are
visible but cannot be changed until a future explicit adoption mechanism exists.

Docker is controlled through its local Engine API. LXC and libvirt operations use
fixed executable argument arrays. Managed identifiers and paths are allocated by
the agent and kept in a root-owned registry. Guest deletion requires a stopped
guest and exact name confirmation; VM disks are limited to that registry.

Production has HTTPS, HttpOnly/SameSite sessions, password hashing with scrypt,
shared login throttling, same-origin checks and CSRF tokens. No default production
password. Local preview data and credentials are isolated from production.

Hypervisor access is powerful: the root agent, installer and authentication
boundary require review. Container isolation is not a guarantee against kernel
vulnerabilities. A successful unit test is not bare-metal acceptance.
