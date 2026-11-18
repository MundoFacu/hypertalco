# Identity and privilege model

No sudo prompt is required during normal web use. The installer runs once as
root to install packages, create users and register systemd services. systemd then
starts each service with its intended identity; the web service cannot choose its
identity or edit the root-owned unit/configuration.

| Identity/process | Privileges and responsibility |
|---|---|
| `talcoadmin` | Application administrator, password stored as scrypt; not an OS login |
| `hypertalco` | System account with nologin: Gunicorn, job worker, websocket proxy; no sudo/Docker group |
| Root agent | Local Unix socket; validates fixed guest/media/network operations and ownership |
| Docker Engine | Standard rootful distro Docker daemon; API socket only reached by agent |
| libvirt daemons | Standard distro privilege separation; QEMU guests run under distro QEMU identity |
| Native LXC | Root-side launcher; container root maps to subordinate host UID/GIDs |
| Guest `talco` | Key-based SSH and guest-local sudo for CT administration; no host sudo grant |

`/run/hypertalco-agent/agent.sock` is root:hypertalco 0660 under a root-owned 0750
directory. The agent checks Linux SO_PEERCRED against the configured service UID
(and root) on every connection. A different user cannot authenticate by supplying
a username in JSON. Only bounded, explicitly dispatched operations exist: no
shell/command endpoint, arbitrary bind mount, privileged container flag or host
configuration editor. Runtime identifiers are checked against the root registry.
Connections/outputs/timeouts are bounded. Guest lifecycle jobs are serialized.

The web service authenticates talcoadmin, requires same-origin + CSRF for mutations,
queues jobs and records the actor. The worker submits them through the private
socket. Socket peer credentials authenticate the service, not the human user;
a compromised service account could invoke the entire allowed operation set.
The root agent does not independently verify a web session. This boundary is
smaller than handing a Docker socket to the web process, but still privileged and
requires review. It is not a multitenant/cloud isolation guarantee.

The root agent uses primary group root and does not set systemd
`NoNewPrivileges`: on Ubuntu 24.04 the former is needed by `newuidmap` and the
latter prevented LXC's transition into its generated AppArmor profile. Its socket
directory and socket are explicitly assigned to the service group, and peer UID
checks remain enforced. This is a reduction in process hardening and requires
further security review; the web and worker services retain their restrictions.

No host sudo password is collected or retained. No host NOPASSWD rule is added.
The CT `talco` sudo rule lives inside its own unprivileged guest. No default
production admin password; loopback preview has clearly disposable credentials.
Web sessions are hashed at rest and expire after eight hours. Password changes
invalidate sessions. Shared SQLite login throttling is per server address; reverse
proxy deployment needs a reviewed trusted-client-IP configuration.

Registry tokens are root-only in `/var/lib/hypertalco-agent/registry.json` and are
never returned to the frontend. Queue payloads may temporarily contain container
environment secrets or signed ISO URLs; the DB is service-private and terminal
job payloads are cleared logically. SQLite WAL/backups can retain old pages; this
is not secure erasure. Backups are sensitive. Guest logs may contain application
secrets, so access requires authentication and managed ownership.

VNC stays on loopback. A running managed VM receives a random ticket that expires
after 120 seconds for connection establishment. nginx proxies the websocket over
HTTPS, without logging the query/ticket. The browser receives the ticket through
a fragment, then sends it to the websocket proxy. Established console sessions
remain until closed. This is not a general host shell or Docker/LXC terminal.

The web UI's exact-name deletion is additional operator friction. The agent also
requires ownership and a stopped guest. VM/LXC disks are deleted with their guest;
Docker named volumes remain. Existing unmanaged guests are read only. Creation
failures retain the record/error and may need explicit operator repair.
