# Networking

The installer inventories links, addresses and default routes before asking for a
network layout. It does not enslave the physical management NIC, move the host IP,
replace the default route, flush the firewall or configure netplan/interfaces.

| Network | Default | Behaviour |
|---|---|---|
| VM/LXC `hypertalco` | `10.77.0.0/24`, `virbr-ht` | libvirt NAT, gateway .1, DHCP .10–.250 |
| Docker `hypertalco` | `10.78.0.0/24`, `ht-docker0` | Docker NAT and optional published ports |
| VM/LXC isolated | Selected /24 | Local DHCP, no libvirt NAT/uplink |
| Docker isolated | Selected /24 | Docker internal bridge |
| Existing bridge | Explicit host bridge | libvirt reference, guest LAN DHCP/static IP |

Default private subnets are operator-selectable. Overlap checks cover existing
host routes and runtime networks when creating additional networks. Networks
created by Hypertalco carry ownership metadata. Default networks are protected;
additional managed networks can only be deleted when no known guests/interfaces
reference them. Foreign networks are visible and may be selected, but not deleted.

Docker iptables forwarding can interfere with libvirt bridges. A boot service
adds only scoped, idempotent DOCKER-USER rules for managed VM/LXC networks; it
never flushes chains. Docker's iptables backend is required; a configuration with
no DOCKER-USER chain is rejected. Compatibility with nftables-only Docker, UFW,
custom routed firewalls, VPN routes and daemon restarts needs integration testing.
These scoped ACCEPT rules are firewall changes and must be reviewed against the
operator's network policy. This version is not a complete host firewall manager.

VMs use virtio NICs. Unprivileged native LXC uses veth pairs on the selected bridge.
An isolated network blocks routed external connectivity; its guests can still reach the host bridge address and potentially other guests on that segment. It is not a host firewall or a tenant security boundary.

Docker receives CPU/RAM limits and its own bridge network. Published ports bind
to all IPv4 interfaces in the current UI; review host/guest port exposure in the
lab. IPv6 inventory/provisioning and UI-controlled NIC/VLAN/bond changes are not
implemented. No automatic port forwarding is created for VM/LXC guests.

Debian/Ubuntu CT creation installs SSH/sudo inside the guest, so initial
provisioning requires an internet-capable NAT/bridge network. Isolated CT creation
is rejected before creating the guest. The installer still permits an isolated
VM/LXC network for VM use; offline CT provisioning is future work.

ISO sources can be HTTP(S), or regular `.iso` files under `/mnt`, `/media` or
`/srv/iso`, including existing NFS/SMB mounts. Sources are copied locally, bounded
and hashed; optionally supply the distribution's expected SHA256. The source mount
can then go away without losing the VM's installation media. Host mounts and
credentials are managed outside Hypertalco. Native template downloads use the
Linux Containers catalog and LXC helper/cache; Docker Hub is a separate image
catalog with optional private registry tokens.
