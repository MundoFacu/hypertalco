#!/usr/bin/env python3
"""Interactive installation coordinator. --plan never installs or stores credentials."""
import argparse
import getpass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from hypertalco.security import hash_password
from hypertalco.store import Store
from scripts import host_setup

PACKAGES = ['python3', 'gunicorn', 'nginx', 'openssl', 'ca-certificates', 'curl', 'wget',
            'gnupg', 'tar', 'xz-utils', 'zstd', 'iproute2', 'iptables', 'dnsmasq-base', 'lxc',
            'lxc-templates', 'uidmap', 'libvirt-daemon-system', 'libvirt-clients', 'virtinst',
            'qemu-utils', 'novnc', 'websockify']


def style(text, code):
    """Keep redirected logs and NO_COLOR output free of terminal escapes."""
    if sys.stdout.isatty() and os.environ.get('TERM') != 'dumb' and 'NO_COLOR' not in os.environ:
        return f'\033[{code}m{text}\033[0m'
    return text


def section(title):
    print('\n' + style('── ' + title + ' ', '1;36') + style('─' * max(2, 48 - len(title)), '36'))


def prompt(title, default, read=input, choices=None):
    while True:
        value = read(f'{title} [{default}]: ').strip() or str(default)
        if choices is None or value in choices:
            return value
        print('Choose: ' + ', '.join(choices))


def collect(args, read=input, links=None):
    settings = vars(args).copy()
    if args.upgrade and Path('/etc/hypertalco/install.json').exists():
        previous = json.loads(Path('/etc/hypertalco/install.json').read_text())
        settings.update({k: previous[k] for k in ('bind', 'port', 'guest_subnet', 'docker_subnet',
                         'network_mode', 'bridge', 'docker_mode', 'guests_dir', 'iso_dir',
                         'template_cache', 'docker_dir') if k in previous})
        print('Upgrade: keeping existing network and storage configuration.')
        return SimpleNamespace(**settings)
    if links is None:
        links = json.loads(host_setup.output(['ip', '-j', '-d', 'link', 'show']))
        addresses = json.loads(host_setup.output(['ip', '-j', 'address', 'show']))
        section('Host network')
        print('Detected interfaces:')
        for row in addresses:
            addresses_ = ', '.join(a['local'] + '/' + str(a['prefixlen']) for a in row.get('addr_info', []) if a['family'] == 'inet')
            print(f"  {row['ifname']:16} {row.get('operstate', '?'):8} {addresses_}")
        print('Current default routes:')
        for row in json.loads(host_setup.output(['ip', '-j', 'route', 'show', 'default'])):
            print('  ' + row.get('dev', '?') + ' via ' + row.get('gateway', 'direct'))
    section('VM and LXC network')
    print('1  NAT + DHCP (recommended)\n2  Existing host bridge\n3  Isolated + DHCP')
    print('A bridge uses LAN DHCP/static guest configuration. Physical host IP/routes are preserved.')
    mode = prompt('VM / LXC network mode', {'nat': '1', 'bridge': '2', 'isolated': '3'}[args.network_mode], read, ['1', '2', '3'])
    settings['network_mode'] = {'1': 'nat', '2': 'bridge', '3': 'isolated'}[mode]
    if mode == '2':
        bridges = [x['ifname'] for x in links if x.get('linkinfo', {}).get('info_kind') == 'bridge']
        if not bridges:
            raise ValueError('No existing host bridge found. Configure a bridge separately or choose NAT.')
        settings['bridge'] = prompt('Existing bridge (' + ', '.join(bridges) + ')', bridges[0], read, bridges)
    else:
        settings['guest_subnet'] = prompt('VM / LXC private subnet (/24)', args.guest_subnet, read)
    section('Docker network')
    print('1  NAT (recommended)\n2  Isolated (no external connectivity)')
    settings['docker_mode'] = 'nat' if prompt('Docker network mode', '1', read, ['1', '2']) == '1' else 'isolated'
    settings['docker_subnet'] = prompt('Docker private subnet (/24)', args.docker_subnet, read)
    section('Storage')
    print('Storage must be mounted already. Directories are created; disks are never formatted.')
    settings['guests_dir'] = prompt('VM / LXC guest directory (qemu/ and lxc/ below it)', args.guests_dir, read)
    settings['iso_dir'] = prompt('Default ISO library directory', args.iso_dir, read)
    settings['template_cache'] = prompt('Default LXC template cache', args.template_cache, read)
    if args.docker_existing:
        daemon = Path('/etc/docker/daemon.json')
        settings['docker_dir'] = json.loads(daemon.read_text()).get('data-root', '/var/lib/docker') if daemon.exists() else '/var/lib/docker'
        print('Existing Docker data-root will be retained: ' + settings['docker_dir'])
    else:
        settings['docker_dir'] = prompt('Docker image / volume data-root', args.docker_dir, read)
    section('Web access')
    settings['bind'] = prompt('Web listener IPv4 address (0.0.0.0 = all interfaces)', args.bind, read)
    settings['port'] = int(prompt('Web HTTPS port', args.port, read))
    if settings['network_mode'] == 'isolated':
        print('Note: Debian/Ubuntu LXC SSH provisioning requires internet. Use NAT/bridge for initial CT creation.')
    return SimpleNamespace(**settings)


def obtain_password(read=getpass.getpass):
    while True:
        value = read('talcoadmin web password (12+ characters): ')
        try:
            encoded = hash_password(value)
        except ValueError as error:
            print(error); continue
        if value != read('Repeat talcoadmin password: '):
            print('Passwords do not match.'); continue
        return encoded


def save_admin(encoded):
    # Initialize the database with service ownership from creation, without password argv/files.
    import pwd
    account = pwd.getpwnam('hypertalco')
    pid = os.fork()
    if pid == 0:
        try:
            os.initgroups(account.pw_name, account.pw_gid)
            os.setgid(account.pw_gid); os.setuid(account.pw_uid)
            store = Store('/var/lib/hypertalco')
            store.set_user('talcoadmin', encoded)
            store.audit('talcoadmin', 'admin.setup')
            Path('/var/lib/hypertalco/.admin-created').touch(mode=0o600)
        except BaseException:
            os._exit(1)
        os._exit(0)
    if os.waitpid(pid, 0)[1] != 0:
        raise RuntimeError('Administrator initialization failed; application services were not started')


def execute(args, encoded):
    packages = PACKAGES.copy()
    if not args.docker_existing:
        packages += ['docker.io']
    packages += ['qemu-system-x86', 'ovmf'] if host_setup.platform.machine() == 'x86_64' else ['qemu-system-arm', 'qemu-efi-aarch64']
    environment = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}
    section('Installing system packages')
    subprocess.run(['apt-get', 'update'], check=True, env=environment)
    subprocess.run(['apt-get', 'install', '--no-install-recommends', '-y', *packages], check=True, env=environment)
    section('Configuring Hypertalco')
    host_setup.install(args)
    if encoded is not None:
        save_admin(encoded)
    host_setup.run(['systemctl', 'enable', '--now', *[u + '.service' for u in host_setup.UNITS]])
    host_setup.run(['nginx', '-t'])
    host_setup.run(['systemctl', 'enable', 'nginx'])
    host_setup.run(['systemctl', 'reload-or-restart', 'nginx'])
    # systemctl enable --now may return before a simple service fails to exec.
    # Check each service separately: systemctl is-active with multiple units
    # succeeds when only one is active.
    time.sleep(2)
    for unit in [*host_setup.UNITS, 'nginx']:
        subprocess.run(['systemctl', 'is-active', '--quiet', unit + '.service'], check=True)
    section('Installation complete')
    print(style('  Web interface: ', '1') + f'https://HOST:{args.port}/')
    print(style('  Administrator: ', '1') + 'talcoadmin')
    print('HTTPS uses a self-signed certificate. No host sudo password is stored.')
    print(style('  cooked in https://vibetool.cloud sauce', '36'))


def main():
    parser = argparse.ArgumentParser(description='Hypertalco interactive bare-metal installer')
    parser.add_argument('--source', default=str(ROOT))
    parser.add_argument('--plan', action='store_true', help='Ask questions and print a plan; no password or installation')
    parser.add_argument('--check', action='store_true', help='Read-only host preflight with supplied/default settings')
    parser.add_argument('--upgrade', action='store_true')
    parser.add_argument('--bind', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--guest-subnet', default='10.77.0.0/24')
    parser.add_argument('--docker-subnet', default='10.78.0.0/24')
    host_setup.add_settings_arguments(parser)
    args = parser.parse_args()
    args.docker_existing = shutil.which('docker') is not None
    if args.check:
        print(json.dumps(host_setup.preflight(args), indent=2)); return
    if not args.plan and os.geteuid() != 0:
        raise SystemExit('The installer requires root. --plan and --check can run without root.')
    # /dev/tty works when the bootstrap script was piped from curl.
    with open('/dev/tty', 'r') as terminal:
        print(style("""
       .-------------------------------.
       |  [::]  HyperTalco             |
       |  [::]  Docker  LXC  QEMU/KVM  |
       '-------------------------------'""", '1;36'))
        print('  Press Enter to accept the value in [brackets].')
        def read(message):
            print(message, end='', flush=True)
            line = terminal.readline()
            if not line:
                raise SystemExit('Installation cancelled: terminal closed')
            return line.rstrip('\n')
        args = collect(args, read)
        host_setup.validate_settings(args)
        host_setup.network(args.guest_subnet); host_setup.network(args.docker_subnet)
        section('Installation plan — no changes yet')
        for label, value in [('VM / LXC network', args.network_mode),
                             ('VM / LXC subnet', args.bridge if args.network_mode == 'bridge' else args.guest_subnet),
                             ('Docker network', f'{args.docker_mode} · {args.docker_subnet}'),
                             ('Guest storage', args.guests_dir), ('ISO library', args.iso_dir),
                             ('LXC template cache', args.template_cache), ('Docker data', args.docker_dir),
                             ('Web listener', f'{args.bind}:{args.port}')]:
            print(f'  {label:<20} {value}')
        print('Web account: talcoadmin. Services: hypertalco (no login). Privileged operations: local root agent.')
        if args.plan:
            print('Plan only. No password collected, packages installed, or configuration written.'); return
        report = host_setup.preflight(args)
        section('Preflight and recovery')
        print(style('PASS', '1;32') + ': ' + report['os'] + ', ' + report['architecture'] + ', KVM API checked.')
        print('BACKUP: Take a verified host backup or snapshot and know how to restore it before installing.')
        print('A root-only snapshot does not cover a separate /boot or EFI partition; snapshots on the same disk are not independent backups.')
        print('Packages and their scripts can change system files including /boot and EFI. The installer does not protect those mounts.')
        print('Rollback is partial: packages, network state and guest data may remain. Keep console access for recovery.')
        print('The web listener uses a self-signed certificate. Restrict access to a trusted management network.')
        for warning in report['warnings']:
            print(style('WARNING', '1;33') + ': ' + warning)
        if read('Install packages and apply this configuration? Type INSTALL: ') != 'INSTALL':
            raise SystemExit('Installation cancelled; no changes made')
        encoded = None if Path('/var/lib/hypertalco/.admin-created').exists() else obtain_password()
        execute(args, encoded)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
