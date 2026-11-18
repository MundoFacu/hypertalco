import argparse
import ast
import json
import subprocess
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock
from urllib.parse import parse_qs, urlsplit

from scripts import installer, host_setup
from hypertalco.engines import Docker, registry_for
from hypertalco.store import Store
from hypertalco.agent import Agent


def settings():
    parser = argparse.ArgumentParser()
    host_setup.add_settings_arguments(parser)
    result = parser.parse_args([])
    result.bind = '0.0.0.0'; result.port = 8443; result.guest_subnet = '10.77.0.0/24'
    result.docker_subnet = '10.78.0.0/24'; result.upgrade = False
    return result


class WizardTests(unittest.TestCase):
    def test_terminal_colours_respect_no_color_and_redirects(self):
        with patch('scripts.installer.sys.stdout') as stream, patch.dict('os.environ', {'TERM': 'xterm'}, clear=True):
            stream.isatty.return_value = True
            self.assertIn('\x1b[', installer.style('ready', '32'))
            with patch.dict('os.environ', {'NO_COLOR': '1'}):
                self.assertEqual(installer.style('ready', '32'), 'ready')
            stream.isatty.return_value = False
            self.assertEqual(installer.style('ready', '32'), 'ready')

    def test_kvm_probe_checks_api_and_denies_root_without_access(self):
        from unittest.mock import mock_open
        with patch('builtins.open', mock_open()), patch('scripts.host_setup.fcntl.ioctl', return_value=12):
            self.assertTrue(host_setup.probe_kvm())
        with patch('builtins.open', side_effect=PermissionError), patch('scripts.host_setup.os.geteuid', return_value=0):
            with self.assertRaisesRegex(RuntimeError, 'Cannot access'):
                host_setup.probe_kvm()
        with patch('builtins.open', side_effect=PermissionError), patch('scripts.host_setup.os.geteuid', return_value=1000):
            self.assertFalse(host_setup.probe_kvm())
        with patch('builtins.open', mock_open()), patch('scripts.host_setup.fcntl.ioctl', return_value=9):
            with self.assertRaisesRegex(RuntimeError, 'unsupported'):
                host_setup.probe_kvm()

    def test_install_fails_when_any_service_is_inactive(self):
        args = settings(); args.docker_existing = True
        def run(command, **kwargs):
            if command[:3] == ['systemctl', 'is-active', '--quiet'] and command[-1] == 'hypertalco-web.service':
                raise subprocess.CalledProcessError(3, command)
            return Mock(returncode=0)
        with patch('scripts.installer.subprocess.run', side_effect=run), \
             patch('scripts.installer.host_setup.install'), patch('scripts.installer.host_setup.run'), \
             patch('scripts.installer.time.sleep'):
            with self.assertRaises(subprocess.CalledProcessError):
                installer.execute(args, None)

    def test_default_plan_collects_network_and_paths_without_execution(self):
        args = settings()
        with patch('builtins.print'), patch.object(installer, 'execute') as execute:
            result = installer.collect(args, read=lambda _: '', links=[])
        self.assertEqual(result.network_mode, 'nat')
        self.assertEqual(result.guests_dir, '/var/lib/hypertalco-guests')
        self.assertEqual(result.template_cache, '/var/cache/lxc')
        execute.assert_not_called()

    def test_bridge_selection_only_accepts_existing_bridge(self):
        args = settings()
        responses = iter(['2', 'br-lan', '1', '', '', '', '', '', '', ''])
        links = [{'ifname': 'br-lan', 'linkinfo': {'info_kind': 'bridge'}}]
        with patch('builtins.print'):
            result = installer.collect(args, read=lambda _: next(responses), links=links)
        self.assertEqual(result.network_mode, 'bridge'); self.assertEqual(result.bridge, 'br-lan')
        with patch('scripts.host_setup.output', return_value=json.dumps(links)):
            host_setup.validate_settings(result)

    def test_no_bridge_cannot_move_primary_nic(self):
        with patch('builtins.print'), self.assertRaises(ValueError):
            installer.collect(settings(), read=lambda _: '2', links=[{'ifname': 'eth0'}])

    def test_storage_cannot_be_inside_service_account_data_or_escape(self):
        for value in ['/var/lib/hypertalco/guests', '/home/user/guests', '/srv/../etc/guests', '/srv/guests;id']:
            args = settings(); args.guests_dir = value
            with self.subTest(path=value), self.assertRaises(ValueError):
                host_setup.validate_settings(args)

    def test_storage_locations_cannot_overlap(self):
        args = settings(); args.iso_dir = args.guests_dir + '/iso'
        with self.assertRaises(ValueError): host_setup.validate_settings(args)

    def test_reserved_web_ports_and_overlapping_subnets_rejected_in_plan(self):
        args = settings(); args.port = 6080
        with self.assertRaises(ValueError): host_setup.validate_settings(args)
        args.port = 8443; args.docker_subnet = args.guest_subnet
        with self.assertRaises(ValueError): host_setup.validate_settings(args)

    def test_password_is_returned_as_hash_not_a_command_argument(self):
        read = Mock(side_effect=['synthetic-password', 'synthetic-password'])
        encoded = installer.obtain_password(read)
        self.assertTrue(encoded.startswith('scrypt$')); self.assertNotIn('synthetic', encoded)

    def test_isolated_and_bridge_network_xml_have_no_nat(self):
        isolated = host_setup.network_xml('10.77.0.0/24', 'isolated')
        self.assertNotIn('<forward', isolated); self.assertIn('<dhcp', isolated)
        bridge = host_setup.network_xml('10.77.0.0/24', 'bridge', 'br-lan')
        self.assertIn('mode="bridge"', bridge); self.assertNotIn('<ip', bridge)


class RegressionTests(unittest.TestCase):
    def test_expired_console_ticket_is_removed_from_proxy_file(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'tokens'
            agent = Agent.__new__(Agent)
            agent.config = {'console_tokens': str(target)}
            agent.console_tokens = {'expired': (0, 5900), 'valid': (9999999999, 5901)}
            agent.write_console_tokens()
            self.assertEqual(target.read_text(), 'valid: 127.0.0.1:5901\n')
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)

    def test_tag_is_not_mistaken_for_registry(self):
        for image in ['nginx:alpine', 'nginx', 'team/app:tag', 'docker.io/team/app']:
            self.assertEqual(registry_for(image), 'docker.io')
        self.assertEqual(registry_for('registry.lan:5000/team/app:tag'), 'registry.lan:5000')

    def test_docker_api_uses_daemon_advertised_version(self):
        version = Mock(status=200); version.read.return_value = b'{"ApiVersion":"1.52"}'
        version.getheader.return_value = 'application/json'
        result = Mock(status=200); result.read.return_value = b'[]'
        result.getheader.return_value = 'application/json'
        conn = Mock(); conn.getresponse.side_effect = [version, result]
        with patch('hypertalco.engines.DockerConnection', return_value=conn):
            Docker().inventory()
        self.assertEqual(conn.request.call_args_list[0].args[1], '/version')
        self.assertEqual(conn.request.call_args_list[1].args[1], '/v1.52/containers/json?all=1')

    def test_completed_job_scrubs_live_queue_payload(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(folder); identifier = store.enqueue('create', {'env': {'TOKEN': 'synthetic'}}, 'tester')
            store.claim(); store.finish(identifier, result={'id': 'guest'})
            with store.db() as db:
                self.assertEqual(db.execute('SELECT payload FROM jobs').fetchone()[0], '{}')
