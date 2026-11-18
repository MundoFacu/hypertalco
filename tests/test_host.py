import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import socket
import tempfile
import unittest
from unittest.mock import patch, Mock

from hypertalco.agent import Agent, peer_allowed
from hypertalco.engines import Docker, LABEL, Libvirt
from hypertalco.media import import_iso, local_source, remote_source
from hypertalco.networks import Networks
from hypertalco.validation import Invalid, create, network

ROOT = Path(__file__).resolve().parent.parent
setup = runpy.run_path(str(ROOT / "scripts/host_setup.py"))


class ValidationTests(unittest.TestCase):
    def test_no_injection_in_names_images_or_networks(self):
        for changes in [{"name": "hello;id"}, {"image": "nginx --privileged"}, {"network": "bridge;id"}, {"privileged": True}]:
            with self.subTest(changes=changes), self.assertRaises(Invalid):
                create({"engine": "docker", "name": "hello", "image": "nginx:alpine", **changes})

    def test_bool_is_not_a_cpu_number(self):
        with self.assertRaises(Invalid):
            create({"engine": "docker", "name": "hello", "image": "nginx", "cpus": True})

    def test_vm_uses_imported_iso_not_arbitrary_host_path(self):
        with self.assertRaises(Invalid):
            create({"engine": "qemu", "name": "hello", "image": "/etc/passwd"})

    def test_volume_cannot_target_root_or_parent(self):
        for path in ["/", "/proc", "/data/../proc"]:
            with self.assertRaises(Invalid):
                create({"engine": "docker", "name": "hello", "image": "nginx", "volume_path": path})

    def test_network_rejects_public_or_non24_subnet(self):
        for cidr in ["8.8.8.0/24", "10.1.0.0/16", "127.0.0.0/24"]:
            with self.assertRaises(Invalid): network(cidr)


class MediaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.source = self.root / "incoming"; self.source.mkdir()
        self.media = self.root / "library"
        self.iso = self.source / "test.iso"
        self.iso.write_bytes(b"\x00" * 32769 + b"CD001" + b"\x00" * 40000)

    def test_mount_path_import_hash_and_copy(self):
        digest = hashlib.sha256(self.iso.read_bytes()).hexdigest()
        result = import_iso({"source": str(self.iso), "kind": "path", "name": "test.iso", "sha256": digest}, self.media, [str(self.source)])
        self.assertEqual(result["sha256"], digest)
        self.assertEqual(Path(result["path"]).read_bytes(), self.iso.read_bytes())

    def test_checksum_failure_discards_partial(self):
        with self.assertRaises(Invalid):
            import_iso({"source": str(self.iso), "kind": "path", "name": "test.iso", "sha256": "0" * 64}, self.media, [str(self.source)])
        self.assertEqual(list(self.media.iterdir()), [])

    def test_symlink_source_rejected(self):
        link = self.source / "link.iso"; link.symlink_to(self.iso)
        with self.assertRaises(OSError): local_source(str(link), [str(self.source)])

    def test_parent_escape_rejected(self):
        with self.assertRaises(Invalid): local_source(str(self.source / ".." / "other.iso"), [str(self.source)])

    def test_non_iso_data_rejected(self):
        self.iso.write_text("not installation media")
        with self.assertRaises(Invalid):
            import_iso({"source": str(self.iso), "kind": "path", "name": "test.iso"}, self.media, [str(self.source)])

    def test_url_rejects_credentials_and_metadata_before_get(self):
        with self.assertRaises(Invalid): remote_source("https://user:password@example.org/disk.iso")
        conn = Mock(); conn.sock.getpeername.return_value = ("169.254.169.254", 80)
        with patch("hypertalco.media.http.client.HTTPConnection", return_value=conn), self.assertRaises(Invalid):
            remote_source("http://169.254.169.254/latest/meta-data")
        conn.request.assert_not_called()


class AdapterTests(unittest.TestCase):
    def test_force_stop_requires_exact_vm_name_and_targets_only_vm(self):
        agent = Agent.__new__(Agent)
        agent.record = Mock(return_value={'id': 'id', 'name': 'test-vm', 'engine': 'qemu', 'physical': 'vm-uuid'})
        agent.check_owned = Mock(return_value='running')
        agent.docker = Mock(); agent.lxc = Mock(); agent.libvirt = Mock()
        with self.assertRaises(Invalid):
            agent.action({'id': 'id', 'action': 'force-stop', 'confirm': 'wrong'})
        agent.libvirt.action.assert_not_called()
        agent.action({'id': 'id', 'action': 'force-stop', 'confirm': 'test-vm'})
        agent.libvirt.action.assert_called_once_with('vm-uuid', 'force-stop')
        agent.record.return_value['engine'] = 'docker'
        with self.assertRaises(Invalid):
            agent.action({'id': 'id', 'action': 'force-stop', 'confirm': 'test-vm'})

    def test_docker_pull_defaults_to_latest_without_changing_tags_or_digests(self):
        from urllib.parse import parse_qs, urlsplit
        docker = Docker()
        for image, expected in [("alpine", "alpine:latest"),
                                ("registry:5000/team/app", "registry:5000/team/app:latest"),
                                ("alpine:3", "alpine:3"),
                                ("alpine@sha256:abc", "alpine@sha256:abc")]:
            with self.subTest(image=image), patch.object(docker, "request") as request:
                docker.pull(image)
                path = request.call_args.args[1]
                self.assertEqual(parse_qs(urlsplit(path).query)["fromImage"], [expected])

    def test_docker_create_uses_json_not_secret_argv(self):
        docker = Docker(); calls = []
        def request(method, path, body=None, **kwargs):
            calls.append((method, path, body))
            return {"Id": "a" * 64}
        spec = create({"engine": "docker", "name": "hello", "image": "nginx:alpine", "env": {"TOKEN": "synthetic-secret"}, "ports": [{"host": 8080, "container": 80}]})
        with patch.object(docker, "pull"), patch.object(docker, "request", side_effect=request):
            docker.create(spec, "123")
        body = next(body for method, path, body in calls if method == "POST")
        self.assertEqual(body["HostConfig"]["SecurityOpt"], ["no-new-privileges:true"])
        self.assertNotIn("Privileged", body["HostConfig"])
        self.assertEqual(body["Labels"][LABEL], "true")
        self.assertEqual(body["Env"], ["TOKEN=synthetic-secret"])

    def test_cached_image_does_not_require_registry_connection(self):
        docker = Docker()
        spec = create({"engine": "docker", "name": "offline", "image": "nginx:alpine"})
        with patch.object(docker, "request", side_effect=[[{"Id": "cached"}], {"Id": "created"}]), patch.object(docker, "pull") as pull:
            self.assertEqual(docker.create(spec, "id"), "created")
            pull.assert_not_called()

    def test_guest_provision_program_parses_and_uses_real_newlines(self):
        import ast
        tree = ast.parse((ROOT / "hypertalco/engines.py").read_text())
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "program" for t in n.targets))
        program = ast.literal_eval(node.value)
        guest = ast.parse(program)
        constants = [n.value for n in ast.walk(guest) if isinstance(n, ast.Constant)]
        self.assertIn("\n", constants)
        self.assertIn("talco ALL=(ALL) NOPASSWD:ALL\n", constants)

    def test_agent_refuses_foreign_docker_label(self):
        agent = Agent.__new__(Agent)
        agent.docker = Mock(); agent.docker.inspect.return_value = {"Config": {"Labels": {}}, "State": {"Running": False}}
        record = {"engine": "docker", "physical": "a" * 64, "id": "b" * 36}
        with self.assertRaises(Invalid): agent.check_owned(record)
        agent.docker.action.assert_not_called()

    def test_libvirt_memory_resize_uses_xml_and_keeps_disks(self):
        runner = Mock(); libvirt = Libvirt(runner)
        xml = '<domain><name>ht-lab</name><memory unit="KiB">1048576</memory><vcpu>1</vcpu><devices><disk><source file="/safe/disk.qcow2"/></disk></devices></domain>'
        captured = []
        def command(*args, **kw):
            if args[0] == "dumpxml": return xml
            captured.append(Path(args[1]).read_text()); return ""
        with patch.object(libvirt, "virsh", side_effect=command):
            libvirt.resize("uuid", {"cpus": 2, "memory_mib": 2048})
        self.assertIn("2097152", captured[0]); self.assertIn("/safe/disk.qcow2", captured[0])

    def test_vm_install_media_is_persistent_and_disk_boots_first(self):
        runner = Mock()
        with tempfile.TemporaryDirectory() as tmp, patch('hypertalco.engines.Path'):
            spec = {'name': 'example', 'disk_gib': 8, 'memory_mib': 512,
                    'cpus': 1, 'firmware': 'uefi', 'autostart': False}
            Libvirt(runner).create(spec, 'vm-id', Path(tmp), Path('/media/test.iso'), 'hypertalco')
        argv = runner.run.call_args_list[-1].args[0]
        self.assertEqual(argv[argv.index('--install') + 1], 'no_install=yes')
        self.assertEqual(argv[argv.index('--boot') + 1], 'uefi,hd,cdrom,menu=on')

    def test_actual_peer_credentials(self):
        a, b = socket.socketpair(); self.addCleanup(a.close); self.addCleanup(b.close)
        self.assertTrue(peer_allowed(a, os.getuid()))
        if os.getuid() != 0:
            self.assertFalse(peer_allowed(a, os.getuid() + 1))


class NetworkTests(unittest.TestCase):
    def test_docker_delete_returns_json_safe_result(self):
        docker = Mock(); docker.request.return_value = b''
        n = Networks(Mock(), docker, Mock())
        with patch.object(n, 'docker_networks', return_value=[{'name': 'ht-test', 'managed': True, 'id': 'docker:abc'}]):
            self.assertEqual(n.delete('ht-test', 'docker', []), {'deleted': 'ht-test'})
        docker.request.assert_called_once_with('DELETE', '/v1.41/networks/abc')

    def test_subnet_overlap_fails_before_mutation(self):
        n = Networks(Mock(), Mock(), Mock())
        with patch.object(n, "interfaces", return_value={"routes": [{"dst": "10.77.0.0/16"}]}), patch.object(n, "docker_networks", return_value=[]), patch.object(n, "libvirt_networks", return_value=[]):
            with self.assertRaises(Invalid): n.validate_subnet("10.77.2.0/24")
        n.runner.run.assert_not_called()

    def test_isolated_rules_cannot_forward_to_other_interfaces(self):
        runner = Mock(); runner.succeeds.return_value = False
        Networks(runner, Mock(), Mock()).forwarding("vht123", "10.79.0.0/24", "isolated")
        calls = [call.args[0] for call in runner.run.call_args_list]
        self.assertEqual(len(calls), 1)
        self.assertIn("-i", calls[0]); self.assertIn("-o", calls[0]); self.assertNotIn("-F", calls[0])

    def test_nat_rules_are_idempotent_and_do_not_flush_firewall(self):
        runner = Mock(); runner.succeeds.return_value = True
        Networks(runner, Mock(), Mock()).forwarding("virbr-ht", "10.77.0.0/24", "nat")
        runner.run.assert_not_called()

    def test_default_network_xml_has_owned_metadata_and_dhcp(self):
        xml = setup["network_xml"]("10.77.0.0/24")
        self.assertIn("urn:hypertalco", xml); self.assertIn("10.77.0.10", xml); self.assertIn('mode="nat"', xml)


class InstallerTests(unittest.TestCase):
    def test_lxc_autostart_skips_empty_inventory_but_propagates_failure(self):
        spec = importlib.util.spec_from_file_location('lxc_autostart_test', ROOT / 'scripts/lxc_autostart.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory, patch.object(module.subprocess, 'run') as run:
            self.assertEqual(module.main('start', directory), 0)
            run.assert_not_called()
            container = Path(directory) / 'guest'; container.mkdir()
            (container / 'config').write_text('lxc.start.auto = 1\n')
            run.return_value.returncode = 42
            self.assertEqual(module.main('start', directory), 42)
            self.assertEqual(module.main('stop', directory), 42)
            self.assertIn('-s', run.call_args.args[0])

    def test_rollback_restores_restrictive_file_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'daemon.json'
            path.write_text('replacement')
            path.chmod(0o644)
            setup['restore_file'](path, 'original', {'mode': 0o600, 'uid': os.getuid(), 'gid': os.getgid()})
            self.assertEqual(path.read_text(), 'original')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_install_directories_remain_traversable_with_strict_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / 'source'; source.mkdir()
            nested = source / 'hypertalco' / 'static'; nested.mkdir(parents=True)
            item = nested / 'app.js'; item.write_text('ok')
            releases = base / 'opt' / 'hypertalco' / 'releases'
            old = os.umask(0o077)
            try:
                setup['mkdir_traversable'](releases)
                release = releases / 'version'
                setup['copy_release'](source, release, [item])
            finally:
                os.umask(old)
            for directory in [base / 'opt', base / 'opt' / 'hypertalco', releases,
                              release, release / 'hypertalco', release / 'hypertalco' / 'static']:
                self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
            self.assertEqual((release / 'hypertalco/static/app.js').stat().st_mode & 0o777, 0o644)

    def test_idmap_avoids_existing_subuid_and_subgid_ranges(self):
        base, add = setup["idmap_base"]("someone:20000000:65536\n", "another:20065536:65536\n")
        self.assertEqual(base, 20131072); self.assertTrue(add)

    def test_existing_matching_root_mapping_is_reused(self):
        self.assertEqual(setup["idmap_base"]("root:100000:65536\n", "root:100000:65536\n"), (100000, False))

    def test_https_config_has_one_frontend_and_loopback_console_proxy(self):
        config = setup["nginx_config"]("0.0.0.0", 8443)
        self.assertIn("listen 0.0.0.0:8443 ssl", config)
        self.assertIn("127.0.0.1:6080", config)
        self.assertIn("access_log off", config)
        self.assertIn("X-Forwarded-Proto https", config)

    def test_bind_cannot_inject_nginx_directives(self):
        with self.assertRaises(ValueError): setup["nginx_config"]("0.0.0.0;evil", 8443)
