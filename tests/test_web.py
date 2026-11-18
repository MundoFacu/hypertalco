import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock

from hypertalco.demo import DemoAgent
from hypertalco.security import hash_password, check_password
from hypertalco.store import Store
from hypertalco.web import App
from hypertalco.worker import process_one


class Client:
    def __init__(self, app):
        self.app, self.cookie, self.csrf = app, "", ""

    def request(self, path, body=None, csrf=True, origin=True):
        raw = json.dumps(body).encode() if body is not None else b""
        env = {"REQUEST_METHOD": "POST" if body is not None else "GET", "PATH_INFO": path.split("?", 1)[0],
               "QUERY_STRING": path.split("?", 1)[1] if "?" in path else "", "wsgi.url_scheme": "http",
               "HTTP_HOST": "localhost:8768", "REMOTE_ADDR": "127.0.0.1", "wsgi.input": io.BytesIO(raw),
               "CONTENT_LENGTH": str(len(raw)), "CONTENT_TYPE": "application/json", "HTTP_COOKIE": self.cookie}
        if csrf:
            env["HTTP_X_CSRF_TOKEN"] = self.csrf
        if origin:
            env["HTTP_ORIGIN"] = "http://localhost:8768"
        info = {}
        def start(status, headers):
            info.update(status=int(status.split()[0]), headers=dict(headers))
        response = b"".join(self.app(env, start))
        if "Set-Cookie" in info["headers"]:
            self.cookie = info["headers"]["Set-Cookie"].split(";", 1)[0]
        if info["headers"]["Content-Type"] == "application/json":
            response = json.loads(response)
            if isinstance(response, dict) and "csrf" in response:
                self.csrf = response["csrf"]
        return info, response


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = hash_password("test-only-admin-password")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = App({"data_dir": self.tmp.name, "demo": True, "allowed_hosts": ["localhost"]}, DemoAgent())
        self.app.store.set_user("admin", self.password)
        self.client = Client(self.app)

    def login(self):
        info, result = self.client.request("/api/login", {"username": "admin", "password": "test-only-admin-password"})
        self.assertEqual(info["status"], 200)
        return info, result

    def test_api_requires_authentication(self):
        self.assertEqual(self.client.request("/api/overview")[0]["status"], 401)

    def test_iso_upload_requires_session_and_csrf_and_cleans_staging(self):
        self.login()
        payload = b'example iso content'
        env = {"REQUEST_METHOD": "POST", "PATH_INFO": "/api/media/upload", "QUERY_STRING": "",
               "wsgi.url_scheme": "http", "HTTP_HOST": "localhost:8768", "REMOTE_ADDR": "127.0.0.1",
               "wsgi.input": io.BytesIO(payload), "CONTENT_LENGTH": str(len(payload)),
               "CONTENT_TYPE": "application/octet-stream", "HTTP_COOKIE": self.client.cookie,
               "HTTP_ORIGIN": "http://localhost:8768", "HTTP_X_UPLOAD_NAME": "test.iso"}
        info = {}
        def start(status, headers): info['status'] = int(status.split()[0])
        self.app(env, start)
        self.assertEqual(info['status'], 403)
        env['HTTP_X_CSRF_TOKEN'] = self.client.csrf
        def handle(operation, data, timeout):
            self.assertEqual(operation, 'media.upload')
            self.assertEqual((Path(self.tmp.name) / 'uploads' / (data['id'] + '.iso')).read_bytes(), payload)
            return {'name': data['name']}
        self.app.agent.call = Mock(side_effect=handle)
        self.app(env, start)
        self.assertEqual(info['status'], 200)
        self.assertEqual(list((Path(self.tmp.name) / 'uploads').iterdir()), [])

    def test_iso_upload_rejects_incomplete_or_invalid_file_names(self):
        self.login()
        env = {"REQUEST_METHOD": "POST", "PATH_INFO": "/api/media/upload", "QUERY_STRING": "",
               "wsgi.url_scheme": "http", "HTTP_HOST": "localhost:8768", "REMOTE_ADDR": "127.0.0.1",
               "wsgi.input": io.BytesIO(b'abc'), "CONTENT_LENGTH": "7", "CONTENT_TYPE": "application/octet-stream",
               "HTTP_COOKIE": self.client.cookie, "HTTP_ORIGIN": "http://localhost:8768",
               "HTTP_X_CSRF_TOKEN": self.client.csrf, "HTTP_X_UPLOAD_NAME": "test.iso"}
        info = {}
        def start(status, headers): info['status'] = int(status.split()[0])
        self.app(env, start)
        self.assertEqual(info['status'], 400)
        self.assertEqual(list((Path(self.tmp.name) / 'uploads').iterdir()), [])
        env['HTTP_X_UPLOAD_NAME'] = '%2Fetc%2Fshadow.iso'
        self.app(env, start)
        self.assertEqual(info['status'], 400)

    def test_template_upload_passes_supported_name_and_cleans_staging(self):
        self.login()
        payload = b'archive test data'
        env = {'REQUEST_METHOD': 'POST', 'PATH_INFO': '/api/templates/upload', 'QUERY_STRING': '',
               'wsgi.url_scheme': 'http', 'HTTP_HOST': 'localhost:8768', 'REMOTE_ADDR': '127.0.0.1',
               'wsgi.input': io.BytesIO(payload), 'CONTENT_LENGTH': str(len(payload)),
               'CONTENT_TYPE': 'application/octet-stream', 'HTTP_COOKIE': self.client.cookie,
               'HTTP_ORIGIN': 'http://localhost:8768', 'HTTP_X_CSRF_TOKEN': self.client.csrf,
               'HTTP_X_UPLOAD_NAME': 'debian.tar.zst'}
        info = {}
        def start(status, headers): info['status'] = int(status.split()[0])
        def handle(operation, data, timeout):
            self.assertEqual(operation, 'templates.upload')
            self.assertEqual((Path(self.tmp.name) / 'uploads' / (data['id'] + '.tar.zst')).read_bytes(), payload)
            return {'name': data['name']}
        self.app.agent.call = Mock(side_effect=handle)
        self.app(env, start)
        self.assertEqual(info['status'], 200)
        self.assertEqual(list((Path(self.tmp.name) / 'uploads').iterdir()), [])

    def test_login_cookie_and_security_headers(self):
        info, _ = self.login()
        self.assertIn("HttpOnly", info["headers"]["Set-Cookie"])
        self.assertIn("SameSite=Strict", info["headers"]["Set-Cookie"])
        self.assertIn("frame-ancestors 'none'", info["headers"]["Content-Security-Policy"])
        self.assertEqual(self.client.request("/api/me")[1]["username"], "admin")

    def test_production_session_is_secure(self):
        self.app.config["demo"] = False
        info, _ = self.login()
        self.assertIn("; Secure", info["headers"]["Set-Cookie"])

    def test_csrf_and_origin_reject_before_job_creation(self):
        self.login()
        for options in ({"csrf": False}, {"origin": False}):
            info, _ = self.client.request("/api/images/pull", {"image": "nginx:alpine"}, **options)
            self.assertEqual(info["status"], 403)
        self.assertEqual(self.app.store.jobs(), [])

    def test_unknown_operations_cannot_be_submitted(self):
        self.login()
        self.assertEqual(self.client.request("/api/exec", {"command": "id"})[0]["status"], 404)

    def test_queued_creation_and_worker_round_trip(self):
        self.login()
        info, result = self.client.request("/api/resources", {"engine": "docker", "name": "hello-test", "image": "nginx:alpine", "cpus": 1, "memory_mib": 256})
        self.assertEqual(info["status"], 202)
        self.assertTrue(process_one(self.app.store, self.app.agent))
        jobs = self.client.request("/api/jobs")[1]
        self.assertEqual(jobs[0]["status"], "succeeded")
        self.assertEqual(jobs[0]["id"], result["job_id"])
        self.assertTrue(any(r["name"] == "hello-test" for r in self.client.request("/api/overview")[1]["resources"]))

    def test_environment_values_not_returned_with_job_list(self):
        self.login()
        self.client.request("/api/resources", {"engine": "docker", "name": "secret-test", "image": "nginx:alpine", "env": {"TOKEN": "synthetic-private-value"}})
        self.assertNotIn("synthetic-private-value", json.dumps(self.client.request("/api/jobs")[1]))

    def test_logout_invalidates_session(self):
        self.login()
        self.client.request("/api/logout", {})
        self.assertEqual(self.client.request("/api/overview")[0]["status"], 401)

    def test_path_traversal_is_not_served(self):
        self.assertEqual(self.client.request("/static/../../store.py")[0]["status"], 404)

    def test_login_throttle_shared_between_app_instances(self):
        for _ in range(10):
            self.assertEqual(self.client.request("/api/login", {"username": "admin", "password": "wrong"})[0]["status"], 401)
        other = Client(App(self.app.config, DemoAgent()))
        self.assertEqual(other.request("/api/login", {"username": "admin", "password": "test-only-admin-password"})[0]["status"], 429)

    def test_password_change_invalidates_existing_session(self):
        self.login()
        info, _ = self.client.request("/api/password", {"current": "test-only-admin-password", "password": "a-new-test-only-password"})
        self.assertEqual(info["status"], 200)
        self.assertEqual(self.client.request("/api/me")[0]["status"], 401)
        self.assertTrue(check_password("a-new-test-only-password", self.app.store.user("admin")))


class QueueTests(unittest.TestCase):
    def test_one_claim_across_concurrent_workers(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(folder); store.enqueue("create", {}, "admin")
            results = []
            threads = [threading.Thread(target=lambda: results.append(store.claim())) for _ in range(4)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(sum(r is not None for r in results), 1)

    def test_interrupted_work_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(folder); store.enqueue("create", {}, "admin"); store.claim(); store.recover_jobs()
            self.assertIsNone(store.claim())
            self.assertEqual(store.jobs()[0]["status"], "interrupted")
