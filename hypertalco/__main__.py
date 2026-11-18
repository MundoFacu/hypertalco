import argparse
import getpass
import json
import logging
import os
from pathlib import Path
import re
import signal
from socketserver import ThreadingMixIn
import threading
from wsgiref.simple_server import WSGIServer, make_server, WSGIRequestHandler

from .broker import AgentClient
from .security import hash_password
from .store import Store
from .worker import run_worker


def load(path):
    return json.loads(Path(path).read_text())


def main():
    parser = argparse.ArgumentParser(prog="hypertalco")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("agent", "worker", "setup", "reset-password"):
        p = sub.add_parser(name)
        p.add_argument("--config", default="/etc/hypertalco/agent.json" if name == "agent" else "/etc/hypertalco/config.json")
        if name in {"setup", "reset-password"}:
            p.add_argument("--username", default="talcoadmin")
    dev = sub.add_parser("dev", help="Explicit loopback-only simulated preview")
    dev.add_argument("--port", type=int, default=8768)
    dev.add_argument("--data-dir", default=f"/tmp/hypertalco-preview-{os.getuid()}")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if args.command == "dev":
        if os.geteuid() == 0:
            raise SystemExit("Do not run the preview as root")
        from .demo import DemoAgent
        from .web import App
        config = {"data_dir": args.data_dir, "demo": True, "allowed_hosts": ["127.0.0.1", "localhost"]}
        app, agent = App(config, DemoAgent()), None
        if not app.store.user("talcoadmin"):
            app.store.set_user("talcoadmin", hash_password("hypertalco-preview-only"))
        stop = threading.Event()
        threading.Thread(target=run_worker, args=(app.store, app.agent, stop), daemon=True).start()

        class Server(ThreadingMixIn, WSGIServer):
            daemon_threads = True
        class Handler(WSGIRequestHandler):
            def log_message(self, fmt, *values):
                # No cookies, bodies, query parameters or credentials in the preview log.
                logging.info("Preview request: %s %s", self.command, self.path.split("?", 1)[0])
        server = make_server("127.0.0.1", args.port, app, server_class=Server, handler_class=Handler)
        print(f"Local preview: http://127.0.0.1:{args.port}\nSimulated guests only. Login: talcoadmin / hypertalco-preview-only", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stop.set(); server.server_close()
        return
    config = load(args.config)
    if args.command == "agent":
        from .agent import serve
        serve(config)
    elif args.command == "worker":
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        run_worker(Store(config["data_dir"]), AgentClient(config["agent_socket"]), stop)
    else:
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{1,31}", args.username):
            raise SystemExit("Invalid administrator username")
        password = getpass.getpass("Administrator password (12+ characters): ")
        if password != getpass.getpass("Repeat password: "):
            raise SystemExit("Passwords do not match")
        store = Store(config["data_dir"])
        store.set_user(args.username, hash_password(password), reset=args.command == "reset-password")
        store.audit(args.username, "admin." + args.command)
        print("Administrator credentials saved. Existing sessions invalidated.")


if __name__ == "__main__":
    main()
