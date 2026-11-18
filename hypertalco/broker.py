"""Length-bounded JSON over a local UNIX socket, never a shell gateway."""
import json
import socket

MAX_MESSAGE = 2 * 1024 * 1024


class AgentError(RuntimeError):
    pass


class AgentClient:
    def __init__(self, path="/run/hypertalco-agent/agent.sock"):
        self.path = path

    def call(self, operation, payload=None, timeout=30):
        data = json.dumps({"operation": operation, "payload": payload or {}}).encode() + b"\n"
        if len(data) > 65536:
            raise AgentError("Request too large")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect(self.path)
                s.sendall(data)
                with s.makefile("rb") as f:
                    response = f.readline(MAX_MESSAGE + 1)
            if len(response) > MAX_MESSAGE or not response.endswith(b"\n"):
                raise AgentError("Invalid agent response")
            message = json.loads(response)
            if not message.get("ok"):
                raise AgentError(message.get("error", "Host operation failed"))
            return message["result"]
        except (OSError, ValueError) as error:
            raise AgentError("Host agent unavailable. Check hypertalco-agent.service.") from error
