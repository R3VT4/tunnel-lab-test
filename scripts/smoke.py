#!/usr/bin/env python3
"""Exercise the compiled binary over real local sockets; no external services."""
import argparse
import http.server
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


PAYLOAD = b"Tunnel Lab binary integration test\n" * 1000


class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, *_):
        pass


def run(binary, observer=None, reverse=False, negotiation="alpn", omit_sni=False):
    binary = str(pathlib.Path(binary).resolve())
    with tempfile.TemporaryDirectory(prefix="tunnellab-smoke-") as tmp:
        root = pathlib.Path(tmp)
        demo = root / "demo"
        subprocess.run([binary, "init", "-dir", str(demo)], check=True)
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
        thread = threading.Thread(target=target.serve_forever, daemon=True)
        thread.start()
        used = {target.server_port}

        def address():
            while (port := free_port()) in used:
                pass
            used.add(port)
            return f"127.0.0.1:{port}"

        relay_addr, edge_addr, relay_admin, edge_admin = [address() for _ in range(4)]
        for role in ("relay", "edge"):
            prefix = "reverse-" if reverse else ""
            path = demo / f"{prefix}{role}.json"
            cfg = json.loads(path.read_text())
            cfg["protocol_negotiation"] = negotiation
            if omit_sni and role == ("relay" if reverse else "edge"):
                cfg["omit_sni"] = True
            cfg["listen"] = ("" if reverse else relay_addr) if role == "relay" else edge_addr
            cfg["admin"] = relay_admin if role == "relay" else edge_admin
            if role == "relay":
                cfg["target"] = f"127.0.0.1:{target.server_port}"
                if reverse:
                    cfg["peer"] = relay_addr
            else:
                if reverse:
                    cfg["tunnel_listen"] = relay_addr
                else:
                    cfg["peer"] = relay_addr
            path.write_text(json.dumps(cfg))
        processes = []
        try:
            with (root / "process.log").open("w") as log:
                for role in ("relay", "edge"):
                    processes.append(subprocess.Popen(
                        [binary, "run", "-config", str(demo / f"{prefix}{role}.json")],
                        stdout=log, stderr=log,
                    ))
                for admin in (relay_admin, edge_admin):
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            with urllib.request.urlopen(f"http://{admin}/api/status", timeout=1) as resp:
                                stats = json.load(resp)
                                assert stats["version"] == (pathlib.Path(__file__).resolve().parent.parent/"VERSION").read_text().strip()
                                if reverse and not stats["control_connected"]:
                                    raise OSError("control is not ready yet")
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise RuntimeError("process failed to become ready")
                            time.sleep(0.05)
                with urllib.request.urlopen(f"http://{edge_addr}/", timeout=5) as resp:
                    assert resp.read() == PAYLOAD, "payload changed in transit"
                for admin in (relay_admin, edge_admin):
                    with urllib.request.urlopen(f"http://{admin}/api/status", timeout=2) as resp:
                        stats = json.load(resp)
                        assert stats["returned_bytes"] >= len(PAYLOAD)
                    with urllib.request.urlopen(f"http://{admin}/", timeout=2) as resp:
                        assert "وضعیت هسته" in resp.read().decode()
                client_path=demo / ("reverse-relay.json" if reverse else "edge.json")
                result=subprocess.run([binary,"probe","-config",str(client_path),"-bytes","262144","-rounds","4"],check=True,capture_output=True,text=True,timeout=10)
                report=json.loads(result.stdout)
                assert report["bytes_each_way"]==262144 and report["download_goodput_mbps"]>0
                assert report["upload_confirmed_goodput_mbps"]>0 and report["packet_loss_measured"] is False
                if observer:
                    observer(f"http://{edge_admin}")
                print(f"PASS: {'reverse' if reverse else 'direct'} compiled binary, mTLS forwarding, exact HTTP payload, live JSON API and Persian status page")
        finally:
            for proc in processes:
                proc.terminate()
            for proc in processes:
                try:
                    code = proc.wait(timeout=3)
                    if code != 0:
                        raise RuntimeError(f"unclean process exit: {code}")
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    raise RuntimeError("process did not shut down")
            target.shutdown()
            target.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="bin/tunnellab-linux-amd64")
    parser.add_argument("--reverse", action="store_true")
    parser.add_argument("--negotiation", choices=("alpn", "encrypted-preface"), default="alpn")
    parser.add_argument("--omit-sni", action="store_true")
    args = parser.parse_args()
    run(args.binary, reverse=args.reverse, negotiation=args.negotiation, omit_sni=args.omit_sni)
