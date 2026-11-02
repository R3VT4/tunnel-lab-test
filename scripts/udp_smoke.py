#!/usr/bin/env python3
"""Run the compiled UDP pair and authenticated probe on local sockets only."""
import argparse
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from smoke import free_port


def run(binary):
    binary=str(pathlib.Path(binary).resolve())
    with tempfile.TemporaryDirectory(prefix="tunnellab-udp-") as tmp:
        root=pathlib.Path(tmp);demo=root/"demo"
        subprocess.run([binary,"init","-dir",str(demo)],check=True)
        target=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        target.bind(("127.0.0.1",0));target.settimeout(0.1)
        stopped=threading.Event()
        def echo():
            while not stopped.is_set():
                try:
                    data,source=target.recvfrom(65536);target.sendto(data,source)
                except socket.timeout:
                    continue
                except OSError:
                    return
        thread=threading.Thread(target=echo,daemon=True);thread.start()
        used={target.getsockname()[1]}
        def address():
            while (port:=free_port()) in used:
                pass
            used.add(port);return f"127.0.0.1:{port}"
        peer,edge,relay_admin,edge_admin=[address() for _ in range(4)]
        paths={}
        for role in ("relay","edge"):
            path=demo/f"udp-{role}.json";paths[role]=path
            cfg=json.loads(path.read_text());cfg["listen"]=peer if role=="relay" else edge
            cfg["admin"]=relay_admin if role=="relay" else edge_admin
            if role=="relay":cfg["target"]="127.0.0.1:"+str(target.getsockname()[1])
            else:cfg["peer"]=peer
            path.write_text(json.dumps(cfg))
        processes=[]
        try:
            with (root/"process.log").open("w") as log:
                for role in ("relay","edge"):
                    processes.append(subprocess.Popen([binary,"run","-config",str(paths[role])],stdout=log,stderr=log))
                for admin in (relay_admin,edge_admin):
                    deadline=time.monotonic()+5
                    while True:
                        try:
                            with urllib.request.urlopen(f"http://{admin}/api/status",timeout=1) as response:
                                assert json.load(response)["version"]==(pathlib.Path(__file__).resolve().parent.parent/"VERSION").read_text().strip()
                            break
                        except OSError:
                            if time.monotonic()>deadline:raise RuntimeError("UDP process not ready")
                            time.sleep(0.05)
                host,port=edge.split(":")
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                    client.connect((host,int(port)));client.settimeout(3)
                    for payload in (b"",b"udp sample",bytes(range(256))*64,b"M"*65507):
                        client.send(payload)
                        assert client.recv(65536)==payload,"UDP payload or datagram boundary changed"
                result=subprocess.run([binary,"probe","-config",str(paths["edge"]),"-bytes","262144","-rounds","4"],check=True,capture_output=True,text=True,timeout=10)
                report=json.loads(result.stdout)
                assert report["packet_loss_measured"] is False and report["upload_confirmed_goodput_mbps"]>0
                for admin in (relay_admin,edge_admin):
                    with urllib.request.urlopen(f"http://{admin}/api/status",timeout=2) as response:
                        stats=json.load(response);assert stats["datagrams_returned"]==4
                print("PASS: compiled UDP pair, zero/binary/maximum datagrams, live counters and authenticated probe")
        finally:
            for process in processes:process.terminate()
            for process in processes:
                try:
                    if process.wait(timeout=3)!=0:raise RuntimeError("UDP process exit was not clean")
                except subprocess.TimeoutExpired:
                    process.kill();process.wait();raise RuntimeError("UDP process shutdown hung")
            stopped.set();target.close();thread.join(timeout=1)


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--binary",default="bin/tunnellab-linux-amd64")
    run(parser.parse_args().binary)
