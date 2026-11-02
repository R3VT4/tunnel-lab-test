#!/usr/bin/env python3
"""Test installation in a disposable root; never use systemd or service accounts."""
import argparse
import json
import os
import pathlib
import subprocess
import tempfile


def run(binary):
    binary=pathlib.Path(binary).resolve()
    project=pathlib.Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="tunnellab-install-") as tmp:
        root=pathlib.Path(tmp);stage=root/"staged-root";fake=root/"fake-bin";fake.mkdir()
        for name in ("systemctl","useradd","getent"):
            path=fake/name;path.write_text('#!/bin/sh\necho "Forbidden global operation" >&2\nexit 99\n');path.chmod(0o755)
        env=os.environ.copy();env["PATH"]=str(fake)+os.pathsep+env["PATH"]
        subprocess.run(["bash",str(project/"scripts/install.sh"),"--binary",str(binary),"--staging-dir",str(stage)],check=True,env=env)
        installed=stage/"usr/local/bin/tunnellab"
        assert installed.read_bytes()==binary.read_bytes()
        assert (stage/"etc/systemd/system/tunnellab@.service").is_file()
        assert not list((stage/"etc/tunnellab/instances").iterdir())
        subprocess.run([str(installed),"selftest"],check=True)
        demo=root/"demo";subprocess.run([str(installed),"init","-dir",str(demo)],check=True)
        subprocess.run([str(installed),"check","-config",str(demo/"edge.json")],check=True)
        instances=root/"instances"
        subprocess.run([str(installed),"service","add","-dir",str(instances),"-name","edge-one","-config",str(demo/"edge.json")],check=True)
        result=subprocess.run([str(installed),"service","list","-dir",str(instances)],check=True,capture_output=True,text=True)
        assert json.loads(result.stdout)["edge-one"]["mode"]=="edge"
        duplicate=subprocess.run([str(installed),"service","add","-dir",str(instances),"-name","edge-one","-config",str(demo/"edge.json")],capture_output=True)
        assert duplicate.returncode!=0
        invalid=root/"invalid.json";invalid.write_text('{}')
        rejected=subprocess.run([str(installed),"check","-config",str(invalid)],capture_output=True)
        assert rejected.returncode!=0
        repeated=subprocess.run(["bash",str(project/"scripts/install.sh"),"--binary",str(binary),"--staging-dir",str(stage)],capture_output=True,env=env)
        assert repeated.returncode!=0,"existing staged directory was overwritten"
        print("PASS: isolated installation, built-in checks, managed add/list, duplicate rejection; no systemd/user changes")


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--binary",default="bin/tunnellab-linux-amd64")
    run(parser.parse_args().binary)
