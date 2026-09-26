#!/usr/bin/env python3
"""Export the optional manager SQLite source for encrypted profile discovery.

Works on any PaperFlux manager installation, without bot/VPS credentials.
No profile data is printed. The output is owner-only and atomically replaced.
"""
import argparse
import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path


def export(database, output, owner=None):
    target = Path(output)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    connection = sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        rows = connection.execute("SELECT id,name,access_token,client_ip,transport,doc,runtime_url FROM profiles ORDER BY id").fetchall()
    finally:
        connection.close()
    profiles = []
    owners = set()
    for identity, name, token, ip, provider, doc, runtime in rows:
        resource = runtime if provider == "cupsonline" else doc
        if not resource or not token or len(token) < 32:
            continue
        docs = [part.strip() for part in resource.split(",") if part.strip()] if provider == "yandex" else [resource.strip()]
        keys = {(provider, item) for item in docs}
        if owners.intersection(keys):
            continue
        owners.update(keys)
        profiles.append(dict(id=str(identity), name=name, token=token, clientIp=ip, transport=provider, documentUrls=docs))
    content = json.dumps(profiles, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if target.exists() and target.read_bytes() == content:
        os.chmod(target, 0o600)
        if owner is not None:
            os.chown(target, *owner)
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".profiles-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if owner is not None:
            os.chown(temporary, *owner)
        os.replace(temporary, target)
        os.chmod(target, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--owner", help="Linux account which reads the private output")
    args = parser.parse_args()
    owner = None
    if args.owner:
        import pwd
        account = pwd.getpwnam(args.owner)
        owner = (account.pw_uid, account.pw_gid)
    while True:
        export(args.database, args.output, owner)
        if not args.watch:
            return
        time.sleep(10)


if __name__ == "__main__":
    main()
