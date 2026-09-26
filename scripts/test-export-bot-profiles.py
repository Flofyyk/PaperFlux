import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("profile_export", Path(__file__).with_name("export-bot-profiles.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ExportTests(unittest.TestCase):
    def test_read_only_export_atomic_update_and_cups_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "profiles.db"
            output = Path(temporary) / "private" / "profiles.json"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE profiles (id INTEGER, name TEXT, access_token TEXT, client_ip TEXT, transport TEXT, doc TEXT, runtime_url TEXT)")
            connection.executemany("INSERT INTO profiles VALUES (?,?,?,?,?,?,?)", [
                (1, "Example", "x"*43, "10.10.10.2", "yandex", "https://disk.yandex.ru/i/example", ""),
                (2, "Duplicate", "y"*43, "10.10.10.3", "yandex", "https://disk.yandex.ru/i/example", ""),
                (3, "Cups", "z"*43, "10.10.10.4", "cupsonline", "https://cups.online", "base64-room-list"),
            ])
            connection.commit()
            before = database.read_bytes()
            module.export(database, output)
            self.assertEqual(before, database.read_bytes())
            rows = json.loads(output.read_text())
            self.assertEqual(["1", "3"], [row["id"] for row in rows])
            self.assertEqual(["base64-room-list"], rows[1]["documentUrls"])
            if os.name != "nt":
                self.assertEqual(0o600, output.stat().st_mode & 0o777)
            connection.execute("DELETE FROM profiles WHERE id=1")
            connection.commit()
            module.export(database, output)
            self.assertEqual(["2", "3"], [row["id"] for row in json.loads(output.read_text())])
            self.assertEqual([], list(output.parent.glob(".profiles-*")))
            connection.close()


if __name__ == "__main__":
    unittest.main()
