import base64
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import procmon  # noqa: E402


def fetch(url, auth=None):
    req = urllib.request.Request(url)
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


class Snapshot(unittest.TestCase):
    def test_shape_and_own_process(self):
        procmon.snapshot()
        time.sleep(1)                      # the cache lives 0.8 s; the second call computes rates
        d = json.loads(procmon.snapshot())
        self.assertGreater(d["mem"][1], 0)
        self.assertLessEqual(d["mem"][0], d["mem"][1])
        self.assertGreaterEqual(d["cpu"], 0)
        self.assertTrue(d["disks"])
        mine = [p for p in d["procs"] if p[0] == os.getpid()]
        self.assertEqual(len(mine), 1)
        pid, comm, user, cpu, rss, rd, wr, threads, cmd = mine[0]
        self.assertGreater(rss, 0)
        self.assertGreaterEqual(threads, 1)


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), procmon.H)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        self._auth = procmon.AUTH

    def tearDown(self):
        procmon.AUTH = self._auth

    def test_open_without_credentials_configured(self):
        procmon.AUTH = (None, None)
        self.assertEqual(fetch(self.base + "/")[0], 200)
        status, body = fetch(self.base + "/api")
        self.assertEqual(status, 200)
        self.assertIn("procs", json.loads(body))

    def test_basic_auth(self):
        procmon.AUTH = ("u", "p")
        self.assertEqual(fetch(self.base + "/api")[0], 401)
        self.assertEqual(fetch(self.base + "/api", "u:wrong")[0], 401)
        self.assertEqual(fetch(self.base + "/api", "u:p")[0], 200)

    def test_healthz_needs_no_login(self):
        procmon.AUTH = ("u", "p")
        self.assertEqual(fetch(self.base + "/healthz"), (200, b"ok"))


if __name__ == "__main__":
    unittest.main()
