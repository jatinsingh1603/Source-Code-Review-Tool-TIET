"""One test per matcher, positive and negative, for Python and JavaScript (E13-01).

Each case is a small program. A positive case must produce exactly the named rule on the named
line; a negative case (the safe form of the same code) must produce nothing at all, from any
matcher, so a safe form that trips a neighbouring rule is caught too.
"""

import textwrap

import pytest

from codekavach.core.models import Language
from tests.support.rules import found

PY, JS = Language.PYTHON, Language.JAVASCRIPT

# (id, language, code, expected [(rule_id, line)]) -----------------------------------------------
POSITIVE = [
    # SQL injection (CWE-89)
    (
        "sql-percent",
        PY,
        """
        def find(cur, account_id):
            cur.execute("SELECT * FROM accounts WHERE id = '%s'" % account_id)
    """,
        [("py.sql-injection", 3)],
    ),
    (
        "sql-fstring",
        PY,
        """
        def find(cur, account_id):
            cur.execute(f"SELECT * FROM accounts WHERE id = {account_id}")
    """,
        [("py.sql-injection", 3)],
    ),
    (
        "sql-format",
        PY,
        """
        def find(cur, name):
            cur.execute("DELETE FROM accounts WHERE name = '{}'".format(name))
    """,
        [("py.sql-injection", 3)],
    ),
    (
        "sql-concat-variable",
        PY,
        """
        def find(cur, name):
            query = "SELECT * FROM accounts WHERE name = '" + name + "'"
            cur.execute(query)
    """,
        [("py.sql-injection", 4)],
    ),
    (
        "sql-js-concat",
        JS,
        """
        function find(db, id) {
          return db.query("SELECT * FROM accounts WHERE id = " + id);
        }
    """,
        [("js.sql-injection", 3)],
    ),
    (
        "sql-js-template",
        JS,
        """
        function find(db, id) {
          return db.query(`SELECT * FROM accounts WHERE id = ${id}`);
        }
    """,
        [("js.sql-injection", 3)],
    ),
    # Command injection (CWE-78)
    (
        "cmd-subprocess-shell",
        PY,
        """
        def pack(folder):
            subprocess.run(f"zip -r out.zip {folder}", shell=True, check=True)
    """,
        [("py.command-injection", 3)],
    ),
    (
        "cmd-os-system",
        PY,
        """
        def clean(name):
            os.system("rm -rf " + name)
    """,
        [("py.command-injection", 3)],
    ),
    (
        "cmd-os-popen-percent",
        PY,
        """
        def listing(directory):
            return os.popen("ls %s" % directory).read()
    """,
        [("py.command-injection", 3)],
    ),
    (
        "cmd-js-exec",
        JS,
        """
        function listing(dir) {
          return child_process.exec(`ls ${dir}`);
        }
    """,
        [("js.command-injection", 3)],
    ),
    (
        "cmd-js-spawn-shell",
        JS,
        """
        function listing(dir) {
          return spawn("ls " + dir, { shell: true });
        }
    """,
        [("js.command-injection", 3)],
    ),
    # Path traversal (CWE-22)
    (
        "path-open",
        PY,
        """
        def read(filename):
            return open(os.path.join(BASE, filename)).read()
    """,
        [("py.path-traversal", 3)],
    ),
    (
        "path-send-file",
        PY,
        """
        def download(request):
            return send_file(request.args["name"])
    """,
        [("py.path-traversal", 3)],
    ),
    (
        "path-js-fs",
        JS,
        """
        function read(req, res) {
          const file = path.join(root, req.query.f);
          fs.readFile(file, (err, data) => res.send(data));
        }
    """,
        [("js.path-traversal", 4)],
    ),
    # Server-side request forgery (CWE-918)
    (
        "ssrf-requests",
        PY,
        """
        def fetch(url):
            return requests.get(url, timeout=5)
    """,
        [("py.ssrf", 3)],
    ),
    (
        "ssrf-urlopen",
        PY,
        """
        def fetch(request):
            return urllib.request.urlopen(request.args["u"])
    """,
        [("py.ssrf", 3)],
    ),
    (
        "ssrf-js-fetch",
        JS,
        """
        async function status(callbackUrl) {
          return fetch(callbackUrl);
        }
    """,
        [("js.ssrf", 3)],
    ),
    (
        "ssrf-js-axios",
        JS,
        """
        function proxy(req) {
          return axios.get(req.query.target);
        }
    """,
        [("js.ssrf", 3)],
    ),
    # Insecure deserialisation (CWE-502)
    (
        "deser-pickle",
        PY,
        """
        def load(blob):
            return pickle.loads(blob)
    """,
        [("py.insecure-deserialisation", 3)],
    ),
    (
        "deser-yaml",
        PY,
        """
        def load(text):
            return yaml.load(text)
    """,
        [("py.insecure-deserialisation", 3)],
    ),
    (
        "deser-js",
        JS,
        """
        function load(req) {
          return serialize.unserialize(req.body.data);
        }
    """,
        [("js.insecure-deserialisation", 3)],
    ),
    # Weak cryptography (CWE-327, CWE-329)
    (
        "hash-md5-password",
        PY,
        """
        def hash_password(password):
            return hashlib.md5(password.encode()).hexdigest()
    """,
        [("py.weak-password-hash", 3)],
    ),
    (
        "hash-sha1-new",
        PY,
        """
        def store(pwd):
            digest = hashlib.new("sha1", pwd)
            return digest
    """,
        [("py.weak-password-hash", 3)],
    ),
    (
        "hash-js-md5",
        JS,
        """
        function hashPassword(password) {
          return crypto.createHash('md5').update(password).digest('hex');
        }
    """,
        [("js.weak-password-hash", 3)],
    ),
    (
        "iv-literal",
        PY,
        """
        def seal(key, data):
            return AES.new(key, AES.MODE_CBC, b"0000000000000000").encrypt(data)
    """,
        [("py.static-iv", 3)],
    ),
    (
        "iv-module-constant",
        PY,
        """
        IV = b"0123456789abcdef"

        def seal(key, data):
            return AES.new(key, AES.MODE_CBC, iv=IV).encrypt(data)
    """,
        [("py.static-iv", 5)],
    ),
    (
        "iv-zero-bytes",
        PY,
        """
        def seal(key, data):
            iv = bytes(16)
            return AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    """,
        [("py.static-iv", 4)],
    ),
    (
        "iv-js-buffer",
        JS,
        """
        function seal(key) {
          return crypto.createCipheriv('aes-256-cbc', key, Buffer.from('0000000000000000'));
        }
    """,
        [("js.static-iv", 3)],
    ),
    # Missing authorisation (CWE-862)
    (
        "authz-flask",
        PY,
        """
        @app.route("/api/accounts/<account_id>/close", methods=["POST"])
        def close_account(account_id):
            return accounts.close(account_id)
    """,
        [("py.missing-authorization", 3)],
    ),
    (
        "authz-fastapi-router",
        PY,
        """
        @router.get("/customers/{customer_id}")
        def customer(customer_id):
            return customers.load(customer_id)
    """,
        [("py.missing-authorization", 3)],
    ),
    (
        "authz-express",
        JS,
        """
        router.get('/accounts/:id/export', exportStatement);
    """,
        [("js.missing-authorization", 2)],
    ),
    # Insecure direct object reference (CWE-639)
    (
        "idor-flask",
        PY,
        """
        @app.route("/api/accounts/<account_id>/statement")
        @require_auth
        def statement(account_id):
            return accounts.get_statement(conn, account_id)
    """,
        [("py.insecure-direct-object-reference", 5)],
    ),
    (
        "idor-express",
        JS,
        """
        router.get('/accounts/:id', requireSession, (req, res) => {
          Account.findById(req.params.id).then((a) => res.json(a));
        });
    """,
        [("js.insecure-direct-object-reference", 3)],
    ),
    # Reflected cross-site scripting (CWE-79)
    (
        "xss-template-string",
        PY,
        """
        def greet(name):
            return render_template_string("<h1>Hello " + name + "</h1>")
    """,
        [("py.reflected-xss", 3)],
    ),
    (
        "xss-make-response",
        PY,
        """
        def search():
            return make_response(f"<p>{request.args['q']}</p>")
    """,
        [("py.reflected-xss", 3)],
    ),
    (
        "xss-res-send",
        JS,
        """
        function greet(req, res) {
          res.send('<h1>Hello ' + req.query.name + '</h1>');
        }
    """,
        [("js.reflected-xss", 3)],
    ),
    (
        "xss-inner-html",
        JS,
        """
        function show(el, data) {
          el.innerHTML = '<b>' + data + '</b>';
        }
    """,
        [("js.reflected-xss", 3)],
    ),
]

NEGATIVE = [
    # SQL injection
    (
        "sql-bound-tuple",
        PY,
        """
        def find(cur, account_id):
            cur.execute("SELECT * FROM accounts WHERE id = %s", (account_id,))
    """,
    ),
    (
        "sql-static",
        PY,
        """
        def listing(cur):
            cur.execute("SELECT * FROM accounts")
    """,
    ),
    (
        "sql-prepared-name",
        PY,
        """
        def run(cur, statement, parameters):
            cur.execute(statement, parameters)
    """,
    ),
    (
        "sql-not-sql",
        PY,
        """
        def log(cache, name):
            cache.query(f"hello {name}")
    """,
    ),
    (
        "sql-js-bound",
        JS,
        """
        function find(db, id) {
          return db.query("SELECT * FROM accounts WHERE id = ?", [id]);
        }
    """,
    ),
    # Command injection
    (
        "cmd-list-argv",
        PY,
        """
        def pack(folder):
            subprocess.run(["zip", "-r", "out.zip", folder], check=True)
    """,
    ),
    (
        "cmd-no-shell",
        PY,
        """
        def pack(folder):
            subprocess.run(f"zip -r out.zip {folder}")
    """,
    ),
    (
        "cmd-quoted",
        PY,
        """
        def pack(folder):
            subprocess.run(f"zip -r out.zip {shlex.quote(folder)}", shell=True)
    """,
    ),
    (
        "cmd-static",
        PY,
        """
        def uptime():
            return os.popen("uptime").read()
    """,
    ),
    (
        "cmd-js-execfile",
        JS,
        """
        function listing(dir) {
          return execFile("ls", [dir]);
        }
    """,
    ),
    (
        "cmd-js-static",
        JS,
        """
        function uptime() {
          return exec("uptime");
        }
    """,
    ),
    (
        "cmd-js-spawn-no-shell",
        JS,
        """
        function listing(dir) {
          return spawn("ls", [dir]);
        }
    """,
    ),
    # Path traversal
    (
        "path-startswith",
        PY,
        """
        def read(filename):
            resolved = os.path.realpath(os.path.join(BASE, filename))
            if not resolved.startswith(BASE):
                abort(400)
            return open(resolved).read()
    """,
    ),
    (
        "path-secure-filename",
        PY,
        """
        def read(filename):
            return open(os.path.join(BASE, secure_filename(filename))).read()
    """,
    ),
    (
        "path-static",
        PY,
        """
        def config():
            return open("config.ini").read()
    """,
    ),
    (
        "path-js-startswith",
        JS,
        """
        function read(req, res) {
          const resolved = path.resolve(root, req.query.f);
          if (!resolved.startsWith(root + path.sep)) { return res.sendStatus(400); }
          fs.readFile(resolved, (err, data) => res.end(data));
        }
    """,
    ),
    (
        "path-js-root-option",
        JS,
        """
        function download(req, res) {
          res.sendFile(req.params.name, { root: DIR });
        }
    """,
    ),
    # SSRF
    (
        "ssrf-allowlist",
        PY,
        """
        def fetch(url):
            if urlparse(url).hostname not in ALLOWED_HOSTS:
                raise ValueError(url)
            return requests.get(url, timeout=5)
    """,
    ),
    (
        "ssrf-constant-url",
        PY,
        """
        def rates():
            return requests.get("https://rates.example.com/today").json()
    """,
    ),
    (
        "ssrf-constant-built",
        PY,
        """
        def rates():
            return requests.get(BASE + "/rates").json()
    """,
    ),
    (
        "ssrf-js-allowlist",
        JS,
        """
        async function rate(url) {
          if (!allowedHosts.includes(new URL(url).hostname)) { throw new Error('no'); }
          return fetch(url);
        }
    """,
    ),
    (
        "ssrf-js-constant",
        JS,
        """
        async function rate() {
          return fetch('https://rates.example.com/today');
        }
    """,
    ),
    # Deserialisation
    (
        "deser-json",
        PY,
        """
        def load(text):
            return json.loads(text)
    """,
    ),
    (
        "deser-safe-load",
        PY,
        """
        def load(text):
            return yaml.safe_load(text)
    """,
    ),
    (
        "deser-yaml-safe-loader",
        PY,
        """
        def load(text):
            return yaml.load(text, Loader=yaml.SafeLoader)
    """,
    ),
    (
        "deser-literal",
        PY,
        """
        def sample():
            return pickle.loads(b"\\x80\\x04N.")
    """,
    ),
    (
        "deser-js-json",
        JS,
        """
        function load(req) {
          return JSON.parse(req.body.data);
        }
    """,
    ),
    # Weak cryptography
    (
        "hash-md5-not-password",
        PY,
        """
        def checksum(data):
            return hashlib.md5(data).hexdigest()
    """,
    ),
    (
        "hash-scrypt",
        PY,
        """
        def hash_password(password, salt):
            return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    """,
    ),
    (
        "hash-sha256-password",
        PY,
        """
        def hash_password(password):
            return hashlib.sha256(password.encode()).hexdigest()
    """,
    ),
    (
        "hash-js-sha256",
        JS,
        """
        function hashPassword(password) {
          return crypto.createHash('sha256').update(password).digest('hex');
        }
    """,
    ),
    (
        "iv-random",
        PY,
        """
        def seal(key, data):
            iv = os.urandom(16)
            return AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    """,
    ),
    (
        "iv-parameter",
        PY,
        """
        def seal(key, iv, data):
            return AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    """,
    ),
    (
        "iv-js-random",
        JS,
        """
        function seal(key) {
          return crypto.createCipheriv('aes-256-cbc', key, crypto.randomBytes(16));
        }
    """,
    ),
    # Missing authorisation
    (
        "authz-decorated",
        PY,
        """
        @app.route("/api/accounts/<account_id>/close", methods=["POST"])
        @login_required
        def close_account(account_id):
            return accounts.close(account_id)
    """,
    ),
    (
        "authz-not-account-scoped",
        PY,
        """
        @app.route("/health")
        def health():
            return "ok"
    """,
    ),
    (
        "authz-inline-check",
        PY,
        """
        @app.route("/api/accounts/<account_id>/close", methods=["POST"])
        def close_account(account_id):
            if g.user is None:
                abort(401)
            return accounts.close(account_id)
    """,
    ),
    (
        "authz-fastapi-depends",
        PY,
        """
        @router.get("/customers/{customer_id}")
        def customer(customer_id, user=Depends(current_user)):
            return customers.load(customer_id)
    """,
    ),
    (
        "authz-express-middleware",
        JS,
        """
        router.get('/accounts/:id/export', requireSession, exportStatement);
    """,
    ),
    (
        "authz-express-public",
        JS,
        """
        router.get('/health', (req, res) => res.json({ ok: true }));
    """,
    ),
    # IDOR
    (
        "idor-owner-check",
        PY,
        """
        @app.route("/api/accounts/<account_id>")
        @require_auth
        def account(account_id):
            account = accounts.find_account_by_id(conn, account_id)
            if account["owner_id"] != g.user["id"]:
                abort(404)
            return account
    """,
    ),
    (
        "idor-not-a-route",
        PY,
        """
        def helper(account_id):
            return accounts.find_account_by_id(conn, account_id)
    """,
    ),
    (
        "idor-js-owner-check",
        JS,
        """
        router.get('/accounts/:id', requireSession, (req, res) => {
          Account.findById(req.params.id).then((a) => {
            if (a.ownerId !== req.user.id) { return res.sendStatus(404); }
            res.json(a);
          });
        });
    """,
    ),
    # XSS
    (
        "xss-escaped",
        PY,
        """
        def greet(name):
            return render_template_string("<h1>Hello " + html.escape(name) + "</h1>")
    """,
    ),
    (
        "xss-template-file",
        PY,
        """
        def greet(name):
            return render_template("greet.html", name=name)
    """,
    ),
    (
        "xss-js-escaped",
        JS,
        """
        function greet(req, res) {
          res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>');
        }
    """,
    ),
    (
        "xss-js-static",
        JS,
        """
        function ok(req, res) {
          res.send('<h1>Welcome</h1>');
        }
    """,
    ),
    (
        "xss-js-plain-text-body",
        JS,
        """
        function greet(req, res) {
          res.send('Hello ' + req.query.name);
        }
    """,
    ),
    (
        "xss-make-response-plain-text",
        PY,
        """
        def greet(name):
            return make_response("Hello " + name)
    """,
    ),
    (
        "xss-js-text-content",
        JS,
        """
        function show(el, data) {
          el.textContent = data;
        }
    """,
    ),
]


def _ids(cases: list[tuple]) -> list[str]:  # type: ignore[type-arg]
    return [f"{case[0]}-{case[1].value}" for case in cases]


@pytest.mark.parametrize(("name", "language", "code", "expected"), POSITIVE, ids=_ids(POSITIVE))
def test_a_weak_form_is_reported(
    name: str, language: Language, code: str, expected: list[tuple[str, int]]
) -> None:
    assert found(textwrap.dedent(code), language) == expected


@pytest.mark.parametrize(("name", "language", "code"), NEGATIVE, ids=_ids(NEGATIVE))
def test_the_safe_form_reports_nothing(name: str, language: Language, code: str) -> None:
    assert found(textwrap.dedent(code), language) == []


def test_every_matcher_is_exercised_in_both_languages() -> None:
    slugs = {
        (rule.split(".", 1)[0], rule.split(".", 1)[1]) for case in POSITIVE for rule, _ in case[3]
    }
    expected = {
        "sql-injection", "command-injection", "path-traversal", "ssrf", "insecure-deserialisation",
        "weak-password-hash", "static-iv", "missing-authorization",
        "insecure-direct-object-reference", "reflected-xss",
    }  # fmt: skip
    for language_prefix in ("py", "js"):
        assert {slug for prefix, slug in slugs if prefix == language_prefix} == expected
