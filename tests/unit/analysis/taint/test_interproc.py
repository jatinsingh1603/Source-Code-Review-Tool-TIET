"""Summaries, interprocedural propagation, recursion and framework entry points (E17-03)."""

from pathlib import Path

from codekavach.analysis.taint.catalogue import Binding
from codekavach.analysis.taint.frameworks import entry_kind, entry_seeds
from codekavach.analysis.taint.interproc import ProjectIndex, compute_summaries, make_lookup
from codekavach.analysis.taint.propagate import Budget, FlowWitness, propagate_bound
from codekavach.analysis.taint.summary import FunctionSummary
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Language
from tests.support.taint import function_of, lower_source, shipped_catalogues

SETTINGS = TaintSettings()


def _project(
    files: dict[str, str], language: Language = Language.PYTHON
) -> tuple[ProjectIndex, dict[str, FunctionSummary], dict[str, Binding]]:
    index = ProjectIndex()
    bindings: dict[str, Binding] = {}
    for path, code in files.items():
        module = lower_source(code, language, path=path)
        index.add(module)
        bindings[path] = Binding(shipped_catalogues(), module.aliases, language.value)
    summaries = compute_summaries(index, lambda path: bindings[path], SETTINGS)
    return index, {f"{k[0]}:{k[1]}": v for k, v in summaries.items()}, bindings


def _flows(
    files: dict[str, str], path: str, qual: str, language: Language = Language.PYTHON
) -> list[FlowWitness]:
    index, _, bindings = _project(files, language)
    summaries = compute_summaries(index, lambda p: bindings[p], SETTINGS)
    function = function_of(index.modules[path], qual)
    return propagate_bound(
        function,
        bindings[path],
        budget=Budget.of(10),
        settings=SETTINGS,
        seeds=entry_seeds(function),
        lookup=make_lookup(index, summaries, path),
    )


REPO = {
    "svc/repo.py": (
        "def find(conn, ident):\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(\"SELECT * FROM t WHERE id = '%s'\" % ident)\n"
        "    return cur.fetchone()\n"
        "\n"
        "def passthrough(value):\n"
        "    return value\n"
        "\n"
        "def clean(value):\n"
        "    return int(value)\n"
    ),
    "svc/views.py": (
        "import repo\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/a/<account_id>')\n"
        "def show(account_id):\n"
        "    conn = repo.connect()\n"
        "    return repo.find(conn, account_id)\n"
        "\n"
        "@app.route('/b/<account_id>')\n"
        "def safe(account_id):\n"
        "    conn = repo.connect()\n"
        "    return repo.find(conn, repo.clean(account_id))\n"
    ),
}


def test_summary_records_param_to_sink_and_return() -> None:
    _, summaries, _ = _project(REPO)
    find = summaries["svc/repo.py:find"]
    assert [(r.param, r.sink.weakness.cwe) for r in find.param_to_sink] == [(1, (89,))]
    assert summaries["svc/repo.py:passthrough"].param_to_return == {0}
    assert summaries["svc/repo.py:clean"].param_to_return == {0}
    assert not summaries["svc/repo.py:clean"].param_to_sink


def test_route_parameter_reaches_a_sink_in_another_file() -> None:
    flows = _flows(REPO, "svc/views.py", "show")
    assert len(flows) == 1
    flow = flows[0]
    assert flow.sink_location.path == "svc/repo.py" and flow.depth == 1
    assert flow.label == "http_param"
    assert flow.steps[0].location.path == "svc/views.py"  # the route parameter
    assert any("call find" in (step.note or "") for step in flow.steps)


def test_a_narrowing_callee_cuts_the_flow() -> None:
    assert _flows(REPO, "svc/views.py", "safe") == []


def test_entry_points_are_recognised() -> None:
    module = lower_source(REPO["svc/views.py"], path="svc/views.py")
    show = function_of(module, "show")
    assert entry_kind(show) == "http_handler"
    assert set(entry_seeds(show)) == {"account_id"}
    assert entry_kind(function_of(module, "<module>")) is None


def test_recursion_terminates() -> None:
    code = (
        "import os\n"
        "def walk(path, depth):\n"
        "    if depth:\n"
        "        return walk(path + 'x', depth - 1)\n"
        "    os.system(path)\n"
        "    return path\n"
    )
    _, summaries, _ = _project({"m.py": code})
    walk = summaries["m.py:walk"]
    assert 0 in walk.param_to_return
    assert any(r.param == 0 for r in walk.param_to_sink)


def test_depth_is_bounded() -> None:
    chain = "".join(f"def f{i}(x):\n    return f{i + 1}(x)\n\n" for i in range(7))
    code = chain + "import os\ndef f7(x):\n    os.system(x)\n"
    files = {"c.py": code, "h.py": "import c\ndef h(request):\n    c.f0(request.args['q'])\n"}
    flows = _flows(files, "h.py", "h")
    assert all(flow.depth <= 5 for flow in flows)


def test_allow_list_guard_clears_the_flow() -> None:
    code = (
        "import requests\n"
        "ALLOWED = {'a.example.test'}\n"
        "def fetch(request):\n"
        "    url = request.args['u']\n"
        "    if url not in ALLOWED:\n"
        "        raise ValueError('no')\n"
        "    return requests.get(url)\n"
    )
    assert _flows({"g.py": code}, "g.py", "fetch") == []


def test_javascript_relative_require_resolves() -> None:
    files = {
        "web/pay.js": (
            "async function pull(u) {\n  return fetch(u);\n}\nmodule.exports = { pull };\n"
        ),
        "web/routes.js": (
            "const { pull } = require('./pay');\n"
            "function handler(req, res) {\n  return pull(req.query.cb);\n}\n"
        ),
    }
    flows = _flows(files, "web/routes.js", "handler", Language.JAVASCRIPT)
    assert [f.sink_location.path for f in flows] == ["web/pay.js"]


def test_sample_payments_summaries() -> None:
    root = Path(__file__).resolve().parents[4] / "fixtures" / "kavachbank" / "services" / "web"
    files = {f"web/{p.name}": p.read_text("utf-8") for p in root.glob("*.js")}
    _, summaries, _ = _project(files, Language.JAVASCRIPT)
    assert summaries["web/payments.js:fetchSettlementStatus"].param_to_sink
    assert not summaries["web/payments.js:fetchPartnerRate"].param_to_sink
