"""param_to_param, method resolution, JS handler seeding and the taint settings (E17-03)."""

from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Language
from tests.unit.analysis.taint.test_interproc import _flows, _project


def test_param_to_param_is_summarised() -> None:
    code = "def fill(src, dst):\n    dst.append(src)\n\ndef plain(a, b):\n    return a\n"
    _, summaries, _ = _project({"p.py": code})
    assert (0, 1) in summaries["p.py:fill"].param_to_param
    assert not summaries["p.py:plain"].param_to_param


def test_param_to_param_carries_taint_to_a_sink() -> None:
    code = (
        "from flask import Flask\n"
        "import os\n"
        "app = Flask(__name__)\n"
        "def fill(src, dst):\n"
        "    dst.append(src)\n"
        "\n"
        "@app.route('/x/<c>')\n"
        "def handler(c):\n"
        "    items = []\n"
        "    fill(c, items)\n"
        "    os.system(items[0])\n"
    )
    assert _flows({"p.py": code}, "p.py", "handler")


def test_instance_method_calls_are_resolved() -> None:
    code = (
        "from flask import Flask\n"
        "import os\n"
        "app = Flask(__name__)\n"
        "class Runner:\n"
        "    def run(self, cmd):\n"
        "        os.system(cmd)\n"
        "    def go(self, cmd):\n"
        "        self.run(cmd)\n"
        "\n"
        "@app.route('/x/<c>')\n"
        "def handler(c):\n"
        "    r = Runner()\n"
        "    r.go(c)\n"
    )
    flows = _flows({"r.py": code}, "r.py", "handler")
    assert flows
    assert flows[0].sink_location.start_line == 6


def test_express_handler_parameter_is_seeded() -> None:
    files = {
        "web/util.js": (
            "function load(u) {\n  return fetch(u.target);\n}\nmodule.exports = { load };\n"
        ),
        "web/r.js": (
            "const { load } = require('./util');\n"
            "function handler(req, res) {\n  return load(req);\n}\n"
        ),
    }
    flows = _flows(files, "web/r.js", "handler", Language.JAVASCRIPT)
    assert [f.sink_location.path for f in flows] == ["web/util.js"]


def test_settings_fields_exist() -> None:
    settings = TaintSettings()
    assert (settings.max_depth, settings.recursion_iterations, settings.unknown_callee) == (
        5,
        3,
        "propagate",
    )
