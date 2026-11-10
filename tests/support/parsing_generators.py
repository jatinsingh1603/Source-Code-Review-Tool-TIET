"""Small, independently valid statements, combined into generated Python/JS programs.

Each snippet is syntactically complete on its own (a top-level statement or definition); joining
any ordering of them with blank lines still parses cleanly, which is what lets
``test_extraction_hypothesis.py`` vary shape without a real grammar-based generator.
"""

_PYTHON_SNIPPETS = [
    "def top_level(a, b):\n    return a + b\n",
    (
        'class Widget:\n    """A docstring."""\n\n'
        "    def method(self, x):\n        # a comment\n        return x\n"
    ),
    "value = 'hello ' + name\n",
    'query = "SELECT * FROM t WHERE id = %s" % value\n',
    "items = [i * 2 for i in range(10) if i % 2 == 0]\n",
    "async def fetch(url):\n    return await client.get(url)\n",
    "with open('data.txt') as handle:\n    contents = handle.read()\n",
    "greeting = f'hi {name}, total {1 + 2}'\n",
]

_JAVASCRIPT_SNIPPETS = [
    "function topLevel(a, b) {\n  return a + b;\n}\n",
    "class Widget {\n  // a comment\n  method(x) {\n    return x;\n  }\n}\n",
    "const value = 'hello ' + name;\n",
    "const query = 'SELECT * FROM t WHERE id = ' + value;\n",
    "const items = [1, 2, 3].filter((i) => i % 2 === 0);\n",
    "async function fetchData(url) {\n  return await fetch(url);\n}\n",
    "const { a, b } = require('./module');\n",
    "const greeting = `hi ${name}, total ${1 + 2}`;\n",
]


def python_program(order: list[int]) -> str:
    """A valid Python program combining the snippet pool in ``order`` (a permutation of 0..7)."""
    return "\n".join(_PYTHON_SNIPPETS[i] for i in order)


def javascript_program(order: list[int]) -> str:
    """A valid JS program combining the snippet pool in ``order`` (a permutation of 0..7)."""
    return "\n".join(_JAVASCRIPT_SNIPPETS[i] for i in order)


_JAVA_SNIPPETS = [
    ("class TopLevel {\n    int add(int a, int b) {\n        return a + b;\n    }\n}\n"),
    ("class Widget {\n    // a comment\n    int method(int x) {\n        return x;\n    }\n}\n"),
    (
        "class Greeter {\n"
        "    String hello(String name) {\n"
        '        return "hello " + name;\n'
        "    }\n"
        "}\n"
    ),
    (
        "class Query {\n"
        "    String q(String id) {\n"
        '        return "SELECT * FROM t WHERE id = " + id;\n'
        "    }\n"
        "}\n"
    ),
    (
        "class Lists {\n"
        "    void each(java.util.List<Integer> xs) {\n"
        "        xs.forEach(i -> use(i * 2));\n"
        "    }\n"
        "}\n"
    ),
    (
        "class Loops {\n"
        "    int sum(int n) {\n"
        "        int t = 0;\n"
        "        for (int i = 0; i < n; i++) { t += i; }\n"
        "        return t;\n"
        "    }\n"
        "}\n"
    ),
    (
        "class Files {\n"
        "    void read(java.io.Reader r) throws Exception {\n"
        "        try (java.io.Reader q = r) { q.read(); }\n"
        "    }\n"
        "}\n"
    ),
    ('class Blocks {\n    String text = """\n        hi\n        """;\n}\n'),
]

_GO_SNIPPETS = [
    ("func topLevel(a int, b int) int {\n\treturn a + b\n}\n"),
    (
        "type Widget struct{ size int }\n"
        "\n"
        "// Grow adds to the size.\n"
        "func (w *Widget) Grow(x int) int {\n"
        "\treturn w.size + x\n"
        "}\n"
    ),
    ('var greeting = "hello " + name\n'),
    ('var query = "SELECT * FROM t WHERE id = " + id\n'),
    ("func each(xs []int) {\n\tfor i, x := range xs {\n\t\tuse(i, x)\n\t}\n}\n"),
    ("func closure() func() int {\n\tn := 0\n\treturn func() int { n++; return n }\n}\n"),
    ("func cond(x int) int {\n\tif y := x + 1; y > 2 {\n\t\treturn y\n\t}\n\treturn 0\n}\n"),
    ("const raw = `line one\nline two`\n"),
]


def java_program(order: list[int]) -> str:
    """A valid Java file combining the snippet pool in ``order`` (a permutation of 0..7)."""
    return "\n".join(_JAVA_SNIPPETS[i] for i in order)


def go_program(order: list[int]) -> str:
    """A valid Go file combining the snippet pool in ``order`` (a permutation of 0..7)."""
    return "package generated\n\n" + "\n".join(_GO_SNIPPETS[i] for i in order)
