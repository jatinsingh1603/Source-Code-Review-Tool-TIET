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
