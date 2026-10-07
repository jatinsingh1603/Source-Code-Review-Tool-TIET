## codekavach run

Run the thing.

A second paragraph with markup and `<SECRET:aws_access_key:1>`.

```text
Usage: codekavach run [OPTIONS] [target]
```

**Arguments**

| Argument | Type | Default | Description |
|---|---|---|---|
| `TARGET` | TEXT | . | What to run `<TARGET>` on. |

**Options**

| Option | Type or choices | Default | Description |
|---|---|---|---|
| `--issues / --no-issues` | flag | on | Create issues. |
| `--colour` | red \| blue | red | The colour. |
| `--include` | TEXT (repeatable) |  | A glob; repeat. A \| B. |
| `--name` | TEXT | required | Required name. |
| `--jobs` | INTEGER 1..64 | 4 | Workers. |
| `--api-token` | TEXT | (dynamic) | A token. |

Global options apply.
