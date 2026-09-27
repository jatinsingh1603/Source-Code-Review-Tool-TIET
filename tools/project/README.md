# Project board coordinates

`board.json` records the GitHub Projects v2 board used for progress tracking: project id and number, field ids, single-select option ids (Status, Priority, Size, Epic) and the Sprint iterations with their start dates. Tooling under `tools/` reads it instead of hardcoding ids. Regenerate it if fields or options are changed on the board.
