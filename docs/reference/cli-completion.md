# Shell completion

`codekavach completion SHELL` prints a completion script for `bash`, `zsh`, `fish` or `powershell`. Without `SHELL`, the shell is detected from the `SHELL` environment variable; if that is not possible, the command exits with code 2 (`shell_unknown`). Redirect the script into your shell's completion directory:

```
bash:        codekavach completion bash > ~/.local/share/bash-completion/completions/codekavach
zsh:         codekavach completion zsh > "${fpath[1]}/_codekavach"   # then: autoload -U compinit && compinit
fish:        codekavach completion fish > ~/.config/fish/completions/codekavach.fish
PowerShell:  codekavach completion powershell >> $PROFILE
```

Bash completion needs bash 4.4 or later. macOS ships bash 3.2, and zsh is the default shell there. When stdout is a terminal, the command also prints the install line for the chosen shell on stderr, so redirecting stdout always gives a clean script. `--json` is ignored for this command, because a completion script is not a JSON document.

## What is completed

- Command and sub-command names, and option names, including the global options after a sub-command (`codekavach scan --pr<TAB>` offers `--privacy-level`, `--profile` and `--progress`).
- `--privacy-level` (`L0` to `L4`), `--fail-on`, `--format` (report formats), `--log-level`, `--log-format` and `doctor --category`.
- `--profile`: the built-in profiles plus the profiles defined in the user and project configuration.
- `--provider` and `providers test PROVIDER_ID`: `mock` plus the configured providers.

## How it behaves

Completion runs on every TAB press, in whatever directory you are in, including an untrusted repository. So:

- **Names without configuration.** Command and option names are answered from the command tree; no configuration is loaded.
- **Bounded reads.** Profile and provider names read the configuration with a 200 ms budget. On any error, such as a malformed `codekavach.toml`, they fall back to the built-in names.
- **Silent and side-effect free.** Nothing is logged or written, no connection is opened, the keyring is not touched, plugins are not discovered, and no project-trust prompt is shown.

The shell asks for candidates by running `codekavach` with `_CODEKAVACH_COMPLETE` set. Both the Click 8 spelling (`bash_complete`) and the spelling in the generated scripts (`complete_bash`) are accepted. Tests: `tests/unit/cli/test_completion.py`.
