"""Internal and private component classification (E19-01).

A component is internal when any of these holds, and the first reason found is recorded:

* its resolved download host is not a known public registry host,
* its name matches a configured private scope or prefix,
* its source is a local path or a version-control reference,
* the project's package-manager configuration (``.npmrc``, ``.yarnrc.yml``, ``pip.conf``,
  ``nuget.config``, ``settings.xml``) points the ecosystem at a private index.

Internal components are never sent to an advisory matcher or any outbound path.
"""

import posixpath
import re
from collections.abc import Iterable, Mapping
from urllib.parse import urlparse

from codekavach.analysis.sca.model import Dependency

PUBLIC_HOSTS = frozenset(
    {
        "registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com",
        "pypi.org", "files.pythonhosted.org", "pypi.python.org",
        "repo.maven.apache.org", "repo1.maven.org", "plugins.gradle.org", "jcenter.bintray.com",
        "proxy.golang.org", "sum.golang.org", "rubygems.org", "index.rubygems.org",
        "repo.packagist.org", "packagist.org", "api.nuget.org", "crates.io", "static.crates.io",
        "index.crates.io", "github.com", "codeload.github.com", "api.github.com",
        "gitlab.com", "bitbucket.org",
    }
)  # fmt: skip
_VCS = re.compile(r"^(git\+|git:|git@|github:|gitlab:|bitbucket:|hg\+|svn\+|ssh:)")
_LOCAL = re.compile(r"^(file:|link:|workspace:|portal:|\.{1,2}/|/)")
_CONFIG_URL = re.compile(
    r"(?:registry|index-url|extra-index-url|<url>|source key=\"[^\"]*\" value=)"
    r"[\s=:\"]*\"?(https?://[^\s\"'<]+)",
    re.IGNORECASE,
)
_CONFIG_NAMES = frozenset({".npmrc", ".yarnrc.yml", "pip.conf", "nuget.config", "settings.xml"})


def host_of(url: str) -> str | None:
    """The host of ``url``, lower-cased, or None when it has none."""
    return (urlparse(url).hostname or "").lower() or None


def is_public_host(host: str) -> bool:
    """True for a known public registry host (or a subdomain of one)."""
    return any(host == h or host.endswith("." + h) for h in PUBLIC_HOSTS)


def private_hosts_from_config(files: Mapping[str, str]) -> dict[str, str]:
    """Hosts that package-manager configuration files point at, mapped to the file naming them."""
    found: dict[str, str] = {}
    for path, text in files.items():
        if posixpath.basename(path).lower() not in _CONFIG_NAMES:
            continue
        for m in _CONFIG_URL.finditer(text):
            host = host_of(m[1])
            if host and not is_public_host(host):
                found.setdefault(host, path)
    return found


def classify(  # noqa: PLR0911 - one return per documented rule
    dep: Dependency,
    *,
    private_prefixes: Iterable[str] = (),
    private_hosts: Mapping[str, str] | None = None,
) -> str | None:
    """The reason ``dep`` is internal, or None when it is a public component."""
    if dep.internal_reason:
        return dep.internal_reason
    for prefix in private_prefixes:
        if prefix and dep.name.lower().startswith(prefix.lower()):
            return f"name matches the configured private prefix {prefix}"
    url = dep.source_url or ""
    declared = dep.declared_range or ""
    for text in (url, declared):
        if _LOCAL.match(text):
            return "local path source"
        if _VCS.match(text):
            return "version-control source"
    if url:
        host = host_of(url)
        if host:
            if private_hosts and host in private_hosts:
                return f"registry host {host} is configured in {private_hosts[host]}"
            if not is_public_host(host):
                return f"registry host {host} is not a known public host"
    if dep.is_internal:
        return "name or lock metadata marks it private"
    return None


def apply(
    deps: Iterable[Dependency],
    files: Mapping[str, str] | None = None,
    private_prefixes: Iterable[str] = (),
) -> tuple[Dependency, ...]:
    """``deps`` with ``is_internal`` and ``internal_reason`` set from every rule."""
    hosts = private_hosts_from_config(files or {})
    prefixes = tuple(private_prefixes)
    out: list[Dependency] = []
    for dep in deps:
        reason = classify(dep, private_prefixes=prefixes, private_hosts=hosts)
        out.append(dep.evolve(is_internal=True, internal_reason=reason) if reason else dep)
    return tuple(out)
