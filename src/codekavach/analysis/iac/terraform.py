# ruff: noqa: SIM102
"""Terraform (HCL) checks, text-based: resource blocks are found by brace matching."""

import re
from dataclasses import dataclass
from typing import Final

from codekavach.analysis.iac.common import Issue
from codekavach.core.models import Confidence, Severity

_RESOURCE: Final = re.compile(r'^\s*resource\s+"([A-Za-z0-9_]+)"\s+"([^"]+)"\s*\{', re.M)
_SENSITIVE_PORTS: Final = {"22", "3389", "3306", "5432", "1433", "6379", "27017", "0"}


@dataclass
class _Block:
    kind: str
    name: str
    start_line: int
    body: str
    body_start: int  # line number of the first body line


def _blocks(text: str) -> list[_Block]:
    out: list[_Block] = []
    for m in _RESOURCE.finditer(text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        start_line = text.count("\n", 0, m.start()) + 1
        out.append(_Block(m.group(1), m.group(2), start_line, text[m.end() : i - 1], start_line))
    return out


def _line(block: _Block, pattern: str) -> int | None:
    m = re.search(pattern, block.body, re.I | re.M)
    return block.body_start + block.body.count("\n", 0, m.start()) if m else None


def _attr_is(block: _Block, name: str, value: str) -> int | None:
    return _line(block, rf'^\s*{name}\s*=\s*"?{value}"?\s*(#.*)?$')


def _has(block: _Block, name: str) -> bool:
    return re.search(rf"^\s*{name}\s*=", block.body, re.M) is not None


def check_terraform(text: str) -> list[Issue]:
    """Public buckets, world-open security groups and unencrypted storage."""
    issues: list[Issue] = []
    for b in _blocks(text):
        if b.kind in {"aws_s3_bucket", "aws_s3_bucket_acl"}:
            line = _line(b, r'^\s*acl\s*=\s*"public-read(-write)?"')
            if line:
                issues.append(
                    Issue(
                        "iac.terraform.s3-public-acl",
                        line,
                        Severity.HIGH,
                        732,
                        f"S3 bucket '{b.name}' uses a public ACL.",
                    )
                )
        if b.kind == "aws_s3_bucket_public_access_block":
            for attr in (
                "block_public_acls",
                "block_public_policy",
                "ignore_public_acls",
                "restrict_public_buckets",
            ):
                line = _attr_is(b, attr, "false")
                if line:
                    issues.append(
                        Issue(
                            "iac.terraform.s3-public-access-block-off",
                            line,
                            Severity.HIGH,
                            732,
                            f"Public access block '{b.name}' leaves {attr} off.",
                        )
                    )
        if b.kind in {
            "aws_security_group",
            "aws_security_group_rule",
            "aws_vpc_security_group_ingress_rule",
        }:
            _security_group(b, issues)
        if b.kind == "aws_db_instance":
            if _attr_is(b, "storage_encrypted", "false") or not _has(b, "storage_encrypted"):
                issues.append(
                    Issue(
                        "iac.terraform.unencrypted-storage",
                        _attr_is(b, "storage_encrypted", "false") or b.start_line,
                        Severity.MEDIUM,
                        311,
                        f"Database '{b.name}' storage is not encrypted.",
                    )
                )
            line = _attr_is(b, "publicly_accessible", "true")
            if line:
                issues.append(
                    Issue(
                        "iac.terraform.public-database",
                        line,
                        Severity.HIGH,
                        668,
                        f"Database '{b.name}' is publicly accessible.",
                    )
                )
        if b.kind in {"aws_ebs_volume", "aws_efs_file_system"}:
            if _attr_is(b, "encrypted", "false") or not _has(b, "encrypted"):
                issues.append(
                    Issue(
                        "iac.terraform.unencrypted-storage",
                        _attr_is(b, "encrypted", "false") or b.start_line,
                        Severity.MEDIUM,
                        311,
                        f"Volume '{b.name}' is not encrypted.",
                    )
                )
    return issues


def _security_group(b: _Block, issues: list[Issue]) -> None:
    for m in re.finditer(r'0\.0\.0\.0/0|"::/0"', b.body):
        line = b.body_start + b.body.count("\n", 0, m.start())
        window = b.body[max(0, m.start() - 400) : m.end() + 400]
        if re.search(r"\begress\b", b.body[max(0, m.start() - 300) : m.start()]) and not re.search(
            r"\bingress\b", b.body[max(0, m.start() - 300) : m.start()]
        ):
            continue
        ports = set(re.findall(r"(?:from_port|to_port)\s*=\s*(\d+)", window))
        sensitive = bool(ports & _SENSITIVE_PORTS)
        issues.append(
            Issue(
                "iac.terraform.open-security-group",
                line,
                Severity.HIGH if sensitive else Severity.MEDIUM,
                284,
                f"Security group '{b.name}' allows ingress from the whole internet"
                + (" on an administrative or database port." if sensitive else "."),
                Confidence.HIGH if sensitive else Confidence.MEDIUM,
            )
        )
