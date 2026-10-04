"""Initial schema: projects, scans, stage runs and findings (E04-25).

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-28

Owning epic: E04. Written by hand; never edit a released revision. Constraint names follow the
naming convention of ``codekavach.core.store.orm``.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from codekavach.core.store.orm import UtcDateTime

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the four tables with their indexes and constraints."""
    op.create_table(
        "projects",
        sa.Column("id", sa.String(40), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("root", sa.Text(), nullable=True),
        sa.Column("repository_url", sa.Text(), nullable=True),
        sa.Column("created_at", UtcDateTime(), nullable=False),
        sa.Column("document_json", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_projects"),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.String(40), nullable=False),
        sa.Column("project_id", sa.String(40), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("started_at", UtcDateTime(), nullable=False),
        sa.Column("finished_at", UtcDateTime(), nullable=True),
        sa.Column("codekavach_version", sa.String(64), nullable=False),
        sa.Column("config_hash", sa.String(64), nullable=False),
        sa.Column("privacy_level", sa.String(8), nullable=False),
        sa.Column("findings_total", sa.Integer(), nullable=True),
        sa.Column("document_json", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name="fk_scans_project_id_projects",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
    )
    op.create_index("ix_scans_project_id", "scans", ["project_id"])
    op.create_index("ix_scans_started_at", "scans", ["started_at"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_table(
        "stage_runs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.String(40), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_type", sa.String(64), nullable=True),
        sa.Column("skip_reason", sa.String(64), nullable=True),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_stage_runs_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_stage_runs"),
        sa.UniqueConstraint("scan_id", "name", name="uq_stage_runs_scan_id"),
    )
    op.create_index("ix_stage_runs_scan_id", "stage_runs", ["scan_id"])
    op.create_table(
        "findings",
        sa.Column("id", sa.String(40), nullable=False),
        sa.Column("scan_id", sa.String(40), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("cwe", sa.Integer(), nullable=True),
        sa.Column("rule_id", sa.String(200), nullable=True),
        sa.Column("primary_path", sa.Text(), nullable=True),
        sa.Column("primary_line", sa.Integer(), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("document_json", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_findings_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
        sa.UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_id"),
    )
    op.create_index("ix_findings_cwe", "findings", ["cwe"])
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])


def downgrade() -> None:
    """Drop the four tables (dependants first)."""
    op.drop_table("findings")
    op.drop_table("stage_runs")
    op.drop_table("scans")
    op.drop_table("projects")
