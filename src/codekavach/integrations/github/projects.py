"""Projects v2 synchronisation through GraphQL.

Owning epic: E34.

Adds each issue to the board and sets the single-select ``Status`` and ``Severity`` fields when
the board has them (matching option names case-insensitively). A board without those fields
still gets the items; field setting is skipped rather than failing.
"""

from collections.abc import Sequence
from typing import Any, Final

from codekavach.integrations.github.transport import GitHubClient, GitHubError

_PROJECT_QUERY: Final = """
query($owner: String!, $number: Int!) {
  %s(login: $owner) {
    projectV2(number: $number) {
      id
      fields(first: 50) {
        nodes { ... on ProjectV2SingleSelectField { id name options { id name } } }
      }
    }
  }
}"""
_ADD: Final = """
mutation($project: ID!, $content: ID!) {
  addProjectV2ItemById(input: {projectId: $project, contentId: $content}) { item { id } }
}"""
_SET: Final = """
mutation($project: ID!, $item: ID!, $field: ID!, $option: String!) {
  updateProjectV2ItemFieldValue(input: {projectId: $project, itemId: $item, fieldId: $field,
    value: {singleSelectOptionId: $option}}) { projectV2Item { id } }
}"""


def load_board(client: GitHubClient, owner: str, number: int) -> dict[str, Any]:
    """The board id and its single-select fields; tries an organisation, then a user."""
    for kind in ("organization", "user"):
        try:
            data = client.graphql(_PROJECT_QUERY % kind, {"owner": owner, "number": number})
        except GitHubError:
            continue
        project = (data.get(kind) or {}).get("projectV2")
        if project:
            fields = {
                n["name"].lower(): n for n in project["fields"]["nodes"] if n and n.get("name")
            }
            return {"id": project["id"], "fields": fields}
    raise GitHubError(f"project {number} of {owner} was not found or is not readable")


def _option(board: dict[str, Any], field: str, value: str) -> tuple[str, str] | None:
    node = board["fields"].get(field)
    if not node:
        return None
    for option in node.get("options", ()):
        if option["name"].lower() == value.lower():
            return node["id"], option["id"]
    return None


def sync_board(
    client: GitHubClient, owner: str, number: int, items: Sequence[dict[str, Any]]
) -> dict[str, int]:
    """Add each ``{node_id, severity}`` issue to the board and set Status and Severity."""
    board = load_board(client, owner, number)
    added = fields_set = 0
    for item in items:
        if not item.get("node_id"):
            continue
        data = client.graphql(_ADD, {"project": board["id"], "content": item["node_id"]})
        item_id = data["addProjectV2ItemById"]["item"]["id"]
        added += 1
        for field, value in (("status", "Todo"), ("severity", item.get("severity", ""))):
            picked = _option(board, field, value)
            if picked:
                client.graphql(
                    _SET,
                    {
                        "project": board["id"],
                        "item": item_id,
                        "field": picked[0],
                        "option": picked[1],
                    },
                )
                fields_set += 1
    return {"added": added, "fields_set": fields_set}
