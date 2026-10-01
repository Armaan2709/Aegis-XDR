"""
Case Management Threaded Comments Submodule Logic.

Handles comment content validation, mention extraction, threaded comment nesting,
edit audit trail creation, and soft deletion handling.
"""

import re
import uuid
from typing import List, Dict, Any, Optional

from app.case_management.models import CaseComment


class CommentManager:
    """Business logic helper for case threaded comments."""

    @staticmethod
    def extract_mentions(content: str) -> List[str]:
        """Extract @mentions handles or UUIDs from markdown content."""
        pattern = r"@([a-zA-Z0-9_\-]+)"
        matches = re.findall(pattern, content)
        return list(dict.fromkeys(matches))  # Preserve order, unique items

    @staticmethod
    def build_threaded_tree(comments: List[CaseComment]) -> List[Dict[str, Any]]:
        """Organize flat list of case comments into a hierarchical threaded tree."""
        comment_dict: Dict[uuid.UUID, Dict[str, Any]] = {}
        roots: List[Dict[str, Any]] = []

        # Convert comments to dictionary representation with children list
        for comment in comments:
            item = {
                "id": comment.id,
                "case_id": comment.case_id,
                "author_id": comment.author_id,
                "author_name": comment.author_name,
                "content": comment.content if not comment.is_deleted else "[Comment deleted]",
                "parent_id": comment.parent_id,
                "mentions": comment.mentions,
                "edit_history": comment.edit_history,
                "is_deleted": comment.is_deleted,
                "deleted_at": comment.deleted_at,
                "deleted_by_id": comment.deleted_by_id,
                "created_at": comment.created_at,
                "updated_at": comment.updated_at,
                "replies": [],
            }
            comment_dict[comment.id] = item

        # Build hierarchy
        for comment in comments:
            item = comment_dict[comment.id]
            if comment.parent_id and comment.parent_id in comment_dict:
                comment_dict[comment.parent_id]["replies"].append(item)
            else:
                roots.append(item)

        return roots
