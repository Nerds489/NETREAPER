# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared pytest fixtures."""
from __future__ import annotations

import pytest


@pytest.fixture
def temp_dir(tmp_path):
    """A throwaway directory for file-writing tests."""
    return tmp_path


@pytest.fixture
def sample_session_data():
    """A representative session payload for exporter tests."""
    return {
        "session": {
            "id": "session_001",
            "name": "test engagement",
            "created_at": "2026-09-11T10:00:00",
            "completed_at": "2026-09-11T11:30:00",
            "status": "completed",
        },
        "targets": [{"value": "192.168.1.10", "type": "ip"}],
        "tool_executions": [
            {"tool_name": "nmap", "exit_code": 0, "duration": 3},
        ],
        "loot": [],
        "findings": [],
    }
