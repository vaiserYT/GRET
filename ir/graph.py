"""ResourceGraph — backward-compatible wrapper for SemanticReferenceGraph.

The old ResourceGraph with four separate nx.DiGraph instances is replaced
by a SINGLE unified SemanticReferenceGraph. This module re-exports the
new class under the old name for backward compatibility.

Everything queries ONE graph now.
"""
from __future__ import annotations

from ir.semantic_graph import SemanticReferenceGraph as ResourceGraph
from ir.semantic_graph import (
    SemanticReferenceGraph,
    SuspiciousItem,
    TraceNode,
    CONTAINS, IS_INSTANCE_OF, USES_SPRITE, INHERITS, PLACED_IN,
    CALLS, CALLS_FUNCTION, CREATES, DESTROYS,
    READS_FLAG, WRITES_FLAG, REFERENCES, REFERENCES_SPRITE,
    REFERENCES_SOUND, REFERENCES_VAR, REFERENCES_OBJ,
    CONNECTED_TO, HAS_EVENT, HAS_CREATION_CODE,
    WITH_REF, ASSET_GET_REF, COLLISION_REF, OWNS, ENTRY_POINT,
    NT_OBJECT, NT_ROOM, NT_SPRITE, NT_SOUND, NT_CODE,
    NT_FUNCTION, NT_SCRIPT, NT_VARIABLE, NT_STRING, NT_FLAG,
    NT_INSTANCE, NT_TIMELINE, NT_PATH, NT_FONT, NT_SHADER,
    NT_SEQUENCE, NT_BACKGROUND,
)

__all__ = [
    "ResourceGraph",
    "SemanticReferenceGraph",
    "SuspiciousItem",
    "TraceNode",
    "CONTAINS", "IS_INSTANCE_OF", "USES_SPRITE", "INHERITS", "PLACED_IN",
    "CALLS", "CALLS_FUNCTION", "CREATES", "DESTROYS",
    "READS_FLAG", "WRITES_FLAG", "REFERENCES", "REFERENCES_SPRITE",
    "REFERENCES_SOUND", "REFERENCES_VAR", "REFERENCES_OBJ",
    "CONNECTED_TO", "HAS_EVENT", "HAS_CREATION_CODE",
    "WITH_REF", "ASSET_GET_REF", "COLLISION_REF", "OWNS", "ENTRY_POINT",
    "NT_OBJECT", "NT_ROOM", "NT_SPRITE", "NT_SOUND", "NT_CODE",
    "NT_FUNCTION", "NT_SCRIPT", "NT_VARIABLE", "NT_STRING", "NT_FLAG",
    "NT_INSTANCE", "NT_TIMELINE", "NT_PATH", "NT_FONT", "NT_SHADER",
    "NT_SEQUENCE", "NT_BACKGROUND",
]
