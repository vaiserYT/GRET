"""Comprehensive validation suite for resolver, graph, and chunks.

Usage:
    from ir.validate import validate_all
    issues = validate_all(game)
"""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

from code.opcodes import is_call


# ─────────────────────────────────────────────
# Result helpers
# ─────────────────────────────────────────────

class ValidationIssue:
    def __init__(self, severity: str, category: str, message: str,
                 source: str = "", details: Optional[dict] = None):
        self.severity = severity       # "error" | "warning" | "info"
        self.category = category       # e.g. "ownership", "reference", "graph"
        self.message = message
        self.source = source           # human-readable label
        self.details = details or {}

    def __repr__(self) -> str:
        return f"[{self.severity.upper()}] {self.category}: {self.message}"

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "source": self.source,
            "details": self.details,
        }


def _code_label(game, cid: int, resolver) -> str:
    owner = resolver.owner_of(cid) if resolver else None
    entry = game.code_entries.get(cid)
    name = entry.name if entry else f"CODE[{cid}]"
    return f"{name} (owned by {owner})" if owner else name


# ─────────────────────────────────────────────
# Chunk validation
# ─────────────────────────────────────────────

def validate_chunks(game) -> list[ValidationIssue]:
    """Validate raw chunk parsing integrity."""
    issues: list[ValidationIssue] = []

    obj_count = len(game.objects)
    issues.append(ValidationIssue("info", "chunk", f"Objects: {obj_count}"))
    dup_obj_names = _find_dup_names(game.objects)
    if dup_obj_names:
        issues.append(ValidationIssue("warning", "chunk",
            f"Duplicate object names: {len(dup_obj_names)} instances. "
            f"Sample: {dup_obj_names[:5]}"))

    room_count = len(game.rooms)
    issues.append(ValidationIssue("info", "chunk", f"Rooms: {room_count}"))
    dup_room_names = _find_dup_names(game.rooms)
    if dup_room_names:
        issues.append(ValidationIssue("warning", "chunk",
            f"Duplicate room names: {dup_room_names}"))

    code_count = len(game.code_entries)
    issues.append(ValidationIssue("info", "chunk", f"Code entries: {code_count}"))
    if not game.code_entries:
        issues.append(ValidationIssue("error", "chunk",
            "No CODE entries parsed — all subsequent validation meaningless"))
        return issues

    code_ids = sorted(game.code_entries.keys())
    expected = list(range(code_count))
    missing = sorted(set(expected) - set(code_ids))
    if missing:
        issues.append(ValidationIssue("warning", "chunk",
            f"Non-contiguous CODE entry IDs — missing: {missing[:20]}..."))

    func_count = len(game.functions)
    issues.append(ValidationIssue("info", "chunk",
        f"Functions (FUNC entries): {func_count}"))
    name_mismatches = 0
    for fname, func in game.functions.items():
        if fname != func.name:
            name_mismatches += 1
    if name_mismatches:
        issues.append(ValidationIssue("warning", "chunk",
            f"Function name mismatches (key != def.name): {name_mismatches}"))

    issues.append(ValidationIssue("info", "chunk",
        f"Sprites: {len(game.sprites)}"))
    issues.append(ValidationIssue("info", "chunk",
        f"Sounds: {len(game.sounds)}"))
    str_count = len(game.strings)
    issues.append(ValidationIssue("info", "chunk",
        f"Strings: {str_count}"))

    return issues


def _find_dup_names(resources: dict) -> list[str]:
    seen: dict[str, int] = {}
    for r in resources.values():
        name = getattr(r, "name", "")
        if name:
            seen[name] = seen.get(name, 0) + 1
    return [n for n, c in seen.items() if c > 1]


# ─────────────────────────────────────────────
# Object validation
# ─────────────────────────────────────────────

def validate_objects(game, resolver) -> list[ValidationIssue]:
    """Validate object cross-references."""
    issues: list[ValidationIssue] = []
    if not game.objects:
        issues.append(ValidationIssue("warning", "object",
            "No objects loaded"))
        return issues

    # Check all objects have valid sprite indices
    for obj_id, obj in game.objects.items():
        # Sprite
        if obj.sprite_index >= 0:
            spr = game.sprite_by_id(obj.sprite_index)
            if spr is None:
                issues.append(ValidationIssue("error", "object",
                    f"Sprite index {obj.sprite_index} not found",
                    source=obj.name))
            elif resolver and resolver.object_sprite.get(obj_id) is None:
                issues.append(ValidationIssue("warning", "object",
                    f"Sprite index {obj.sprite_index}='{spr.name}' not in resolver's sprite_users",
                    source=obj.name))

        # Mask
        if obj.mask_index >= 0:
            mask = game.sprite_by_id(obj.mask_index)
            if mask is None:
                issues.append(ValidationIssue("error", "object",
                    f"Mask index {obj.mask_index} not found",
                    source=obj.name))

        # Parent
        if obj.parent_index >= 0:
            parent = game.object_by_id(obj.parent_index)
            if parent is None:
                issues.append(ValidationIssue("error", "object",
                    f"Parent index {obj.parent_index} not found",
                    source=obj.name))
            elif resolver and resolver.object_parent.get(obj_id) is None:
                issues.append(ValidationIssue("warning", "object",
                    f"Parent index {obj.parent_index}='{parent.name}' not in resolver.parents",
                    source=obj.name))

        # Events — check code_id refers to valid code
        for ev in obj.events:
            code_id = ev.code_id
            if code_id >= 0:
                code_entry = game.code_entries.get(code_id)
                if code_entry is None:
                    issues.append(ValidationIssue("warning", "object",
                        f"Object '{obj.name}' event[{ev.event_type}]({ev.subtype}) "
                        f"code_id={code_id} not found in CODE entries"))
                elif code_entry.name and obj.name in code_entry.name:
                    pass  # Expected: name contains object name

    return issues


# ─────────────────────────────────────────────
# Room validation
# ─────────────────────────────────────────────

def validate_rooms(game, resolver) -> list[ValidationIssue]:
    """Validate room cross-references."""
    issues: list[ValidationIssue] = []

    if not game.rooms:
        issues.append(ValidationIssue("warning", "room",
            "No rooms loaded"))
        return issues

    # Track unique error types for summary
    missing_cc_ids: set[int] = set()
    zero_instance_rooms = 0

    for room_id, room in game.rooms.items():
        if room.creation_code_id >= 0:
            if room.creation_code_id not in game.code_entries:
                missing_cc_ids.add(room.creation_code_id)

        total_instances = len(room.instances) + sum(len(l.instances) for l in room.layers)
        if total_instances == 0:
            zero_instance_rooms += 1

    if missing_cc_ids:
        issues.append(ValidationIssue("error", "room",
            f"{len(missing_cc_ids)} unique creation_code_ids not in code_entries: "
            f"{sorted(missing_cc_ids)} — GMS2.3 uses different encoding"))
    if zero_instance_rooms:
        issues.append(ValidationIssue("warning", "room",
            f"{zero_instance_rooms}/{len(game.rooms)} rooms have zero instances parsed "
            f"(GMS2.3 layer format — instances stored in layers, not top-level)"))

        # Check instance object references
        for inst in room.instances:
            obj = game.object_by_id(inst.object_id)
            if obj is None:
                issues.append(ValidationIssue("error", "room",
                    f"Instance references object_id={inst.object_id} not found",
                    source=room.name))
            if inst.creation_code_id >= 0:
                if inst.creation_code_id not in game.code_entries:
                    issues.append(ValidationIssue("error", "room",
                        f"Instance creation_code_id={inst.creation_code_id} not in code_entries",
                        source=room.name))

        # Check layer instance references
        for layer in room.layers:
            for inst in layer.instances:
                obj = game.object_by_id(inst.object_id)
                if obj is None:
                    issues.append(ValidationIssue("error", "room",
                        f"Layer instance references object_id={inst.object_id} not found",
                        source=f"{room.name}/layer:{layer.name}"))

    return issues


# ─────────────────────────────────────────────
# Code ownership validation
# ─────────────────────────────────────────────

def validate_code_ownership(game, resolver) -> list[ValidationIssue]:
    """Validate every CODE entry has an owner, and every owner is plausible."""
    issues: list[ValidationIssue] = []

    code_count = len(game.code_entries)
    owned_count = len(resolver.code_entry_owner) if resolver else 0
    if owned_count != code_count:
        issues.append(ValidationIssue("error", "ownership",
            f"Owned {owned_count}/{code_count} CODE entries — expected {code_count}"))

    # Check: every code entry has exactly one owner
    if resolver:
        for cid in game.code_entries:
            if cid not in resolver.code_owner:
                issues.append(ValidationIssue("error", "ownership",
                    f"CODE[{cid}] has no owner"))
            owner_type = resolver.owner_type.get(cid, -1)
            if owner_type == -1:
                issues.append(ValidationIssue("warning", "ownership",
                    f"CODE[{cid}] = '{game.code_entries[cid].name}' is unknown type",
                    source=f"CODE[{cid}]"))

    # Check: function (FUNC) code_off maps to a valid CODE entry
    for fname, func in game.functions.items():
        if func.code_offset >= 0:
            # code_offset is a file offset — find which CODE entry contains it
            found = None
            for cid, entry in game.code_entries.items():
                blob_end = entry.offset + entry.length
                if entry.offset <= func.code_offset < blob_end:
                    found = cid
                    break
            if found is None:
                issues.append(ValidationIssue("warning", "ownership",
                    f"Function '{fname}' code_offset=0x{func.code_offset:x} not within any CODE entry",
                    source=func.name))

            # Check: function code_id matches
            if func.code_id >= 0 and func.code_id != found:
                # code_id might be different from found — report but don't error
                if found is not None:
                    actual_name = game.code_entries[found].name if found in game.code_entries else "?"
                    issues.append(ValidationIssue("info", "ownership",
                        f"Function '{fname}' code_id={func.code_id} but bytecode at 0x{func.code_offset:x} "
                        f"is in CODE[{found}]='{actual_name}'",
                        source=func.name))

    # Check: OBJT event code_ids map to actual CODE entries
    bad_event_refs = 0
    good_event_refs = 0
    for obj_id, obj in game.objects.items():
        for ev in obj.events:
            if 0 <= ev.code_id < code_count:
                code = game.code_entries.get(ev.code_id)
                if code and code.name:
                    good_event_refs += 1
                else:
                    bad_event_refs += 1
            elif ev.code_id >= code_count:
                bad_event_refs += 1
    if bad_event_refs:
        issues.append(ValidationIssue("warning", "ownership",
            f"{bad_event_refs} event code_ids don't map to CODE entries "
            f"(of {good_event_refs + bad_event_refs} total event refs)"))
    if good_event_refs:
        issues.append(ValidationIssue("info", "ownership",
            f"{good_event_refs} event code_ids map to valid CODE entries"))

    return issues


# ─────────────────────────────────────────────
# Call graph validation
# ─────────────────────────────────────────────

def validate_call_graph(game, resolver) -> list[ValidationIssue]:
    """Validate call graph integrity."""
    issues: list[ValidationIssue] = []

    code_count = len(game.code_entries)

    # Check all callee references
    broken_refs = 0
    for caller_id, callees in resolver.callees.items():
        for callee_id in callees:
            if callee_id not in game.code_entries:
                broken_refs += 1
                owner = resolver.owner_of(caller_id)
                issues.append(ValidationIssue("error", "callgraph",
                    f"Call target CODE[{callee_id}] not found",
                    source=f"CODE[{caller_id}] ({owner or '?'})"))

    if broken_refs == 0:
        issues.append(ValidationIssue("info", "callgraph",
            f"All {sum(len(c) for c in resolver.callees.values())} call edges point to valid targets"))

    # Built-in calls count
    builtin_count = sum(len(v) for v in resolver.builtin_calls.values())
    issues.append(ValidationIssue("info", "callgraph",
        f"Built-in calls: {builtin_count}"))

    # Check: all CODE entries referenced as targets are actually called
    called = set(resolver.callers.keys())
    uncalled = set(game.code_entries.keys()) - called
    if uncalled:
        # Show sample
        sample = sorted(uncalled)[:10]
        sample_info = [(cid, game.code_entries[cid].name) for cid in sample]
        issues.append(ValidationIssue("info", "callgraph",
            f"{len(uncalled)} CODE entries are never called (leaf/dead code). "
            f"Sample: {[(cid, n) for cid, n in sample_info[:5]]}"))

    # Check: orphan CODE entries (no owner and no callers)
    if resolver:
        orphaned = set(game.code_entries.keys()) - set(resolver.callers.keys()) - set(resolver.callees.keys())
        if orphaned:
            issues.append(ValidationIssue("info", "callgraph",
                f"{len(orphaned)} CODE entries have no calls in or out"))

    return issues


# ─────────────────────────────────────────────
# Graph consistency validation
# ─────────────────────────────────────────────

def validate_graphs(game, rgraph, resolver) -> list[ValidationIssue]:
    """Validate graph builder consistency vs resolver data."""
    issues: list[ValidationIssue] = []

    if rgraph is None:
        issues.append(ValidationIssue("error", "graph",
            "No graph built — call ResourceGraph.build_all() first"))
        return issues

    # Room graph
    rg = rgraph.room
    resolver_room_edges = resolver.room_transitions
    target_rooms_in_graph = set()
    for code_id, trans_type, target_id in resolver_room_edges:
        if target_id is not None and target_id in game.rooms:
            target_rooms_in_graph.add(target_id)

    if resolver_room_edges and not target_rooms_in_graph:
        issues.append(ValidationIssue("error", "graph",
            "Resolver found room transitions but none target a valid room"))
    elif resolver_room_edges:
        edge_count = rg.number_of_edges()
        if edge_count < len(target_rooms_in_graph):
            issues.append(ValidationIssue("warning", "graph",
                f"Room graph has {edge_count} edges but resolver found "
                f"{len(target_rooms_in_graph)} unique target rooms"))

    # Call graph
    cg = rgraph.call
    resolver_edge_count = sum(len(c) for c in resolver.callees.values())
    graph_edge_count = cg.number_of_edges()
    if resolver_edge_count != graph_edge_count:
        issues.append(ValidationIssue("warning", "graph",
            f"Call graph mismatch: resolver has {resolver_edge_count} edges, "
            f"graph has {graph_edge_count}"))

    graph_node_count = cg.number_of_nodes()
    if graph_node_count < len(game.code_entries):
        diff = len(game.code_entries) - graph_node_count
        issues.append(ValidationIssue("warning", "graph",
            f"Call graph is missing {diff} CODE entry nodes"))

    # Object graph
    og = rgraph.object
    issues.append(ValidationIssue("info", "graph",
        f"Object graph: {og.number_of_nodes()} nodes, {og.number_of_edges()} edges"))

    # Flag graph
    fg = rgraph.flag
    issues.append(ValidationIssue("info", "graph",
        f"Flag graph: {fg.number_of_nodes()} nodes, {fg.number_of_edges()} edges"))

    return issues


# ─────────────────────────────────────────────
# String reference validation
# ─────────────────────────────────────────────

def validate_strings(game, resolver) -> list[ValidationIssue]:
    """Validate string reference integrity."""
    issues: list[ValidationIssue] = []

    str_count = len(game.strings)

    # Check string refs for out-of-range IDs
    invalid_str_refs = sum(1 for sid in resolver.string_refs if sid < 0 or sid >= str_count)
    for str_id in sorted(resolver.string_refs.keys()):
        if str_id < 0 or str_id >= str_count:
            sample = resolver.string_refs[str_id][:3]
            issues.append(ValidationIssue("info", "string",
                f"String ID {str_id} out of range [0, {str_count}) — "
                f"likely encoded/named reference, not a string ID",
                source=f"referenced by CODE{sample[:3]}"))
    valid_refs = {sid: cids for sid, cids in resolver.string_refs.items() if 0 <= sid < str_count}
    total_valid_refs = sum(len(v) for v in valid_refs.values())
    issues.append(ValidationIssue("info", "string",
        f"{total_valid_refs} valid string refs, {invalid_str_refs} OOB (encoded/named) refs"))

    # Unreferenced strings
    referenced = set(valid_refs.keys())
    all_str_count = len(game.strings)
    unreferenced = all_str_count - len(referenced)
    if unreferenced:
        issues.append(ValidationIssue("info", "string",
            f"{unreferenced}/{all_str_count} strings are unreferenced by any code"))

    return issues


# ─────────────────────────────────────────────
# Sprite/sound usage validation
# ─────────────────────────────────────────────

def validate_resource_usage(game, resolver) -> list[ValidationIssue]:
    """Validate sprite and sound usage references."""
    issues: list[ValidationIssue] = []

    # Sprite users
    for spr_id, objects in resolver.sprite_users.items():
        if spr_id not in game.sprites:
            issues.append(ValidationIssue("error", "resource",
                f"Sprite ID {spr_id} referenced by {len(objects)} objects but not in sprites dict"))

    # Objects without sprites
    obj_without_sprite = []
    for obj_id, obj in game.objects.items():
        if obj.sprite_index < 0:
            obj_without_sprite.append(obj.name)
    if obj_without_sprite:
        # Only report as warning — some objects legitimately have no sprite
        issues.append(ValidationIssue("info", "resource",
            f"{len(obj_without_sprite)} objects have no sprite assigned: "
            f"{obj_without_sprite[:10]}..."))

    return issues


# ─────────────────────────────────────────────
# Flag validation
# ─────────────────────────────────────────────

def validate_flags(game, resolver) -> list[ValidationIssue]:
    """Validate flag read/write indexes."""
    issues: list[ValidationIssue] = []

    all_write_flags = set(resolver.flag_writes.keys())
    all_read_flags = set(resolver.flag_reads.keys())
    read_only = all_read_flags - all_write_flags
    if read_only:
        sample = sorted(read_only)[:20]
        issues.append(ValidationIssue("warning", "flag",
            f"{len(read_only)} flags are only read, never written. "
            f"Sample: {sample}"))

    total_flag_reads = sum(len(v) for v in resolver.flag_reads.values())
    total_flag_writes = sum(len(v) for v in resolver.flag_writes.values())
    issues.append(ValidationIssue("info", "flag",
        f"Flag refs: {total_flag_reads} reads, {total_flag_writes} writes across "
        f"{len(all_write_flags | all_read_flags)} unique flags"))

    return issues


# ─────────────────────────────────────────────
# Main validation entry point
# ─────────────────────────────────────────────

def validate_all(game) -> dict[str, list[ValidationIssue]]:
    """Run all validators and return categorized results."""
    resolver = getattr(game, 'resolver', None)
    rgraph = getattr(game, 'rgraph', None)

    results: dict[str, list[ValidationIssue]] = {
        "chunks": [],
        "objects": [],
        "rooms": [],
        "ownership": [],
        "callgraph": [],
        "graphs": [],
        "strings": [],
        "resources": [],
        "flags": [],
    }

    # Run validators
    results["chunks"] = validate_chunks(game)
    if resolver:
        results["objects"] = validate_objects(game, resolver)
        results["rooms"] = validate_rooms(game, resolver)
        results["ownership"] = validate_code_ownership(game, resolver)
        results["callgraph"] = validate_call_graph(game, resolver)
        results["strings"] = validate_strings(game, resolver)
        results["resources"] = validate_resource_usage(game, resolver)
        results["flags"] = validate_flags(game, resolver)
        if rgraph:
            results["graphs"] = validate_graphs(game, rgraph, resolver)
    else:
        results["objects"].append(ValidationIssue("error", "general",
            "No resolver — call resolver.build(game) first"))
        results["rooms"].append(ValidationIssue("error", "general",
            "No resolver — call resolver.build(game) first"))

    return results


def print_validation_results(results: dict[str, list[ValidationIssue]],
                              show_info: bool = False) -> None:
    """Print validation results grouped by category."""
    total_errors = 0
    total_warnings = 0
    total_info = 0

    for category, issues in results.items():
        errors = [i for i in issues if i.severity == "error"]
        warnings = [i for i in issues if i.severity == "warning"]
        infos = [i for i in issues if i.severity == "info"]
        total_errors += len(errors)
        total_warnings += len(warnings)
        total_info += len(infos)

        if not issues:
            continue

        print(f"\n  [{category.upper()}]")
        if show_info:
            for i in infos:
                print(f"    INFO: {i.message}")
        for i in warnings:
            print(f"    WARN: {i.message}")
        for i in errors:
            print(f"    ERROR: {i.message}")

    print(f"\n  SUMMARY: {total_errors} errors, {total_warnings} warnings, "
          f"{total_info} info items")
