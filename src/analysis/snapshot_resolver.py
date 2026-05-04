from __future__ import annotations
"""Lazy snapshot resolution for threat generation.

Each heuristic materializer declares the graph-derived views it needs. This
resolver loads those views on demand and caches them for the duration of a
single threat-generation run.
"""

from collections.abc import Mapping
from typing import Any, Callable, Iterator

from graph.graph_queries import GraphQueries

SnapshotRows = list[dict[str, Any]]
SnapshotFetcher = Callable[[GraphQueries], SnapshotRows]


SNAPSHOT_FETCHERS: dict[str, SnapshotFetcher] = {
    "internet_modules": lambda queries: queries.internet_exposed_modules(),
    "sensitive_workflows": lambda queries: queries.workflows_involving_sensitive_data(),
    "attack_paths": lambda queries: queries.low_to_high_trust_attack_paths(),
    "high_priv_modules": lambda queries: queries.high_privilege_externally_reachable_modules(),
    "ai_dependencies": lambda queries: queries.modules_depending_on_ai_services(),
    "critical_workflows": lambda queries: queries.risks_targeting_critical_workflows_view(),
    "regulated_data": lambda queries: queries.threats_affecting_regulated_data_view(),
    "dependency_edges": lambda queries: queries.dependency_edges(),
    "trust_boundaries": lambda queries: queries.trust_boundary_crossings(),
    "boundary_objects": lambda queries: queries.high_value_objects_crossing_boundaries(),
    "unverified_actor_workflows": lambda queries: queries.unverified_actor_workflows(),
    "sensitive_writes": lambda queries: queries.module_writes_to_sensitive_datastore(),
    "exposed_fan_out": lambda queries: queries.exposed_module_fan_out(),
    "privilege_escalation": lambda queries: queries.privilege_escalation_dependencies(),
    "cross_domain_stores": lambda queries: queries.cross_domain_datastore_access(),
    "workflow_module_concentration": lambda queries: queries.workflow_module_concentration(),
    "regulated_ai_data": lambda queries: queries.regulated_ai_data(),
    "transitive_priv_escalation": lambda queries: queries.transitive_privilege_escalation(),
    "actor_privileged_modules": lambda queries: queries.actor_to_privileged_module(),
    "cross_trust_writes": lambda queries: queries.cross_trust_write_access(),
    "credential_low_trust": lambda queries: queries.credential_in_low_trust_workflow(),
    "high_fan_in": lambda queries: queries.high_fan_in_targets(),
    "workflow_trust_span": lambda queries: queries.workflow_trust_span(),
    "actor_regulated_access": lambda queries: queries.actor_regulated_data_access(),
    "untrusted_ai_store": lambda queries: queries.untrusted_ai_datastore_access(),
    "multi_domain_chain": lambda queries: queries.multi_domain_dependency_chain(),
    "exposed_transitive_stores": lambda queries: queries.exposed_transitive_datastore_access(),
    "unauth_actor_modules": lambda queries: queries.unauthenticated_actor_modules(),
    "unencrypted_boundary": lambda queries: queries.unencrypted_boundary_flows(),
    "exposed_no_validation": lambda queries: queries.exposed_without_input_validation(),
    "exposed_no_rate_limit": lambda queries: queries.exposed_without_rate_limiting(),
    "critical_unlogged": lambda queries: queries.critical_workflow_unlogged_modules(),
    "unencrypted_sensitive_store": lambda queries: queries.unencrypted_sensitive_datastore_flow(),
    "bidirectional_boundary": lambda queries: queries.bidirectional_boundary_flows(),
    "api_across_boundary": lambda queries: queries.api_endpoints_across_boundary(),
    "unauth_chain_privileged": lambda queries: queries.unauthenticated_chain_to_privileged(),
    "mobile_edge_regulated": lambda queries: queries.mobile_edge_regulated_data(),
    "no_flow_enforcement": lambda queries: queries.boundary_without_flow_enforcement(),
    "no_access_control": lambda queries: queries.actor_workflow_without_access_control(),
    "no_boundary_protection": lambda queries: queries.boundary_without_protection_module(),
    "no_encryption_service": lambda queries: queries.sensitive_flow_without_encryption_service(),
    "no_auth_service": lambda queries: queries.actor_to_backend_without_auth_service(),
    "no_validation_service": lambda queries: queries.exposed_path_without_validation_service(),
    "no_audit_module": lambda queries: queries.critical_workflow_without_audit(),
    "no_encryption_at_rest": lambda queries: queries.classified_store_without_encryption_at_rest(),
    "no_change_control": lambda queries: queries.privileged_module_without_change_control(),
    "spof_no_contingency": lambda queries: queries.spof_without_contingency(),
}


class ThreatSnapshotResolver(Mapping[str, SnapshotRows]):
    """Lazy, cached resolver for graph-derived threat snapshot views."""

    def __init__(
        self,
        queries: GraphQueries,
        *,
        fetchers: dict[str, SnapshotFetcher] | None = None,
    ) -> None:
        """Create a resolver bound to graph queries and a snapshot-fetcher catalog."""
        self._queries = queries
        self._fetchers = fetchers or SNAPSHOT_FETCHERS
        self._cache: dict[str, SnapshotRows] = {}

    def __getitem__(self, key: str) -> SnapshotRows:
        """Resolve and cache a named snapshot view."""
        if key not in self._fetchers:
            raise KeyError(key)
        if key not in self._cache:
            self._cache[key] = self._fetchers[key](self._queries)
        return self._cache[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._cache)

    def __len__(self) -> int:
        return len(self._cache)

    def get(self, key: str, default: SnapshotRows | None = None) -> SnapshotRows | None:
        """Return a resolved view without raising for unknown keys."""
        if key not in self._fetchers:
            return default
        return self[key]

    def preload(self, keys: tuple[str, ...] | list[str] | set[str]) -> None:
        """Warm the cache for a materializer's declared dependencies."""
        for key in keys:
            self[key]

    def resolved_keys(self) -> tuple[str, ...]:
        """Return the snapshot keys that were actually used in the current run."""
        return tuple(self._cache.keys())
