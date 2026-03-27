"""Attack Surface Graph — models and builder for deep intelligence mode."""
from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class AssetNode:
    """Represents a domain/subdomain."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    domain: str = ""
    ip: str = ""
    technologies: list[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class EndpointNode:
    """Represents a URL endpoint."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    url: str = ""
    method: str = "GET"
    asset_id: str = ""
    parameters: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class ParameterNode:
    """Represents an injectable parameter."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    type: str = "query"
    endpoint_id: str = ""
    injectable: bool = False
    finding_ids: list[str] = field(default_factory=list)


@dataclass
class VulnNode:
    """Represents a vulnerability in the graph."""
    id: str = ""
    vuln_type: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    endpoint_id: str = ""
    parameter_id: str = ""
    related_cve_ids: list[str] = field(default_factory=list)
    is_entry_point: bool = False


@dataclass
class AttackSurfaceGraph:
    """The complete attack surface graph."""
    assets: list[AssetNode] = field(default_factory=list)
    endpoints: list[EndpointNode] = field(default_factory=list)
    parameters: list[ParameterNode] = field(default_factory=list)
    vulnerabilities: list[VulnNode] = field(default_factory=list)

    def get_riskiest_endpoints(self, top_n: int = 5) -> list[EndpointNode]:
        return sorted(self.endpoints,
                      key=lambda e: len(e.finding_ids), reverse=True)[:top_n]

    def get_entry_points(self) -> list[VulnNode]:
        return [v for v in self.vulnerabilities if v.is_entry_point]

    def get_vulns_for_endpoint(self, endpoint_id: str) -> list[VulnNode]:
        return [v for v in self.vulnerabilities if v.endpoint_id == endpoint_id]

    def get_technology_risks(self) -> dict[str, list[str]]:
        tech_cves: dict[str, list[str]] = defaultdict(list)
        for v in self.vulnerabilities:
            for cve in v.related_cve_ids:
                for ep in self.endpoints:
                    if ep.id == v.endpoint_id:
                        for asset in self.assets:
                            if asset.id == ep.asset_id:
                                for tech in asset.technologies:
                                    tech_cves[tech].append(cve)
        return dict(tech_cves)

    def calculate_risk_scores(self) -> None:
        for ep in self.endpoints:
            vulns = self.get_vulns_for_endpoint(ep.id)
            if vulns:
                ep.risk_score = sum(v.cvss_score for v in vulns)

        for asset in self.assets:
            asset_endpoints = [e for e in self.endpoints if e.asset_id == asset.id]
            if asset_endpoints:
                asset.risk_score = sum(e.risk_score for e in asset_endpoints)

    def to_dict(self) -> dict:
        return {
            "assets": [vars(a) for a in self.assets],
            "endpoints": [vars(e) for e in self.endpoints],
            "parameters": [vars(p) for p in self.parameters],
            "vulnerabilities": [vars(v) for v in self.vulnerabilities],
            "summary": {
                "total_assets": len(self.assets),
                "total_endpoints": len(self.endpoints),
                "total_parameters": len(self.parameters),
                "total_vulnerabilities": len(self.vulnerabilities),
                "riskiest_endpoints": [
                    {"url": e.url, "risk_score": e.risk_score, "vuln_count": len(e.finding_ids)}
                    for e in self.get_riskiest_endpoints(5)
                ],
                "entry_points": [
                    {"id": v.id, "type": v.vuln_type, "endpoint": v.endpoint_id}
                    for v in self.get_entry_points()
                ],
            },
        }


def _is_entry_point(vuln: dict) -> bool:
    vuln_type = vuln.get("vulnerability_type", "")
    return vuln_type in (
        "xss", "xss_stored", "xss_reflected",
        "sqli", "time_based_sqli",
        "cmdi", "time_based_cmdi",
        "ssrf", "open_redirect",
        "lfi", "path_traversal",
    )


def build_attack_surface_graph(
    scan_result: dict,
    analyzed_vulnerabilities: list[dict],
    cve_records: list[dict] | None = None,
) -> AttackSurfaceGraph:
    graph = AttackSurfaceGraph()

    # 1. Build Asset nodes
    discovery = scan_result.get("discovery") or {}
    domain = discovery.get("domain") or scan_result.get("target", "")
    subdomains = discovery.get("subdomains") or []
    technologies = discovery.get("technologies") or []

    all_domains = [domain] + subdomains if domain else subdomains
    if not all_domains:
        all_domains = [scan_result.get("target", "unknown")]

    for d in all_domains:
        asset = AssetNode(domain=d, technologies=technologies if d == domain else [])
        graph.assets.append(asset)

    default_asset_id = graph.assets[0].id if graph.assets else ""

    # Also add endpoints from crawled_endpoints
    crawled = scan_result.get("crawled_endpoints") or []

    # 2. Build Endpoint nodes
    seen_endpoints: dict[str, EndpointNode] = {}

    for vuln in analyzed_vulnerabilities:
        ep_url = vuln.get("endpoint", "")
        ep_method = vuln.get("http_method", "GET")
        ep_key = f"{ep_method}:{ep_url}"
        if ep_key not in seen_endpoints:
            ep_node = EndpointNode(url=ep_url, method=ep_method, asset_id=default_asset_id)
            seen_endpoints[ep_key] = ep_node
            graph.endpoints.append(ep_node)

    for url in crawled:
        ep_key = f"GET:{url}"
        if ep_key not in seen_endpoints:
            ep_node = EndpointNode(url=url, method="GET", asset_id=default_asset_id)
            seen_endpoints[ep_key] = ep_node
            graph.endpoints.append(ep_node)

    # 3. Build Parameter nodes
    seen_params: set[str] = set()
    for vuln in analyzed_vulnerabilities:
        param_name = vuln.get("parameter", "")
        if not param_name or param_name == "—":
            continue
        ep_url = vuln.get("endpoint", "")
        ep_method = vuln.get("http_method", "GET")
        ep_node = seen_endpoints.get(f"{ep_method}:{ep_url}")
        if not ep_node:
            continue
        param_key = f"{ep_node.id}:{param_name}"
        if param_key in seen_params:
            continue
        seen_params.add(param_key)
        param_node = ParameterNode(name=param_name, endpoint_id=ep_node.id, injectable=True)
        graph.parameters.append(param_node)
        if param_name not in ep_node.parameters:
            ep_node.parameters.append(param_name)

    # 4. Build Vulnerability nodes
    for vuln in analyzed_vulnerabilities:
        ep_url = vuln.get("endpoint", "")
        ep_method = vuln.get("http_method", "GET")
        ep_node = seen_endpoints.get(f"{ep_method}:{ep_url}")

        param_name = vuln.get("parameter", "")
        param_node = next(
            (p for p in graph.parameters
             if p.name == param_name and ep_node and p.endpoint_id == ep_node.id),
            None,
        )

        vuln_node = VulnNode(
            id=vuln.get("finding_id", ""),
            vuln_type=vuln.get("vulnerability_type", ""),
            severity=vuln.get("severity", ""),
            cvss_score=float(vuln.get("cvss_score", 0.0)),
            cwe_id=vuln.get("cwe_id", vuln.get("cwe", "")),
            endpoint_id=ep_node.id if ep_node else "",
            parameter_id=param_node.id if param_node else "",
            related_cve_ids=vuln.get("related_cve_ids", []),
            is_entry_point=_is_entry_point(vuln),
        )
        graph.vulnerabilities.append(vuln_node)

        if ep_node:
            ep_node.finding_ids.append(vuln_node.id)
        if param_node:
            param_node.finding_ids.append(vuln_node.id)

    # 5. Calculate risk scores
    graph.calculate_risk_scores()

    return graph
