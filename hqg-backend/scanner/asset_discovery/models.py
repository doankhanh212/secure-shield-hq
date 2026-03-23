from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class DNSResolution:
    host: str
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)

    @property
    def ips(self) -> list[str]:
        return [*self.a, *self.aaaa]


@dataclass(slots=True)
class ServiceProbeResult:
    host: str
    scheme: str
    url: str
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    server_banner: str | None = None
    body_snippet: str = ""
    error: str | None = None


@dataclass(slots=True)
class AssetDiscoveryOutput:
    domain: str
    subdomains: list[str]
    ips: list[str]
    services: list[str]
    technologies: list[str]
    dns_records: dict[str, DNSResolution]
    service_details: list[ServiceProbeResult]

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "ips": self.ips,
            "services": self.services,
            "technologies": self.technologies,
            "dns_records": {
                host: {
                    "A": record.a,
                    "AAAA": record.aaaa,
                    "CNAME": record.cname,
                    "MX": record.mx,
                    "TXT": record.txt,
                    "NS": record.ns,
                }
                for host, record in self.dns_records.items()
            },
            "service_details": [
                {
                    "host": result.host,
                    "scheme": result.scheme,
                    "url": result.url,
                    "status_code": result.status_code,
                    "headers": result.headers,
                    "server_banner": result.server_banner,
                    "error": result.error,
                }
                for result in self.service_details
            ],
        }
