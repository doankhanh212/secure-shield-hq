from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class FormModel:
    action: str
    method: str
    fields: list[str] = field(default_factory=list)


@dataclass(slots=True)
class GraphQLEndpoint:
    url: str
    introspection_enabled: bool = False

    def to_dict(self) -> dict[str, object]:
        return {"url": self.url, "introspection_enabled": self.introspection_enabled}


@dataclass(slots=True)
class EndpointInfo:
    """A discovered injection point with full context for the injector."""
    url: str                       # normalized URL, values stripped: /product.php?id=
    parameters: list[str]          # query/form param names discovered here
    method: str                    # GET | POST
    source: str                    # html | form | js | force

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "parameters": self.parameters,
            "method": self.method,
            "source": self.source,
        }


@dataclass(slots=True)
class CrawlOutput:
    endpoints: list[str] = field(default_factory=list)
    endpoint_info: list[EndpointInfo] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    forms: list[FormModel] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    graphql_endpoints: list[GraphQLEndpoint] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoints": self.endpoints,
            "endpoint_info": [e.to_dict() for e in self.endpoint_info],
            "parameters": self.parameters,
            "forms": [
                {
                    "action": form.action,
                    "method": form.method,
                    "fields": form.fields,
                }
                for form in self.forms
            ],
            "api_endpoints": self.api_endpoints,
            "graphql_endpoints": [
                gql.to_dict() for gql in self.graphql_endpoints
            ],
        }
