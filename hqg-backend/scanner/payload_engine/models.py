from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class InjectionRequest:
    endpoint: str
    vulnerability_type: str
    payload: str
    url: str
    method: str
    params: dict[str, str]
    json_body: dict[str, str] | None
    form_data: dict[str, str] | None
    headers: dict[str, str] | None
    parameter: str = ""  # name of the injected parameter


@dataclass(slots=True)
class InjectionResult:
    endpoint: str
    vulnerability_type: str
    payload: str
    response_code: int | None
    response_time: float
    response_body: str = ""
    response_length: int = 0
    error: str | None = None
    parameter: str = ""  # name of the injected parameter

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "vulnerability_type": self.vulnerability_type,
            "payload": self.payload,
            "parameter": self.parameter,
            "response_code": self.response_code,
            "response_time": self.response_time,
            "response_body": self.response_body,
            "response_length": self.response_length,
            "error": self.error,
        }
