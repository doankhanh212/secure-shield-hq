from __future__ import annotations

from fastapi import APIRouter

from backend.api.routes.assets import (
    DomainCreate,
    create_asset,
    delete_asset,
    domain_report,
    list_assets,
)

router = APIRouter(prefix="/domains", tags=["domains"])


@router.get("", summary="List all domains")
async def list_domains() -> list[dict[str, object]]:
    return await list_assets()


@router.post("", status_code=201, summary="Add a domain manually")
async def create_domain(body: DomainCreate) -> dict[str, object]:
    return await create_asset(body)


@router.delete("/{domain_id}", summary="Delete a domain")
async def delete_domain(domain_id: str) -> dict[str, str]:
    return await delete_asset(domain_id)


@router.get(
    "/{domain_id}/report",
    summary="Download a domain-scoped report excluding false positives",
)
async def get_domain_report(domain_id: str, format: str = "html") -> object:  # noqa: A002
    return await domain_report(domain_id=domain_id, format=format)

