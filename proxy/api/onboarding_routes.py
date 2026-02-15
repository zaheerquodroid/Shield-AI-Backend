"""Customer domain onboarding API endpoints.

Provides CRUD operations for automated customer domain onboarding:
- POST: Initiate onboarding (request ACM certificate)
- GET: Check onboarding status
- GET (list): List all onboardings for a customer
- DELETE: Offboard (remove tenant, delete certificate)
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException

from proxy.api.auth import require_api_key
from proxy.middleware.url_validator import validate_origin_url
from proxy.models.onboarding import (
    OnboardingCreate,
    OnboardingResponse,
    OnboardingStatus,
    OnboardingStatusResponse,
)
from proxy.store import postgres as pg_store
from proxy.store.postgres import StoreUnavailable
from proxy.store import onboarding as onboarding_store
from proxy.store.onboarding import DuplicateDomain

logger = structlog.get_logger()

router = APIRouter(
    prefix="/api/onboard",
    tags=["onboarding"],
    dependencies=[Depends(require_api_key)],
)

# Injected AWS clients (set during lifespan startup)
_acm_client: Any = None
_cloudfront_client: Any = None


def set_acm_client(client: Any) -> None:
    """Inject ACM client (called during app lifespan startup)."""
    global _acm_client
    _acm_client = client


def set_cloudfront_client(client: Any) -> None:
    """Inject CloudFront client (called during app lifespan startup)."""
    global _cloudfront_client
    _cloudfront_client = client


def _safe_cert_id(arn: str) -> str:
    """Extract only the certificate UUID from an ACM ARN for safe logging.

    Full ARNs contain AWS account IDs — only log the cert's unique suffix.
    """
    if not arn:
        return ""
    # ARN format: arn:aws:acm:region:account:certificate/uuid
    parts = arn.rsplit("/", 1)
    return parts[-1] if len(parts) == 2 else arn[:8] + "..."


def _build_status_response(record: dict) -> OnboardingStatusResponse:
    """Build a status response with required actions and next steps."""
    status = record.get("status", "")
    required_actions: list[str] = []
    next_steps: list[str] = []

    if status == OnboardingStatus.CERTIFICATE_PENDING:
        cname_name = record.get("validation_cname_name", "")
        cname_value = record.get("validation_cname_value", "")
        if cname_name and cname_value:
            required_actions.append(
                f"Add DNS CNAME record: {cname_name} → {cname_value}"
            )
        next_steps.append("Certificate will be validated automatically once DNS record is added")

    elif status == OnboardingStatus.CERTIFICATE_VALIDATED:
        next_steps.append("CloudFront distribution tenant is being created")

    elif status == OnboardingStatus.TENANT_CREATED:
        cf_cname = record.get("cloudfront_cname", "")
        domain = record.get("customer_domain", "")
        if cf_cname and domain:
            required_actions.append(
                f"Add DNS CNAME record: {domain} → {cf_cname}"
            )
        next_steps.append("Point your domain to CloudFront to activate protection")

    elif status == OnboardingStatus.ACTIVE:
        next_steps.append("Your domain is fully protected by ShieldAI")

    elif status == OnboardingStatus.FAILED:
        error = record.get("error_message", "")
        if error:
            next_steps.append(f"Error: {error}")
        next_steps.append("Delete this onboarding and retry")

    return OnboardingStatusResponse(
        id=record["id"],
        customer_domain=record.get("customer_domain", ""),
        status=status,
        required_actions=required_actions,
        next_steps=next_steps,
        cloudfront_cname=record.get("cloudfront_cname", ""),
        error_message=record.get("error_message", ""),
    )


def _safe_record(record: dict) -> dict:
    """Strip AWS-internal fields from a record before returning to client.

    Prevents leaking ACM certificate ARNs and CloudFront distribution
    tenant IDs — these are internal AWS resource identifiers that clients
    should never see.
    """
    return {
        k: v for k, v in record.items()
        if k not in ("acm_certificate_arn", "distribution_tenant_id")
    }


async def _request_acm_certificate(domain: str) -> dict[str, str]:
    """Request an ACM certificate for a domain via boto3.

    Returns dict with certificate_arn, cname_name, cname_value.
    Runs synchronous boto3 in executor.
    """
    if _acm_client is None:
        raise HTTPException(
            status_code=503,
            detail="ACM service not configured",
        )

    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None,
            lambda: _acm_client.request_certificate(
                DomainName=domain,
                ValidationMethod="DNS",
            ),
        )
    except Exception:
        logger.error("acm_request_failed", domain=domain)
        raise HTTPException(
            status_code=502,
            detail="Failed to request SSL certificate",
        )

    cert_arn = response.get("CertificateArn", "")
    if not cert_arn:
        raise HTTPException(
            status_code=502,
            detail="ACM did not return a certificate ARN",
        )

    # Describe to get validation records
    try:
        desc = await loop.run_in_executor(
            None,
            lambda: _acm_client.describe_certificate(CertificateArn=cert_arn),
        )
    except Exception:
        logger.error("acm_describe_failed", cert_id=_safe_cert_id(cert_arn))
        raise HTTPException(
            status_code=502,
            detail="Failed to retrieve certificate validation details",
        )

    cert_detail = desc.get("Certificate", {})
    validation_options = cert_detail.get("DomainValidationOptions", [])

    cname_name = ""
    cname_value = ""
    if validation_options:
        resource_record = validation_options[0].get("ResourceRecord", {})
        cname_name = resource_record.get("Name", "")
        cname_value = resource_record.get("Value", "")

    return {
        "certificate_arn": cert_arn,
        "cname_name": cname_name,
        "cname_value": cname_value,
    }


async def _cleanup_acm_certificate(cert_arn: str) -> None:
    """Best-effort ACM certificate cleanup on failure.

    Prevents orphaned certificates when the DB insert fails after
    the certificate was already requested.
    """
    if not cert_arn or _acm_client is None:
        return
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(
            None,
            lambda: _acm_client.delete_certificate(CertificateArn=cert_arn),
        )
        logger.info("acm_orphan_cleaned", cert_id=_safe_cert_id(cert_arn))
    except Exception:
        logger.error("acm_orphan_cleanup_failed", cert_id=_safe_cert_id(cert_arn))


@router.post("/customers/{customer_id}/", status_code=201, response_model=OnboardingResponse)
async def create_onboarding(customer_id: UUID, body: OnboardingCreate):
    """Initiate customer domain onboarding.

    Validates domain, requests ACM certificate, stores onboarding record,
    returns DNS validation CNAME records.
    """
    # Validate customer exists
    try:
        customer = await pg_store.get_customer(customer_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")

    # Validate origin URL against SSRF
    ssrf_error = validate_origin_url(body.origin_url, strict_dns=True)
    if ssrf_error:
        logger.warning("onboarding_origin_ssrf_blocked", url=body.origin_url, reason=ssrf_error)
        raise HTTPException(status_code=422, detail="Origin URL validation failed")

    # Check for duplicate active onboarding on this domain
    try:
        existing = await onboarding_store.get_onboarding_by_domain(body.customer_domain)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="Domain already has an active onboarding",
        )

    # Check per-customer onboarding limit
    try:
        count = await onboarding_store.count_active_onboardings(customer_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if count >= onboarding_store.MAX_ONBOARDINGS_PER_CUSTOMER:
        raise HTTPException(
            status_code=422,
            detail=f"Maximum onboardings per customer ({onboarding_store.MAX_ONBOARDINGS_PER_CUSTOMER}) reached",
        )

    # Request ACM certificate
    acm_result = await _request_acm_certificate(body.customer_domain)

    # Create onboarding record — if DB insert fails, clean up the orphaned cert
    try:
        record = await onboarding_store.create_onboarding(
            customer_id=customer_id,
            customer_domain=body.customer_domain,
            origin_url=body.origin_url,
            acm_certificate_arn=acm_result["certificate_arn"],
            validation_cname_name=acm_result["cname_name"],
            validation_cname_value=acm_result["cname_value"],
        )
    except DuplicateDomain:
        # TOCTOU race: another request inserted this domain between our check
        # and our insert. Clean up the orphaned cert.
        await _cleanup_acm_certificate(acm_result["certificate_arn"])
        raise HTTPException(
            status_code=409,
            detail="Domain already has an active onboarding",
        )
    except StoreUnavailable:
        # DB failed — clean up orphaned ACM certificate
        await _cleanup_acm_certificate(acm_result["certificate_arn"])
        raise HTTPException(status_code=503, detail="Database unavailable")
    except Exception:
        # Any other error — clean up orphaned ACM certificate
        await _cleanup_acm_certificate(acm_result["certificate_arn"])
        logger.error("onboarding_create_failed", domain=body.customer_domain)
        raise HTTPException(status_code=500, detail="Failed to create onboarding record")

    return _safe_record(record)


@router.get("/customers/{customer_id}/")
async def list_onboardings(customer_id: UUID):
    """List all onboardings for a customer."""
    try:
        records = await onboarding_store.list_onboardings(customer_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return {"data": [_safe_record(r) for r in records], "total": len(records)}


@router.get("/customers/{customer_id}/{onboarding_id}", response_model=OnboardingResponse)
async def get_onboarding_detail(customer_id: UUID, onboarding_id: UUID):
    """Get full onboarding record, scoped to customer (prevents IDOR)."""
    try:
        record = await onboarding_store.get_onboarding(
            onboarding_id, customer_id=customer_id,
        )
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if record is None:
        raise HTTPException(status_code=404, detail="Onboarding not found")
    return _safe_record(record)


@router.get("/customers/{customer_id}/{onboarding_id}/status")
async def get_onboarding_status(customer_id: UUID, onboarding_id: UUID):
    """Get onboarding status with required actions and next steps."""
    try:
        record = await onboarding_store.get_onboarding(
            onboarding_id, customer_id=customer_id,
        )
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if record is None:
        raise HTTPException(status_code=404, detail="Onboarding not found")
    return _build_status_response(record)


@router.delete("/customers/{customer_id}/{onboarding_id}", status_code=204)
async def delete_onboarding(customer_id: UUID, onboarding_id: UUID):
    """Offboard: mark as offboarded, clean up AWS resources.

    Idempotent — offboarding an already offboarded record is a no-op (204).
    If AWS resource cleanup fails, marks as failed instead of offboarded
    to prevent dangling resources being invisible.
    """
    try:
        record = await onboarding_store.get_onboarding(
            onboarding_id, customer_id=customer_id,
        )
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if record is None:
        raise HTTPException(status_code=404, detail="Onboarding not found")

    # Already offboarded — idempotent
    if record.get("status") == OnboardingStatus.OFFBOARDED:
        return

    # Track cleanup failures
    cleanup_errors: list[str] = []

    # Delete CloudFront distribution tenant if created
    tenant_id = record.get("distribution_tenant_id", "")
    if tenant_id and _cloudfront_client is not None:
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: _cloudfront_client.delete_distribution_tenant(
                    Id=tenant_id,
                    IfMatch="*",
                ),
            )
            logger.info("onboarding_tenant_deleted", tenant_id=tenant_id)
        except Exception:
            logger.error(
                "onboarding_tenant_delete_failed",
                tenant_id=tenant_id,
                onboarding_id=str(onboarding_id),
            )
            cleanup_errors.append("CloudFront tenant deletion failed")

    # Delete ACM certificate
    cert_arn = record.get("acm_certificate_arn", "")
    if cert_arn and _acm_client is not None:
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: _acm_client.delete_certificate(CertificateArn=cert_arn),
            )
            logger.info("onboarding_cert_deleted", cert_id=_safe_cert_id(cert_arn))
        except Exception:
            logger.error(
                "onboarding_cert_delete_failed",
                cert_id=_safe_cert_id(cert_arn),
                onboarding_id=str(onboarding_id),
            )
            cleanup_errors.append("ACM certificate deletion failed")

    # If cleanup had failures, mark as failed (not offboarded) so the resources
    # remain visible and can be retried later. Only mark offboarded on clean exit.
    if cleanup_errors:
        try:
            await onboarding_store.update_onboarding(
                onboarding_id,
                customer_id=customer_id,
                status=OnboardingStatus.FAILED,
                error_message=f"Offboarding incomplete: {'; '.join(cleanup_errors)}",
            )
        except StoreUnavailable:
            raise HTTPException(status_code=503, detail="Database unavailable")
        raise HTTPException(
            status_code=502,
            detail="Offboarding partially failed — some AWS resources could not be cleaned up",
        )

    # All cleanup succeeded — mark as offboarded
    try:
        await onboarding_store.update_onboarding(
            onboarding_id,
            customer_id=customer_id,
            status=OnboardingStatus.OFFBOARDED,
        )
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
