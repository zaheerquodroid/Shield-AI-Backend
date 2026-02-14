"""Distribution tenant creator — background job creating CloudFront tenants.

When a certificate validates (status = ``certificate_validated``), this job
creates a CloudFront distribution tenant via boto3 and updates the onboarding
record to ``tenant_created`` with the CloudFront CNAME for DNS setup.

All AWS API calls are via boto3 — injected for testability.

Concurrency safety: uses ``claim_and_update`` with ``expected_status`` guard
so that if multiple creator instances run, only one will successfully claim
each record (optimistic lock via ``WHERE status = $expected``).
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

logger = structlog.get_logger()

# Default poll interval (seconds)
DEFAULT_POLL_INTERVAL = 30

# Minimum poll interval to prevent tight loops (seconds)
_MIN_POLL_INTERVAL = 10


async def create_distribution_tenant(
    onboarding: dict[str, Any],
    *,
    cloudfront_client: Any,
    distribution_id: str,
) -> dict[str, Any] | None:
    """Create a CloudFront distribution tenant for a validated onboarding.

    Returns a dict with tenant_id and cloudfront_cname, or None on failure.

    Runs synchronous boto3 calls in a thread executor.
    """
    customer_domain = onboarding.get("customer_domain", "")
    origin_url = onboarding.get("origin_url", "")
    cert_arn = onboarding.get("acm_certificate_arn", "")

    if not customer_domain or not origin_url or not cert_arn:
        logger.error(
            "tenant_creator_missing_fields",
            onboarding_id=str(onboarding["id"]),
            has_domain=bool(customer_domain),
            has_origin=bool(origin_url),
            has_cert=bool(cert_arn),
        )
        return None

    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None,
            lambda: cloudfront_client.create_distribution_tenant(
                DistributionId=distribution_id,
                Name=f"shieldai-tenant-{customer_domain}",
                Domains=[{
                    "Domain": customer_domain,
                    "CertificateArn": cert_arn,
                }],
            ),
        )
    except Exception:
        logger.error(
            "tenant_creator_api_failed",
            onboarding_id=str(onboarding["id"]),
            customer_domain=customer_domain,
        )
        return None

    tenant = response.get("DistributionTenant", {})
    tenant_id = tenant.get("Id", "")
    # CloudFront provides a domain like d12345.cloudfront.net
    cf_domain = tenant.get("DomainName", "")

    if not tenant_id:
        logger.error(
            "tenant_creator_no_id",
            onboarding_id=str(onboarding["id"]),
            response_keys=list(response.keys()),
        )
        return None

    logger.info(
        "tenant_creator_success",
        onboarding_id=str(onboarding["id"]),
        customer_domain=customer_domain,
        tenant_id=tenant_id,
        cloudfront_cname=cf_domain,
    )

    return {
        "tenant_id": tenant_id,
        "cloudfront_cname": cf_domain,
    }


async def run_tenant_creator(
    *,
    poll_interval: int = DEFAULT_POLL_INTERVAL,
    cloudfront_client: Any = None,
    distribution_id: str = "",
    shutdown_event: asyncio.Event | None = None,
) -> None:
    """Run the tenant creator poller loop.

    Args:
        poll_interval: Seconds between polls (minimum 10).
        cloudfront_client: boto3 CloudFront client (injected for testability).
        distribution_id: The multi-tenant CloudFront distribution ID.
        shutdown_event: Event to signal graceful shutdown.
    """
    from proxy.store.onboarding import list_validated_onboardings, claim_and_update

    poll_interval = max(_MIN_POLL_INTERVAL, poll_interval)

    if shutdown_event is None:
        shutdown_event = asyncio.Event()

    logger.info(
        "tenant_creator_started",
        poll_interval=poll_interval,
        distribution_id=distribution_id,
    )

    while not shutdown_event.is_set():
        try:
            validated = await list_validated_onboardings()
            for onboarding in validated:
                if shutdown_event.is_set():
                    break

                if cloudfront_client is None or not distribution_id:
                    logger.warning(
                        "tenant_creator_not_configured",
                        has_client=cloudfront_client is not None,
                        has_distribution_id=bool(distribution_id),
                    )
                    break

                result = await create_distribution_tenant(
                    onboarding,
                    cloudfront_client=cloudfront_client,
                    distribution_id=distribution_id,
                )

                if result is not None:
                    # Atomic claim — only succeeds if still certificate_validated
                    updated = await claim_and_update(
                        onboarding["id"],
                        expected_status="certificate_validated",
                        new_status="tenant_created",
                        distribution_tenant_id=result["tenant_id"],
                        cloudfront_cname=result["cloudfront_cname"],
                    )
                    if updated is not None:
                        logger.info(
                            "tenant_creator_updated",
                            onboarding_id=str(onboarding["id"]),
                            tenant_id=result["tenant_id"],
                        )
                    else:
                        logger.info(
                            "tenant_creator_already_claimed",
                            onboarding_id=str(onboarding["id"]),
                        )
                else:
                    # Atomic claim — only mark failed if still certificate_validated
                    await claim_and_update(
                        onboarding["id"],
                        expected_status="certificate_validated",
                        new_status="failed",
                        error_message="Failed to create CloudFront distribution tenant",
                    )

        except Exception:
            # logger.error (not .exception) — tracebacks may leak cert ARNs
            logger.error("tenant_creator_error")

        # Wait for next poll or shutdown
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=poll_interval)
        except asyncio.TimeoutError:
            pass  # Normal: timeout means keep polling

    logger.info("tenant_creator_stopped")
