"""Certificate validation poller — background job checking ACM certificate status.

Polls every ``poll_interval`` seconds for onboardings in ``certificate_pending``
status.  When ACM reports ``ISSUED``, updates status to ``certificate_validated``.
Marks as ``failed`` after ``timeout_hours`` (default 72h).

All AWS API calls are via boto3 — injected for testability.

Concurrency safety: uses ``claim_and_update`` with ``expected_status`` guard
so that if multiple poller instances run, only one will successfully claim
each record (optimistic lock via ``WHERE status = $expected``).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger()

# Default poll interval (seconds)
DEFAULT_POLL_INTERVAL = 60

# Maximum time to wait for certificate validation (hours)
DEFAULT_TIMEOUT_HOURS = 72

# Minimum poll interval to prevent tight loops (seconds)
_MIN_POLL_INTERVAL = 10


async def check_certificate_status(
    onboarding: dict[str, Any],
    *,
    acm_client: Any,
) -> str | None:
    """Check a single ACM certificate's status.

    Returns the new onboarding status string, or None if no change.

    Runs synchronous boto3 calls in a thread executor to avoid blocking
    the event loop.
    """
    cert_arn = onboarding.get("acm_certificate_arn", "")
    if not cert_arn:
        logger.warning(
            "cert_poller_no_arn",
            onboarding_id=str(onboarding["id"]),
        )
        return "failed"

    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None,
            lambda: acm_client.describe_certificate(CertificateArn=cert_arn),
        )
    except Exception:
        logger.error(
            "cert_poller_describe_failed",
            onboarding_id=str(onboarding["id"]),
            cert_arn=cert_arn,
        )
        return None

    cert = response.get("Certificate", {})
    status = cert.get("Status", "")

    if status == "ISSUED":
        logger.info(
            "cert_poller_issued",
            onboarding_id=str(onboarding["id"]),
            cert_arn=cert_arn,
        )
        return "certificate_validated"

    if status == "FAILED":
        failure_reason = cert.get("FailureReason", "unknown")
        logger.error(
            "cert_poller_acm_failed",
            onboarding_id=str(onboarding["id"]),
            cert_arn=cert_arn,
            reason=failure_reason,
        )
        return "failed"

    # Check timeout
    created_at = onboarding.get("created_at")
    if created_at is not None:
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        elapsed = datetime.now(timezone.utc) - created_at
        if elapsed.total_seconds() > DEFAULT_TIMEOUT_HOURS * 3600:
            logger.error(
                "cert_poller_timeout",
                onboarding_id=str(onboarding["id"]),
                cert_arn=cert_arn,
                elapsed_hours=elapsed.total_seconds() / 3600,
            )
            return "failed"

    # Still pending
    return None


async def run_cert_poller(
    *,
    poll_interval: int = DEFAULT_POLL_INTERVAL,
    acm_client: Any = None,
    shutdown_event: asyncio.Event | None = None,
) -> None:
    """Run the certificate validation poller loop.

    Args:
        poll_interval: Seconds between polls (minimum 10).
        acm_client: boto3 ACM client (injected for testability).
        shutdown_event: Event to signal graceful shutdown.
    """
    from proxy.store.onboarding import list_pending_onboardings, claim_and_update

    poll_interval = max(_MIN_POLL_INTERVAL, poll_interval)

    if shutdown_event is None:
        shutdown_event = asyncio.Event()

    logger.info("cert_poller_started", poll_interval=poll_interval)

    while not shutdown_event.is_set():
        try:
            pending = await list_pending_onboardings()
            for onboarding in pending:
                if shutdown_event.is_set():
                    break

                if acm_client is None:
                    logger.warning("cert_poller_no_acm_client")
                    break

                new_status = await check_certificate_status(
                    onboarding, acm_client=acm_client,
                )
                if new_status is not None:
                    error_msg = ""
                    if new_status == "failed":
                        error_msg = "Certificate validation failed or timed out"
                    # Atomic claim — only succeeds if still certificate_pending
                    result = await claim_and_update(
                        onboarding["id"],
                        expected_status="certificate_pending",
                        new_status=new_status,
                        error_message=error_msg if error_msg else None,
                    )
                    if result is not None:
                        logger.info(
                            "cert_poller_status_updated",
                            onboarding_id=str(onboarding["id"]),
                            new_status=new_status,
                        )
                    else:
                        logger.info(
                            "cert_poller_already_claimed",
                            onboarding_id=str(onboarding["id"]),
                        )
        except Exception:
            # logger.error (not .exception) — tracebacks may leak cert ARNs
            logger.error("cert_poller_error")

        # Wait for next poll or shutdown
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=poll_interval)
        except asyncio.TimeoutError:
            pass  # Normal: timeout means keep polling

    logger.info("cert_poller_stopped")
