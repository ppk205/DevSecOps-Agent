"""Consent checks for the baseline model stages of ``scan-run`` (B7).

The harness gates every model call behind G0. ``scan-run``'s model paths
(``--mode hunt``, ``--ai-review``, ``--ai-report``) are a baseline, not the
harness, but they still send code excerpts to the provider. A cloud provider
therefore needs an explicit flag; a provider whose base URL is loopback does
not, because nothing leaves the machine.
"""

from __future__ import annotations

from urllib.parse import urlparse

from vulnscan.contracts.provider import ProviderProfile

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def is_local_base_url(base_url: str) -> bool:
    """True only for loopback hosts; ``localhost.example.com`` is not local."""
    try:
        hostname = urlparse(base_url).hostname
    except ValueError:
        return False
    return hostname in LOCAL_HOSTS


def model_use_allowed(profile: ProviderProfile, allow_cloud_model: bool) -> tuple[bool, str]:
    """Decide whether the baseline model stages may call this profile."""
    if is_local_base_url(profile.base_url):
        return (True, "local provider")
    if allow_cloud_model:
        return (True, "cloud provider allowed by --allow-cloud-model")
    return (
        False,
        (
            f"cloud provider {profile.id} needs --allow-cloud-model; "
            "code excerpts would leave this machine"
        ),
    )
