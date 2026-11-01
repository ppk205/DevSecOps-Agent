"""The hand-written AI harness: session loop, gates, tools and providers.

Nothing here uses an agent framework or a provider SDK. Model calls go
through :mod:`vulnscan.harness.providers` transports built on httpx.
"""
