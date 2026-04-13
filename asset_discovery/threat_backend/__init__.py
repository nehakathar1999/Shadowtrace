"""Integrated threat intelligence package for asset_discovery.

This package intentionally avoids eager database initialization at import time.
The threat backend is optional during local development, so importing the
package should not fail just because PostgreSQL credentials are missing or
incorrect.
"""

__all__ = []
