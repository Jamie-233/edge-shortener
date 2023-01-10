"""netlint — lint network device configs for common mistakes."""

from .lint import Issue, lint

__all__ = ["lint", "Issue"]
__version__ = "0.1.0"
