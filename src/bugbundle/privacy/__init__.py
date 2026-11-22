"""Privacy layer. All report data passes through :mod:`bugbundle.privacy.redactor`."""

from .redactor import Redactor

__all__ = ["Redactor"]
