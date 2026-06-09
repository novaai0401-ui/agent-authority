"""Error types for Behalf."""


class BehalfError(Exception):
    """Base class for all Behalf errors."""


class AuthorizationError(BehalfError):
    """Raised by ``authorize()`` when the requested action is not permitted."""

    def __init__(self, action: str, reason: str) -> None:
        self.action = action
        self.reason = reason
        super().__init__(f'authorization denied for "{action}": {reason}')


class WideningError(BehalfError):
    """Raised by ``attenuate()`` when a requested capability would widen authority."""

    def __init__(self, capability: str) -> None:
        self.capability = capability
        super().__init__(
            f'attenuation would widen authority: "{capability}" '
            "is not covered by the parent mandate"
        )


class IntegrityError(BehalfError):
    """Raised when a token's signature chain does not verify."""

    def __init__(self, message: str = "mandate signature is invalid") -> None:
        super().__init__(message)


class CapabilityParseError(BehalfError):
    """Raised when a capability string cannot be parsed."""

    def __init__(self, capability: str, detail: str) -> None:
        self.capability = capability
        super().__init__(f'invalid capability "{capability}": {detail}')
