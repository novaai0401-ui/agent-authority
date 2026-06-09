/** Base class for all Behalf errors, so callers can `catch (e instanceof BehalfError)`. */
export class BehalfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Thrown by `authorize()` when the requested action is not permitted. */
export class AuthorizationError extends BehalfError {
  constructor(
    public readonly action: string,
    public readonly reason: string,
  ) {
    super(`authorization denied for "${action}": ${reason}`);
  }
}

/** Thrown by `attenuate()` when a requested capability would widen authority. */
export class WideningError extends BehalfError {
  constructor(public readonly capability: string) {
    super(
      `attenuation would widen authority: "${capability}" is not covered by the parent mandate`,
    );
  }
}

/** Thrown when a token's signature chain does not verify. */
export class IntegrityError extends BehalfError {
  constructor(message = "mandate signature is invalid") {
    super(message);
  }
}

/** Thrown when a capability string cannot be parsed. */
export class CapabilityParseError extends BehalfError {
  constructor(public readonly capability: string, detail: string) {
    super(`invalid capability "${capability}": ${detail}`);
  }
}
