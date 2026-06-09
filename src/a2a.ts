import type { IncomingMessage, ServerResponse } from "node:http";
import { Behalf } from "./behalf.js";
import { Mandate } from "./mandate.js";
import { AuthorizationError } from "./errors.js";
import type { AttenuateOptions } from "./types.js";

/**
 * A2A (agent-to-agent) HTTP transport.
 *
 * The in-process `withBehalf` middleware secures tool calls inside one agent;
 * this secures calls *between* agents over the wire. A caller attaches its
 * mandate to an outgoing request (optionally attenuating it first, so the callee
 * receives strictly less authority); the callee verifies the mandate and its
 * whole delegation chain — offline, with only the issuer's public key — and
 * authorizes the action before doing any work. The verifiable chain travels with
 * the request, so a compromised hop still can't widen scope.
 *
 * Zero dependencies: built on `node:http` types and the global `fetch`.
 */

/** Header carrying the serialized mandate on an A2A request. */
export const MANDATE_HEADER = "x-behalf-mandate";

export interface PresentOptions {
  /** Narrow the mandate before sending, so the callee gets less authority. */
  attenuate?: AttenuateOptions;
}

/** Build the header(s) that carry a mandate to a downstream agent. */
export function present(mandate: Mandate, opts: PresentOptions = {}): Record<string, string> {
  const outgoing = opts.attenuate ? mandate.attenuate(opts.attenuate) : mandate;
  return { [MANDATE_HEADER]: outgoing.serialize() };
}

/** `fetch` wrapper that attaches (and optionally attenuates) a mandate. */
export function behalfFetch(
  input: string | URL,
  mandate: Mandate,
  init: RequestInit = {},
  presentOpts: PresentOptions = {},
): Promise<Response> {
  const headers = { ...(init.headers as Record<string, string>), ...present(mandate, presentOpts) };
  return fetch(input, { ...init, headers });
}

function headerValue(
  headers: Record<string, string | string[] | undefined> | Headers,
  name: string,
): string | undefined {
  if (typeof (headers as Headers).get === "function") {
    return (headers as Headers).get(name) ?? undefined;
  }
  const raw = (headers as Record<string, string | string[] | undefined>)[name];
  return Array.isArray(raw) ? raw[0] : raw;
}

/**
 * Verify + authorize an incoming A2A request. Returns the verified Mandate, or
 * throws {@link AuthorizationError} if it is missing, untrusted, or out of scope.
 * Framework-agnostic: pass any header bag (node:http or fetch `Headers`).
 */
export async function authorizeIncoming(
  engine: Behalf,
  headers: Record<string, string | string[] | undefined> | Headers,
  capability: string,
): Promise<Mandate> {
  const raw = headerValue(headers, MANDATE_HEADER);
  if (!raw) throw new AuthorizationError(capability, "no mandate presented");
  const mandate = engine.import(raw);
  await mandate.authorize(capability); // signature chain + scope + expiry + revocation + audit
  return mandate;
}

export interface GuardOptions {
  /** Engine that holds the trusted issuer key(s). Defaults to the shared one. */
  engine?: Behalf;
  /** Map a request to the capability it requires (return undefined to skip). */
  capability: (req: IncomingMessage) => string | undefined;
  /** Override the default 403 JSON response. */
  onDenied?: (req: IncomingMessage, res: ServerResponse, reason: string) => void;
}

/** Request with the verified mandate attached by {@link guard}. */
export interface GuardedRequest extends IncomingMessage {
  mandate?: Mandate;
}

/**
 * A connect/express/node:http-style middleware that authorizes each request
 * before it reaches your handler. On success the verified mandate is attached as
 * `req.mandate` and `next()` is called; on failure it writes 403 and returns.
 */
export function guard(opts: GuardOptions) {
  const engine = opts.engine ?? Behalf.default;
  return async (req: GuardedRequest, res: ServerResponse, next?: () => void): Promise<boolean> => {
    const capability = opts.capability(req);
    if (capability === undefined) {
      next?.();
      return true;
    }
    try {
      req.mandate = await authorizeIncoming(engine, req.headers, capability);
      next?.();
      return true;
    } catch (e) {
      const reason = e instanceof AuthorizationError ? e.reason : String(e);
      if (opts.onDenied) {
        opts.onDenied(req, res, reason);
      } else {
        res.statusCode = 403;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: "forbidden", reason }));
      }
      return false;
    }
  };
}

/** The symmetric in-process A2A binding (re-exported for continuity). */
export { withBehalfA2A } from "./mcp.js";
