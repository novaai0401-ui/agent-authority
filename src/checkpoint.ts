import type { AuditCheckpoint } from "./types.js";

/** The slice of the engine this helper needs (so it doesn't import Behalf). */
export interface Checkpointable {
  checkpointAudit(): Promise<AuditCheckpoint>;
}

export interface CheckpointingOptions {
  /** How often to take a checkpoint, in ms. */
  intervalMs: number;
  /**
   * Where each checkpoint goes — store it **out of the audit writer's reach**
   * (another host, object storage, a ledger) for the guarantee to hold.
   */
  sink: (checkpoint: AuditCheckpoint) => void | Promise<void>;
  /** Called if a checkpoint or sink throws (default: ignore). */
  onError?: (err: unknown) => void;
}

/**
 * Periodically anchor the audit log: every `intervalMs`, sign the current head
 * (`engine.checkpointAudit()`) and hand it to `sink`. Returns a `stop()` function.
 * The timer is `unref`'d so it won't keep a Node process alive on its own.
 *
 * This automates the manual `checkpointAudit()` / `verifyAuditCheckpoint()`
 * pattern so tail-deletion and rewrites stay detectable without remembering to
 * checkpoint by hand — provided the sink stores checkpoints somewhere the log's
 * writer cannot reach.
 */
export function startAuditCheckpointing(
  engine: Checkpointable,
  opts: CheckpointingOptions,
): () => void {
  const tick = async (): Promise<void> => {
    try {
      await opts.sink(await engine.checkpointAudit());
    } catch (err) {
      opts.onError?.(err);
    }
  };
  const timer = setInterval(tick, opts.intervalMs);
  (timer as { unref?: () => void }).unref?.();
  return () => clearInterval(timer);
}
