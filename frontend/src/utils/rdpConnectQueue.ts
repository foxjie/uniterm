// Connect-phase mutex shared by every RDP tab in the app. It MUST live in a
// real module scope: the previous attempt declared it at the top level of
// RDPTabContent.vue's <script setup>, which is per-component setup scope —
// every tab got its own private chain and the "lock" serialized nothing.
//
// Why the mutex is needed: the IronRDP wasm layer is not safe for two
// concurrent connect() calls. Observed when a restored tab group reconnects
// both sessions at once: the first session's WebSocket never reaches Open
// (or never sends its RDCleanPath request) and the tab hangs; an earlier
// wasm build crashed with "memory access out of bounds" on the same flow.
// Session registration + connect therefore run one tab at a time; an
// established session's run loop may freely overlap the next connect.
let chain: Promise<unknown> = Promise.resolve()

export function rdpQueueConnect<T>(phase: () => Promise<T>): Promise<T> {
  const run = chain.then(phase, phase)
  // Never let a stuck connect wedge the chain forever: release the queue
  // after 90 s even if the phase is still pending (the tab's own 30 s
  // connect timer has already errored it out by then).
  chain = Promise.race([
    run.then(() => undefined, () => undefined),
    new Promise((resolve) => setTimeout(resolve, 90_000)),
  ])
  return run
}
