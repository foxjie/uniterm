import { SessionResize } from '../../bindings/github.com/ys-ll/uniterm/app'

// Per-session record of the last size whose SessionResize call SUCCEEDED.
// Identical sizes skip the IPC round-trip and the Go-side work it triggers
// (capture-emulator rebuild + a fresh WindowChange, which makes remote shells
// redraw on every duplicate). Mount retry bursts and observer echoes produce
// 6-7 identical resizes per attach; only the first needs to reach the backend.
//
// Keyed by session id, so transferTerminal/duplicate (new id) naturally
// re-sends. Reconnects reuse the id but get a new backend channel that
// defaults to 80x24, so the 'connected' handler must force-send (force=true)
// — that is deliberate, not a duplicate. Failed calls are never recorded,
// so the next fit attempt retries (the burst exists precisely because early
// calls can race session registration).
const lastSent = new Map<string, string>()

export function requestSessionResize(sessionId: string, cols: number, rows: number, force = false): void {
  const key = `${cols}:${rows}`
  if (!force && lastSent.get(sessionId) === key) return
  SessionResize(sessionId, cols, rows)
    .then(() => { lastSent.set(sessionId, key) })
    .catch(() => {})
}
