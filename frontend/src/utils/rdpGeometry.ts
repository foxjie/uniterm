import { useLocalStateStore } from '../stores/localStateStore'

export type RdpDesktopSize = { width: number; height: number }
export type RdpDisplayRect = RdpDesktopSize & { left: number; top: number }

/**
 * Host → "server applies RDP DPI scaling completely", learned from the WASM
 * layer after each connect. Shared across tabs so a host known to apply DPI
 * only partially (pre-Windows 10 servers) starts in fit-to-panel mode —
 * logical session size, no scale, client-side upscale — from the very first
 * frame instead of resizing once the server version is discovered.
 *
 * Persisted in the local-state store (local_state.json): the server's RDP
 * protocol version never changes mid-life, so what one connect learns, every
 * later connect (even after an app restart) starts with — one probing session
 * per host, ever. Deliberately NOT in WebView2 localStorage: the WebView2
 * profile is torn down on clean exit and is not reliably persisted.
 */
export function hostDpiSupportFor(host: string): boolean {
  try {
    return useLocalStateStore().state.hostDpiSupport?.[host] ?? true
  } catch {
    // Store not ready: assume full DPI support (the pre-Win10 probe flow).
    return true
  }
}

export function rememberHostDpiSupport(host: string, supported: boolean): void {
  try {
    const store = useLocalStateStore()
    const current = store.state.hostDpiSupport || {}
    if (current[host] === supported) return
    // Fire-and-forget: losing this write only costs one probe next connect.
    void store.update({ hostDpiSupport: { ...current, [host]: supported } })
  } catch {
    // Best-effort persistence: the server re-reports capability every connect.
  }
}

/** Use the same aligned size for initial negotiation and subsequent resizes. */
export function adaptiveRdpSize(width: number, height: number, pixelRatio = 1): RdpDesktopSize {
  const ratio = Number.isFinite(pixelRatio) && pixelRatio > 0 ? pixelRatio : 1
  return {
    width: Math.max(640, Math.min(0xfffe, Math.floor(width * ratio / 2) * 2)),
    height: Math.max(480, Math.min(0xfffe, Math.floor(height * ratio / 2) * 2)),
  }
}

/**
 * The desktop DPI scale factor to request from the server, in percent, or
 * null to leave the server at its own DPI.
 *
 * Adaptive mode negotiates the viewport's physical pixels, so on a scaled
 * display the remote UI renders at the server's own DPI and appears small.
 * The display control channel carries a per-monitor desktop scale factor
 * that raises the session DPI to match the client display, the way mstsc
 * does. The server must ignore factors below 100 or above 500 percent
 * (MS-RDPEDISP 2.2.2.2.1), so out-of-range ratios request no scaling.
 */
export function rdpScaleFactor(pixelRatio: number): number | null {
  if (!Number.isFinite(pixelRatio)) return null
  const percent = Math.round(pixelRatio * 100)
  return percent > 100 && percent <= 500 ? percent : null
}

/** The visible bitmap inside a centered object-fit canvas. */
export function rdpContentRect(
  bounds: RdpDisplayRect,
  desktop: RdpDesktopSize,
  adaptive: boolean,
): RdpDisplayRect | null {
  if (bounds.width <= 0 || bounds.height <= 0 || desktop.width <= 0 || desktop.height <= 0) return null
  // DOMRect coordinates are prototype accessors, so object spread loses them.
  if (adaptive) return { left: bounds.left, top: bounds.top, width: bounds.width, height: bounds.height }
  const scale = Math.min(bounds.width / desktop.width, bounds.height / desktop.height)
  const width = desktop.width * scale
  const height = desktop.height * scale
  return {
    left: bounds.left + (bounds.width - width) / 2,
    top: bounds.top + (bounds.height - height) / 2,
    width,
    height,
  }
}

export function rdpPointerPosition(
  clientX: number,
  clientY: number,
  bounds: RdpDisplayRect,
  desktop: RdpDesktopSize,
  adaptive: boolean,
  clampOutside = false,
): { x: number; y: number } | null {
  const content = rdpContentRect(bounds, desktop, adaptive)
  if (!content) return null
  if (!clampOutside && (clientX < content.left || clientY < content.top ||
    clientX >= content.left + content.width || clientY >= content.top + content.height)) return null
  return {
    x: Math.max(0, Math.min(desktop.width - 1, Math.floor((clientX - content.left) / content.width * desktop.width))),
    y: Math.max(0, Math.min(desktop.height - 1, Math.floor((clientY - content.top) / content.height * desktop.height))),
  }
}
