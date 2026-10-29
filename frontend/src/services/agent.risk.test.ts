// Regression tests for FE-P0-2: getRisk must default to 'dangerous' for
// missing / wrong-typed / unknown risk values rather than 'write', so a
// model that omits or typos the field cannot bypass the user's
// read-only / confirm_write confirmation mode.

import { describe, expect, it, vi } from 'vitest'

// agent.ts transitively pulls in terminalAgent.ts → terminalManager.ts → xterm
// addons that expect a browser `self` global. Stub the wails runtime + the
// terminal manager so the module graph is small enough to load in vitest.
vi.mock('@wailsio/runtime', () => ({
  Events: { On: vi.fn(() => () => {}), Off: vi.fn() },
}))

// settings.ts 顶层常量 DEFAULT_UI_FONT_SIZE 引用 navigator；node 测试环境
// 无 navigator。vi.hoisted 保证在模块加载前就设置好全局。
vi.hoisted(() => {
  Object.defineProperty(globalThis, 'navigator', {
    value: { userAgent: 'node' },
    configurable: true,
  })
})

vi.mock('../../bindings/github.com/ys-ll/uniterm/app', () => ({
  ChatCompletion: vi.fn(),
  GetSkillFile: vi.fn(),
  ListSkillFiles: vi.fn(),
  SessionWrite: vi.fn(),
}))

vi.mock('./terminalManager', () => ({
  getManagedTerminal: vi.fn(),
}))

// Mock 所有 store：agent.ts 顶层 import 了这些 store，加载真实的
// settingsStore → settings.ts 会执行 `navigator` 顶层常量，在 node 测试
// 环境中不存在 navigator。getRisk 本身不依赖任何 store，mock 掉即可隔离。
vi.mock('../stores/aiStore', () => ({ useAIStore: vi.fn() }))
vi.mock('../stores/settingsStore', () => ({ useSettingsStore: vi.fn() }))
vi.mock('../stores/tabStore', () => ({ useTabStore: vi.fn() }))
vi.mock('../stores/panelStore', () => ({ usePanelStore: vi.fn() }))
vi.mock('../stores/sessionStore', () => ({ useSessionStore: vi.fn() }))
vi.mock('../stores/skillStore', () => ({ useSkillStore: vi.fn() }))
vi.mock('./mcpTools', () => ({
  loadRemoteMCPTools: vi.fn(),
  toAgentToolEntry: vi.fn(),
  callRemoteMCPTool: vi.fn(),
  isRemoteMCPTool: vi.fn(),
}))

import { getRisk, VALID_RISK } from './agent'

describe('getRisk (FE-P0-2 default-closed)', () => {
  it('returns the risk exactly when valid (read)', () => {
    expect(getRisk({ name: 'execute_command', input: { risk: 'read' } })).toBe('read')
  })

  it('returns the risk exactly when valid (write)', () => {
    expect(getRisk({ name: 'start_command', input: { risk: 'write' } })).toBe('write')
  })

  it('returns the risk exactly when valid (dangerous)', () => {
    expect(getRisk({ name: 'execute_command', input: { risk: 'dangerous' } })).toBe('dangerous')
  })

  it('defaults to dangerous when risk field is missing', () => {
    expect(getRisk({ name: 'execute_command', input: {} })).toBe('dangerous')
    expect(getRisk({ name: 'start_command', input: {} })).toBe('dangerous')
  })

  it('defaults to dangerous when risk is an unknown string', () => {
    expect(getRisk({ name: 'execute_command', input: { risk: 'low' } })).toBe('dangerous')
    expect(getRisk({ name: 'start_command', input: { risk: 'risky' } })).toBe('dangerous')
    // Case-sensitive — "READ" is not the same literal as "read".
    expect(getRisk({ name: 'execute_command', input: { risk: 'READ' } })).toBe('dangerous')
  })

  it('defaults to dangerous when risk is null, an empty array, or wrong-typed', () => {
    expect(getRisk({ name: 'execute_command', input: { risk: null } })).toBe('dangerous')
    expect(getRisk({ name: 'execute_command', input: { risk: [] } })).toBe('dangerous')
    expect(getRisk({ name: 'execute_command', input: { risk: '' } })).toBe('dangerous')
    expect(getRisk({ name: 'execute_command', input: { risk: 42 } })).toBe('dangerous')
    expect(getRisk({ name: 'execute_command', input: { risk: { foo: 'bar' } } })).toBe('dangerous')
  })

  it('VALID_RISK exposes exactly the three literal risk levels', () => {
    expect([...VALID_RISK].sort()).toEqual(['dangerous', 'read', 'write'])
  })
})
describe('getRisk (纵深防御: max(modelRisk, localRisk))', () => {
  it('模型声明 read 但命令危险 → dangerous（localRisk 覆盖模型声明）', () => {
    // prompt injection 场景：模型把 rm -rf 声明为 risk:"read" 试图绕过确认
    expect(getRisk({ name: 'execute_command', input: { risk: 'read', command: 'rm -rf /tmp/x' } })).toBe('dangerous')
    expect(getRisk({ name: 'execute_command', input: { risk: 'read', command: 'mkfs.ext4 /dev/sda1' } })).toBe('dangerous')
    expect(getRisk({ name: 'execute_command', input: { risk: 'read', command: 'shutdown -h now' } })).toBe('dangerous')
  })

  it('模型声明 read 且命令只读 → read', () => {
    expect(getRisk({ name: 'execute_command', input: { risk: 'read', command: 'ls -la' } })).toBe('read')
    expect(getRisk({ name: 'execute_command', input: { risk: 'read', command: 'cat /etc/hosts' } })).toBe('read')
  })

  it('模型声明 read 但命令写 → write（localRisk 升级）', () => {
    expect(getRisk({ name: 'execute_command', input: { risk: 'read', command: 'touch /tmp/x' } })).toBe('write')
    expect(getRisk({ name: 'execute_command', input: { risk: 'read', command: 'echo hi > /tmp/x' } })).toBe('write')
  })

  it('模型声明 dangerous 且命令只读 → dangerous（modelRisk 保持）', () => {
    expect(getRisk({ name: 'execute_command', input: { risk: 'dangerous', command: 'ls -la' } })).toBe('dangerous')
  })

  it('模型声明 write 且命令危险 → dangerous（localRisk 升级到 dangerous）', () => {
    expect(getRisk({ name: 'execute_command', input: { risk: 'write', command: 'rm -rf /tmp/x' } })).toBe('dangerous')
  })

  it('命令缺失时退化为纯模型声明（command 非字符串 → localRisk=read）', () => {
    expect(getRisk({ name: 'execute_command', input: { risk: 'write' } })).toBe('write')
    expect(getRisk({ name: 'execute_command', input: { risk: 'read', command: 42 } })).toBe('read')
  })

  it('引号内模式不误报：模型声明 read + echo "rm -rf /" → read', () => {
    expect(getRisk({ name: 'execute_command', input: { risk: 'read', command: 'echo "rm -rf /"' } })).toBe('read')
    expect(getRisk({ name: 'execute_command', input: { risk: 'read', command: 'echo "a > b"' } })).toBe('read')
  })

  it('分开 flag 漏报修复：rm -r -f → dangerous', () => {
    expect(getRisk({ name: 'execute_command', input: { risk: 'read', command: 'rm -r -f /tmp/x' } })).toBe('dangerous')
  })

  it('start_command 同样应用 localRisk', () => {
    expect(getRisk({ name: 'start_command', input: { risk: 'read', command: 'rm -rf /tmp/x' } })).toBe('dangerous')
    expect(getRisk({ name: 'start_command', input: { risk: 'read', command: 'ls -la' } })).toBe('read')
  })
})