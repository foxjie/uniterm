package session

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ys-ll/uniterm/backend/log"
	"golang.org/x/crypto/ssh"
)

// HostKeyStrategy 控制 SSH 主机密钥校验策略。
type HostKeyStrategy int

const (
	// HostKeyAcceptNew 是默认策略：首次连接记录指纹（TOFU），变更时返回
	// *HostKeyChangedError 并通过事件发射器通知前端弹窗确认。
	HostKeyAcceptNew HostKeyStrategy = iota
	// HostKeyStrict 严格模式：首次连接仍记录指纹，但变更时直接拒绝
	// （不发射前端事件，错误中仍含旧/新指纹便于日志排查）。
	HostKeyStrict
	// HostKeyOff 关闭校验，等价于 ssh.InsecureIgnoreHostKey()，保留旧行为。
	HostKeyOff
)

// ParseHostKeyStrategy 将字符串转为 HostKeyStrategy。
// 空串与未知值均回退到 HostKeyAcceptNew，保证默认安全。
func ParseHostKeyStrategy(s string) HostKeyStrategy {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict":
		return HostKeyStrict
	case "off", "insecure", "disable", "disabled":
		return HostKeyOff
	default:
		return HostKeyAcceptNew
	}
}

// String 返回策略的小写标识，用于 JSON 持久化与前端展示。
func (s HostKeyStrategy) String() string {
	switch s {
	case HostKeyStrict:
		return "strict"
	case HostKeyOff:
		return "off"
	default:
		return "accept-new"
	}
}

// HostKeyChangedError 描述一次主机密钥变更。导出字段供前端事件 payload 序列化。
type HostKeyChangedError struct {
	Host      string `json:"host"`
	Port      string `json:"port"`
	KeyType   string `json:"keyType"`
	OldFp     string `json:"oldFp"`     // SHA256 指纹（ssh.FingerprintSHA256 格式）
	NewFp     string `json:"newFp"`     // SHA256 指纹
	OldKeyB64 string `json:"oldKeyB64"` // base64(SSH wire format)，便于前端展示与调试
	NewKeyB64 string `json:"newKeyB64"`
}

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf("host key for %s:%s changed (%s): old=%s new=%s — possible MITM; verify the new fingerprint before accepting",
		e.Host, e.Port, e.KeyType, e.OldFp, e.NewFp)
}

// Is 使 errors.Is/As 能识别 host key 变更错误。
func (e *HostKeyChangedError) Is(target error) bool {
	_, ok := target.(*HostKeyChangedError)
	return ok
}

// hostKeyEmitterFunc 是 App 层注入的事件发射器签名，用于在变更时通知
// 前端弹出确认对话框。
type hostKeyEmitterFunc = func(name string, payload any)

var (
	// hostKeyMu 串行化 known_hosts 文件读写，避免并发连接互相覆盖。
	hostKeyMu sync.Mutex

	hostKeyEmitterMu sync.RWMutex
	hostKeyEmitter   hostKeyEmitterFunc

	defaultStrategyMu sync.RWMutex
	defaultStrategy   = HostKeyAcceptNew
)

// SetHostKeyEmitter 注入 Wails 事件发射器。由 app.go 启动时调用一次。
// 传入 nil 可清除（主要用于测试）。
func SetHostKeyEmitter(emitter hostKeyEmitterFunc) {
	hostKeyEmitterMu.Lock()
	defer hostKeyEmitterMu.Unlock()
	hostKeyEmitter = emitter
}

func getHostKeyEmitter() hostKeyEmitterFunc {
	hostKeyEmitterMu.RLock()
	defer hostKeyEmitterMu.RUnlock()
	return hostKeyEmitter
}

// SetDefaultHostKeyStrategy 设置全局默认策略（用户在设置页选择的值）。
// app.go 在启动和设置变更时调用。
func SetDefaultHostKeyStrategy(s HostKeyStrategy) {
	defaultStrategyMu.Lock()
	defer defaultStrategyMu.Unlock()
	defaultStrategy = s
}

// GetDefaultHostKeyStrategy 返回当前全局默认策略。
func GetDefaultHostKeyStrategy() HostKeyStrategy {
	defaultStrategyMu.RLock()
	defer defaultStrategyMu.RUnlock()
	return defaultStrategy
}

// KnownHostsPath 返回 ~/.uniterm/known_hosts 的绝对路径。导出以便测试与管理。
func KnownHostsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".uniterm", "known_hosts"), nil
}

// knownHostsKey 构造 known_hosts 行的 host 列。OpenSSH 风格：非 22 端口用 [host]:port。
func knownHostsKey(host, port string) string {
	if port == "" || port == "22" {
		return host
	}
	return fmt.Sprintf("[%s]:%s", host, port)
}

// HostKeyCallback 返回 SSH 主机密钥校验回调。
//
//   - HostKeyOff：等价 ssh.InsecureIgnoreHostKey()，保留旧行为。
//   - HostKeyAcceptNew（默认）：首次连接记录指纹（TOFU），变更时返回
//     *HostKeyChangedError 并通过事件发射器通知前端弹窗确认。
//   - HostKeyStrict：首次连接仍记录指纹，变更时直接拒绝（不通知前端）。
//
// host/port 用于在 known_hosts 中定位条目；hostname 是 ssh 库传入的拨号地址，仅用于日志。
func HostKeyCallback(host, port string, strategy HostKeyStrategy) ssh.HostKeyCallback {
	if strategy == HostKeyOff {
		return ssh.InsecureIgnoreHostKey()
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return verifyHostKey(host, port, strategy, key)
	}
}

// verifyHostKey 实现 TOFU 校验核心逻辑。调用方必须已持有 hostKeyMu。
func verifyHostKey(host, port string, strategy HostKeyStrategy, newKey ssh.PublicKey) error {
	hostKeyMu.Lock()
	defer hostKeyMu.Unlock()

	path, err := KnownHostsPath()
	if err != nil {
		// 拿不到 home 目录是环境异常，拒绝连接比放行更安全。
		return fmt.Errorf("hostkey: resolve known_hosts path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("hostkey: mkdir %s: %w", filepath.Dir(path), err)
	}

	keyType := newKey.Type()
	newKeyB64 := base64.StdEncoding.EncodeToString(newKey.Marshal())
	newFp := ssh.FingerprintSHA256(newKey)
	lookupKey := knownHostsKey(host, port)

	oldKeyB64, oldKey, err := lookupKnownHostKey(path, lookupKey, keyType)
	if err != nil {
		// 文件损坏不应当阻断首次连接：记录日志后按"未记录"处理，
		// 让用户能继续连上并重新写入新指纹，而不是被旧数据卡死。
		log.Writef("hostkey: read %s failed (%v); treating as first connect", path, err)
		oldKeyB64, oldKey = "", nil
	}

	if oldKey == nil {
		// 首次连接：记录并放行（TOFU）。
		if err := appendKnownHostKey(path, lookupKey, keyType, newKeyB64); err != nil {
			return fmt.Errorf("hostkey: write %s: %w", path, err)
		}
		return nil
	}

	oldFp := ssh.FingerprintSHA256(oldKey)
	if oldKeyB64 == newKeyB64 {
		// 指纹匹配：放行。
		return nil
	}

	// 变更：构造错误。AcceptNew 通知前端弹窗；Strict 直接拒绝。
	changed := &HostKeyChangedError{
		Host:      host,
		Port:      port,
		KeyType:   keyType,
		OldFp:     oldFp,
		NewFp:     newFp,
		OldKeyB64: oldKeyB64,
		NewKeyB64: newKeyB64,
	}
	if strategy == HostKeyAcceptNew {
		if emitter := getHostKeyEmitter(); emitter != nil {
			emitter("session:hostkey-changed", map[string]any{
				"host":      changed.Host,
				"port":      changed.Port,
				"keyType":   changed.KeyType,
				"oldFp":     changed.OldFp,
				"newFp":     changed.NewFp,
				"oldKeyB64": changed.OldKeyB64,
				"newKeyB64": changed.NewKeyB64,
			})
		}
	}
	return changed
}

// lookupKnownHostKey 在 known_hosts 文件中查找 host+keyType 对应的 base64 公钥。
// 返回 (keyB64, parsedKey, error)。未找到时返回 ("", nil, nil)。
func lookupKnownHostKey(path, host, keyType string) (string, ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, nil
		}
		return "", nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[0] != host || fields[1] != keyType {
			continue
		}
		keyB64 := fields[2]
		raw, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return "", nil, fmt.Errorf("decode key for %s: %w", host, err)
		}
		parsed, err := ssh.ParsePublicKey(raw)
		if err != nil {
			return "", nil, fmt.Errorf("parse key for %s: %w", host, err)
		}
		return keyB64, parsed, nil
	}
	return "", nil, nil
}

// appendKnownHostKey 追加一条记录到 known_hosts 文件。
func appendKnownHostKey(path, host, keyType, keyB64 string) error {
	line := fmt.Sprintf("%s %s %s\n", host, keyType, keyB64)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

// AcceptHostKeyChange 用新公钥替换 known_hosts 中 host 的旧记录。
// 前端用户在"主机密钥变更"对话框点击"接受并继续"时调用。
// 传入的 newKeyB64 是 base64 编码的 SSH wire format 公钥。
func AcceptHostKeyChange(host, port, keyType, newKeyB64 string) error {
	hostKeyMu.Lock()
	defer hostKeyMu.Unlock()

	path, err := KnownHostsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	lookupKey := knownHostsKey(host, port)
	return replaceKnownHostKey(path, lookupKey, keyType, newKeyB64)
}

// replaceKnownHostKey 替换 known_hosts 中 host+keyType 的条目；不存在则追加。
func replaceKnownHostKey(path, host, keyType, newKeyB64 string) error {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 3 && fields[0] == host && fields[1] == keyType {
			continue // 删除旧条目
		}
		kept = append(kept, line)
	}
	kept = append(kept, fmt.Sprintf("%s %s %s", host, keyType, newKeyB64))
	content := strings.Join(kept, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0600)
}

// ResolveHostKeyStrategy 解析有效的 host key 策略：非空 config 值优先，否则用全局默认。
// 各 SSH session 在构造 ClientConfig 时调用本函数。
func ResolveHostKeyStrategy(configStrategy string) HostKeyStrategy {
	if s := strings.TrimSpace(configStrategy); s != "" {
		return ParseHostKeyStrategy(s)
	}
	return GetDefaultHostKeyStrategy()
}

// AsHostKeyChangedError 若 err 是 *HostKeyChangedError 则返回它和 true。
// 便于 App 层在 failSessionConnect 中识别并附加更友好的终端提示。
func AsHostKeyChangedError(err error) (*HostKeyChangedError, bool) {
	var changed *HostKeyChangedError
	if errors.As(err, &changed) {
		return changed, true
	}
	return nil, false
}
