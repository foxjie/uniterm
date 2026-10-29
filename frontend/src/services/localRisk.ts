// S2: AI Agent 本地危险命令防线
//
// assessLocalRisk 对一条 shell 命令做纯模式匹配，独立于 LLM 自声明的
// `input.risk` 字段。agent.ts 的 getRisk 会取 max(modelRisk, localRisk)，
// 这样即使被 prompt injection 劫持的模型把 `rm -rf ~` 声明为 risk:"read"
// 也无法绕过用户确认。
//
// 这是"纵深防御"而非绝对防线：base64/变量拼接等绕过检测不可能穷尽，
// 只能覆盖常见模式。文档中需说明这一点。
//
// 评级语义：
//   - 'read'      只读、无副作用（默认）
//   - 'write'     修改/创建数据，但不系统级破坏
//   - 'dangerous' 潜在破坏性或系统级影响

export type LocalRiskLevel = 'read' | 'write' | 'dangerous'

// ---- 危险模式黑名单（强制 dangerous） ----
// 用正则做大小写不敏感匹配；命令前可能有空白、变量赋值、sudo/doas 前缀，
// 所以一律用 \b 边界 + 任意前缀通配。
const DANGEROUS_PATTERNS: RegExp[] = [
  // rm -rf / rm -fr（任意路径，含 ~、*、$HOME）。
  // flag 可能与其他短选项组合（-rfv / -frv），所以 r 与 f 之间允许任意字母，
  // 且不要求 flag 串结尾（去掉 \b），用 \s 确保 flag 后是空白即命令参数边界。
  /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s/,
  /\brm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s/,
  // rm -r -f / rm -f -r（分开写 flag，组合形式上面已覆盖，这里补漏）
  /\brm\s+-r\s+-f\b/,
  /\brm\s+-f\s+-r\b/,
  // rm --recursive --force（长选项形式）
  /\brm\s+[^&|;]*--recursive[^&|;]*--force/,
  /\brm\s+[^&|;]*--force[^&|;]*--recursive/,
  // mkfs 系列（mkfs.ext4 / mkfs.vfat / mkswap）
  /\bmkfs\b/,
  /\bmkswap\b/,
  // dd 写块设备：dd if=...of=/dev/... 或 dd of=/dev/...
  /\bdd\b[^|;&]*\bof=\/dev\//,
  // chmod -R 777 / 或 chmod 777 /（系统级权限破坏）
  /\bchmod\s+(-R\s+)?777\s+\/(?:\s|$|;|&|\|)/,
  // chmod -R 000 /（剥夺所有权限）
  /\bchmod\s+-R\s+000\s+\/(?:\s|$|;|&|\|)/,
  // curl/wget 管道到 shell（远程脚本执行）
  /\b(curl|wget)\b[^|;&]*\|\s*(sh|bash|zsh|fish|python|python3|perl|ruby)\b/,
  // fork bomb :(){ :|:& };:
  /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
  // 直接重定向到块设备 > /dev/sda
  />\s*\/dev\/(?:sd|nvme|hd|vd|disk)/,
  // shutdown / reboot / halt / poweroff
  /\b(shutdown|reboot|halt|poweroff)\b/,
  // kill -9 1（杀 init）
  /\bkill\s+-9\s+1\b/,
  /\bkill\s+-KILL\s+1\b/,
  // killall / pkill -9（批量强杀）
  /\bkillall\b/,
  /\bpkill\s+-9\b/,
  /\bpkill\s+-KILL\b/,
]

// ---- 写操作模式（write） ----
// 命中即 write；若同时命中 DANGEROUS 则取 dangerous（在 assessLocalRisk 里合并）。
const WRITE_PATTERNS: RegExp[] = [
  // 文件系统修改：rm（非 -rf，-rf 已被危险匹配）、mv、chmod、chown、mkdir、touch
  /\brm\b/,
  /\bmv\b/,
  /\bchmod\b/,
  /\bchown\b/,
  /\bmkdir\b/,
  /\btouch\b/,
  // 输出重定向 > / >>（写文件）由 hasRedirectWrite() 专门检测引号外的重定向，
  // 不在此用裸 />>?/ 匹配，避免 echo "a > b" 引号内的 > 被误判为 write。
  // 包管理器安装
  /\bapt(?:-get)?\s+install\b/,
  /\baptitude\s+install\b/,
  /\byum\s+install\b/,
  /\bdnf\s+install\b/,
  /\bbrew\s+install\b/,
  /\bpip\s+install\b/,
  /\bpip3\s+install\b/,
  /\bnpm\s+install\b/,
  /\bnpx\s+install\b/,
  /\byarn\s+add\b/,
  // docker 容器/镜像销毁
  /\bdocker\s+rm\b/,
  /\bdocker\s+rmi\b/,
  /\bdocker\s+stop\b/,
  /\bdocker\s+kill\b/,
  /\bdocker\s+container\s+rm\b/,
  // kubectl delete
  /\bkubectl\s+delete\b/,
  // systemctl stop/disable
  /\bsystemctl\s+stop\b/,
  /\bsystemctl\s+disable\b/,
  // iptables -F（清空防火墙规则）
  /\biptables\s+-F\b/,
  /\biptables\s+--flush\b/,
  // 用户管理
  /\buserdel\b/,
  /\busermod\b/,
  /\bgroupdel\b/,
]

// ---- 反绕过检测（一律 dangerous） ----
// 这些模式试图隐藏真实命令，无法静态展开，统一按危险处理。
const BYPASS_PATTERNS: RegExp[] = [
  // base64 解码后管道执行：echo ...|base64 -d|sh
  /\bbase64\b[^|;&]*\|\s*(sh|bash|zsh|fish|python|python3|perl|ruby)\b/,
  // sh -c / bash -c / zsh -c 内层命令
  /\b(sh|bash|zsh|fish)\s+-c\b/,
  // eval 内层命令
  /\beval\b/,
  // $() 命令替换
  /\$\(/,
  // 反引号命令替换
  /`/,
  // 变量拼接执行：VAR="cmd"; $VAR ... — 将命令赋值给变量后通过 $VAR 执行，
  // 无法静态判断 $VAR 展开内容，一律按危险处理。
  // 仅匹配"赋值 + 分隔符 + $VAR 在命令首位"的精确模式，不会误伤
  // echo $HOME / ls $PATH 等正常变量引用（那些 $VAR 不在命令首位）。
  /\b\w+\s*=\s*["'][^"']*["']\s*[;&|]+\s*\$\w+/,
]

/**
 * 将单/双引号内的内容替换为占位符 _STR_，使后续模式匹配只针对引号外
 * 的真实 shell 语法，不会把 `echo "rm -rf /"` 或 `echo "a > b"` 引号内
 * 的文本误判为危险/写命令。
 *
 * 注意：反引号不在此处理（它是命令替换，属 BYPASS_PATTERNS 管辖）。
 * 嵌套引号处理为尽力而为：先替换单引号再替换双引号。
 */
function stripQuotes(s: string): string {
  return s.replace(/'[^']*'/g, '_STR_').replace(/"[^"]*"/g, '_STR_')
}

/**
 * 剥离 shell 语法噪音，收窄误报。
 *
 * 依次：引号内容 → 占位符、${VAR}/$VAR → 占位符、重定向目标文件名 → 移除，
 * 使后续危险/写模式匹配只针对实际命令部分，不会把 $HOME、> output.txt
 * 或引号内的文本误判为危险命令。
 *
 * 注意：$() 命令替换和反引号 **不** 被剥离——它们是真正的命令替换，
 * 属于 BYPASS_PATTERNS 的检测范畴，需在原始命令上匹配。
 */
function stripShellNoise(command: string): string {
  let s = stripQuotes(command)
  // 1. ${VAR} → _VAR_（花括号变量引用）
  s = s.replace(/\$\{[a-zA-Z_]\w*\}/g, '_VAR_')
  // 2. $VAR → _VAR_（裸变量引用，排除 $( 命令替换）
  s = s.replace(/\$(?!\()[a-zA-Z_]\w*/g, '_VAR_')
  // 3. 移除重定向目标文件名（保留到 /dev/ 的重定向，那是危险操作）
  //    匹配 > file、>> file、2> file、2>> file、&> file、&>> file
  //    但不匹配 > /dev/xxx（块设备重定向属 DANGEROUS_PATTERNS 管辖）
  s = s.replace(/(?:&|\d+)?>>?\s*(?!\/dev\/)\S+/g, '')
  return s
}

/**
 * 检测引号外的重定向操作符（> / >>），即写文件操作。
 *
 * 先剥离引号内容再匹配 >>? ，这样 `echo "a > b"` 中引号内的 > 不会
 * 被误判为写操作，而 `echo hi > /tmp/x` 中引号外的 > 仍能命中。
 */
function hasRedirectWrite(command: string): boolean {
  return />>?/.test(stripQuotes(command))
}

/**
 * 评估单条命令的本地风险等级。
 *
 * 不依赖模型声明，纯模式匹配。命令可能是复合命令（&&、||、;、|），
 * 对整条字符串做正则扫描即可：任何子命令命中危险模式则整条危险，
 * 任何子命令命中写模式则整条至少 write。
 *
 * 反绕过模式（base64/sh -c/eval/$()/变量拼接）一律按 dangerous 处理，
 * 因为无法静态判断内层命令的真实意图。
 *
 * 默认返回 'read'（无匹配）。
 */
export function assessLocalRisk(command: string): LocalRiskLevel {
  if (!command || typeof command !== 'string') return 'read'

  // 反绕过优先：一旦命中，直接 dangerous，不再继续。
  // 注意：$() 和反引号是真正的命令替换，不属于"变量引用噪音"，
  // 所以 BYPASS_PATTERNS 对原始命令做匹配。
  for (const re of BYPASS_PATTERNS) {
    if (re.test(command)) return 'dangerous'
  }

  // 剥离引号内容 / $VAR / ${VAR} / 重定向目标，收窄误报。
  // 危险与写模式都对剥离后的命令部分匹配，避免引号内的 "rm -rf /" 或
  // $HOME、> output.txt 等 shell 语法噪音被误判。
  const stripped = stripShellNoise(command)

  let isDangerous = false
  for (const re of DANGEROUS_PATTERNS) {
    if (re.test(stripped)) {
      isDangerous = true
      break
    }
  }

  // 写操作对剥离后的命令匹配：引号内的 rm/mv 等不会误命中。
  let isWrite = false
  for (const re of WRITE_PATTERNS) {
    if (re.test(stripped)) {
      isWrite = true
      break
    }
  }
  // 引号外的重定向操作符（> / >>）是写文件操作，单独检测以避免
  // 引号内的 > 误报（stripShellNoise 会移除重定向目标，故在此用原始命令）。
  if (!isWrite && hasRedirectWrite(command)) isWrite = true

  if (isDangerous) return 'dangerous'
  if (isWrite) return 'write'
  return 'read'
}