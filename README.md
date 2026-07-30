# YSU Net Watch

面向 Windows 的燕山大学 `iYanDa` 校园网络认证守护工具。它可以连接
`iYanDa`、完成校园网或宽带认证、持续检查认证状态，并在确认掉线后自动
重新认证。

> [!IMPORTANT]
> 本项目是非官方工具，与燕山大学、锐捷网络及各宽带运营商无隶属或授权
> 关系。请仅用于本人账号及获准使用的校园网络，不得绕过验证码、设备确认
> 或学校安全策略。门户升级后，部分功能可能暂时失效。

## 功能

- 校园网认证，以及中国联通、中国电信、中国移动宽带认证。
- 无参数启动交互式控制台，支持方向键选择、切换认证模式、下线和停止监听。
- Wi-Fi 开启但未连接任何网络时自动连接 `iYanDa`；连接热点或其他 Wi-Fi
  时跳过，不抢占当前网络。
- 最多 10 个可独立开关的定时器，可设置执行时间、星期、认证模式和失败
  补偿时间。
- 默认定时器在工作日 06:00 启动中国联通监听；本轮持续认证失败时，
  08:00 再尝试一次。
- 连续 3 次 Ping 失败后，只有 HTTP 探测明确重定向到燕大认证门户，或
  HTTPS 门户连续确认离线，才会读取凭据。
- 疑似掉线后默认等待 120 秒复核，避免瞬时网络波动触发认证。
- 认证连续失败 5 次后停止监听，并将脱敏原因写入日志。
- 宽带账号明确被旧设备占用时，可按门户设备管理流程下线旧会话并补偿登录。
- 使用 Windows 凭据管理器保存账号密码；设置文件只保存非敏感偏好。
- 单文件 Windows EXE，目标电脑无需预装 Python。

## 系统要求

- Windows 10 或 Windows 11。
- 已开启的 Wi-Fi 网卡；程序不能绕过飞行模式、物理无线开关或管理员禁用。
- 可连接到燕山大学 `iYanDa` 无线网络。
- 本人合法的校园网或宽带认证账号。

## 快速开始

### 使用 Windows EXE

从本仓库的 Releases 下载 `ysu-net-watch.exe`，核对发布页提供的 SHA-256
后运行。程序没有商业代码签名，Windows SmartScreen 首次运行时可能显示
“未知发布者”。

首次保存凭据：

```powershell
.\ysu-net-watch.exe credential set --mode campus
.\ysu-net-watch.exe credential set --mode broadband
```

随后直接打开：

```powershell
.\ysu-net-watch.exe
```

### 从源码安装

需要 Python 3.10 或更高版本：

```powershell
git clone https://github.com/kindness314/ysu-net-watch.git
cd ysu-net-watch
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
ysu-net-watch
```

## 凭据安全

推荐使用 Windows 凭据管理器。`credential set` 会通过隐藏输入读取密码，
密码不会出现在命令行参数、项目文件或普通设置文件中：

```powershell
ysu-net-watch credential set --mode campus
ysu-net-watch credential set --mode broadband
ysu-net-watch credential delete --mode campus
ysu-net-watch credential delete --mode broadband
```

环境变量仅作为回退方式：

```powershell
$env:YSU_CAMPUS_USERNAME = "学号"
$env:YSU_CAMPUS_PASSWORD = "密码"
ysu-net-watch login --mode campus --credential-source env
```

程序首次读取环境变量后会将其从当前进程环境中移除，但环境变量仍不能对
管理员、同权限调试器或进程转储保密。不要把真实凭据写入 `.env`、源码、
Issue、日志或命令行参数。

## 交互控制台与定时器

不带子命令运行时进入常驻控制台：

```powershell
ysu-net-watch
```

菜单中的“修改常用/定时设置”可以配置常用认证模式和最多 10 个定时器。
每个定时器支持：

- 开启或关闭。
- 自定义执行时间。
- 工作日、每天、周末或自定义星期。
- 校园网或指定宽带运营商。
- 可选的失败补偿时间。

设置保存在 `%LOCALAPPDATA%\YSUNetWatch\settings.json`，不包含账号密码。
定时器依赖程序保持运行；窗口可以最小化，但退出程序后定时器不会运行。
同一分钟有多个定时器时，编号较小的优先执行。

## 命令行

持续监听校园网：

```powershell
ysu-net-watch watch --mode campus --credential-source windows
```

持续监听联通宽带：

```powershell
ysu-net-watch watch --mode broadband --service unicom --credential-source windows
```

运营商参数还支持 `telecom` 和 `mobile`。

单次认证、状态查询和下线：

```powershell
ysu-net-watch login --mode campus --credential-source windows
ysu-net-watch status
ysu-net-watch logout
```

禁止程序切换 Wi-Fi：

```powershell
ysu-net-watch watch --no-auto-wifi --mode campus
```

查看全部选项：

```powershell
ysu-net-watch --help
ysu-net-watch watch --help
```

## 掉线判断

正式参数默认每 60 秒检查一次：

1. 对多个公共目标分别执行 Ping。
2. 只有全部 Ping 失败，才检查固定 HTTP 探测地址。
3. 探测地址必须返回重定向，且目标主机精确匹配燕大认证门户；攻击者后缀
   域名不会被接受。
4. 公共探测无法确认时，仅在当前确实连接 `iYanDa` 的情况下查询 HTTPS
   门户状态。
5. 默认等待 120 秒再次确认。
6. 确认认证失效后才从凭据管理器读取账号密码并认证。

连接热点、离开 `iYanDa`、门户状态不明确或仅发生普通网络故障时，程序
不会提交凭据。

## 日志与隐私

日志默认写入当前目录的 `ysu-net-watch.log`，并在达到大小限制后轮换。
日志会过滤：

- 密码及完整用户名。
- Cookie、Token、ticket、sessionId 和 Authorization。
- 完整 IP、MAC 和请求正文。

提交 Issue 前仍请人工检查日志，并删除任何不希望公开的信息。

## 开发

安装开发版本并运行离线测试：

```powershell
python -m pip install -e .
python -m compileall src tests
python -m unittest discover -s tests -v
```

测试不会访问真实认证站，也不会使用真实凭据。

构建单文件 EXE：

```powershell
python -m pip install pyinstaller
.\scripts\build-exe.ps1
```

## 退出码

| 退出码 | 含义 |
| ---: | --- |
| `0` | 正常结束或认证成功 |
| `10` | 缺少凭据 |
| `20` | 连续认证失败 |
| `30` | 认证门户协议发生变化 |
| `40` | 无法配置或连接指定 Wi-Fi |

## 致谢与来源

本项目的燕山大学锐捷 V2 认证协议流程及部分实现思路参考了
[KamijoToma/YSUNetLoginv2](https://github.com/KamijoToma/YSUNetLoginv2)，
感谢作者 **SkyRain / KamijoToma** 对新版认证流程进行研究并公开实现。

YSU Net Watch 在此基础上重新组织并扩展了 Windows 凭据管理、Wi-Fi
连接验证、持续监听、两阶段掉线确认、定时器、旧设备下线、安全重定向
检查和日志脱敏等能力。第三方来源与许可证说明见
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 许可证

本项目采用 [MIT License](LICENSE)。第三方代码或实现思路仍受其各自许可
条款约束。
