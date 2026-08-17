#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SoulTunnel (stu) - Linux 设备间数据对拷工具
支持局域网/公网传输，模块化选择系统配置、用户数据、软件包列表等，
敏感数据（如 SSH/GPG 密钥）强制使用 GPG 加密并通过带外方式交换公钥。
"""

import os
import sys
import json
import yaml
import shutil
import subprocess
import argparse
import tempfile
import getpass
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

# 依赖第三方库，若未安装则提示安装
try:
    from rich.console import Console
    from rich.tree import Tree
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.text import Text
    from rich import print as rprint
except ImportError:
    print("请先安装 rich: pip install rich")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("请先安装 pyyaml: pip install pyyaml")
    sys.exit(1)

# ==================== 日志配置 ====================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("stu")
console = Console()

# ==================== 常量与配置 ====================
CONFIG_DIR = Path.home() / ".config" / "stu"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
RECV_BASE_DIR = Path.home() / ".cache" / "stu_recv"
GPG_TEMP_HOME = Path(tempfile.gettempdir()) / "stu_gpg_home"

DEFAULT_TUNNEL = "tailscale"   # 默认公网隧道后端
SUPPORTED_TUNNELS = ["tailscale", "devtunnel", "easytier"]

# ==================== 数据类 ====================
class ModuleType(Enum):
    SYNC_DIR = "sync_dir"
    SYNC_FILE = "sync_file"
    GEN_LIST = "gen_list"
    EXEC_CMD = "exec_cmd"

@dataclass
class Module:
    id: str
    name: str
    type: ModuleType
    source: str
    dest: str
    pre_cmd: Optional[str] = None
    post_cmd: Optional[str] = None
    risk: str = "low"   # low, medium, high
    encrypt: bool = False  # 是否强制加密（用于 secrets）
    sub_items: List[str] = field(default_factory=list)  # 用于可复选的子路径

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type.value,
            "source": self.source,
            "dest": self.dest,
            "pre_cmd": self.pre_cmd,
            "post_cmd": self.post_cmd,
            "risk": self.risk,
            "encrypt": self.encrypt,
            "sub_items": self.sub_items,
        }

# ==================== 模块仓库 ====================
def get_system_modules() -> List[Module]:
    """返回系统相关的模块定义"""
    modules = []
    # 常见 /etc 配置子项（用于 sys.other）
    etc_sub = [
        "ssh/", "samba/", "sudoers.d/", "apt/sources.list", "cron.d/", "crontab",
        "logrotate.d/", "sysctl.d/", "nginx/", "apache2/", "fail2ban/",
        "network/", "netplan/", "environment", "profile", "modules-load.d/"
    ]
    modules.append(Module(
        id="sys.grub",
        name="Grub 配置",
        type=ModuleType.SYNC_DIR,
        source="/etc/default/grub",
        dest="/etc/default/grub",
        post_cmd="update-grub",
        risk="medium"
    ))
    modules.append(Module(
        id="sys.fstab",
        name="fstab (⚠️ 高风险)",
        type=ModuleType.SYNC_FILE,
        source="/etc/fstab",
        dest="/etc/fstab",
        risk="high"
    ))
    modules.append(Module(
        id="sys.time",
        name="时间和日期",
        type=ModuleType.EXEC_CMD,
        source="",
        dest="",
        pre_cmd="timedatectl show",
        post_cmd="timedatectl set-timezone {timezone} && timedatectl set-time {time}"
    ))
    modules.append(Module(
        id="sys.hosts",
        name="Hosts 和网关",
        type=ModuleType.SYNC_DIR,
        source="/etc/hosts",
        dest="/etc/hosts",
        risk="medium"
    ))
    modules.append(Module(
        id="sys.systemd",
        name="Systemd 服务",
        type=ModuleType.SYNC_DIR,
        source="/etc/systemd/system/",
        dest="/etc/systemd/system/",
        post_cmd="systemctl daemon-reload"
    ))
    modules.append(Module(
        id="sys.other",
        name="其他 /etc 配置",
        type=ModuleType.SYNC_DIR,
        source="/etc/",
        dest="/etc/",
        sub_items=etc_sub,
        risk="medium"
    ))
    modules.append(Module(
        id="pkg.list",
        name="软件包列表",
        type=ModuleType.GEN_LIST,
        source="",
        dest="",
        pre_cmd="dpkg --get-selections > /tmp/pkglist.txt",
        post_cmd="dpkg --set-selections < /tmp/pkglist.txt && apt-get dselect-upgrade -y"
    ))
    # 全局数据（/usr/share）子文件夹示例
    usr_sub = ["fonts/", "icons/", "themes/", "applications/", "wallpapers/"]
    modules.append(Module(
        id="global.data",
        name="/usr/share 数据",
        type=ModuleType.SYNC_DIR,
        source="/usr/share/",
        dest="/usr/share/",
        sub_items=usr_sub,
        risk="medium"
    ))
    return modules

def get_user_modules(username: str) -> List[Module]:
    """返回指定用户的模块定义"""
    home = Path(f"/home/{username}")
    if not home.exists():
        return []
    modules = []
    # 用户配置
    modules.append(Module(
        id=f"user.{username}.config",
        name="用户配置 (.config)",
        type=ModuleType.SYNC_DIR,
        source=str(home / ".config"),
        dest=str(home / ".config"),
        risk="low"
    ))
    # 用户数据
    modules.append(Module(
        id=f"user.{username}.local",
        name="数据文件 (.local/share)",
        type=ModuleType.SYNC_DIR,
        source=str(home / ".local/share"),
        dest=str(home / ".local/share"),
        risk="low"
    ))
    # XDG 标准文件夹
    xdg_dirs = ["Documents", "Downloads", "Music", "Pictures", "Videos", "Desktop"]
    modules.append(Module(
        id=f"user.{username}.xdg",
        name="XDG 标准文件夹",
        type=ModuleType.SYNC_DIR,
        source=str(home),
        dest=str(home),
        sub_items=xdg_dirs,
        risk="low"
    ))
    # Agent 工作区
    agent_dirs = [".memory", ".openclaw", ".qwenpaw", ".cursor", ".codeium"]
    modules.append(Module(
        id=f"user.{username}.agents",
        name="Agent 工作区",
        type=ModuleType.SYNC_DIR,
        source=str(home),
        dest=str(home),
        sub_items=agent_dirs,
        risk="low"
    ))
    # 敏感身份文件（强制加密）
    secret_sub = [".ssh/", ".gnupg/", ".aws/", ".azure/", ".kube/", ".docker/config.json", ".config/gcloud/"]
    modules.append(Module(
        id=f"user.{username}.secrets",
        name="🔐 身份文件和密钥 (默认不选)",
        type=ModuleType.SYNC_DIR,
        source=str(home),
        dest=str(home),
        sub_items=secret_sub,
        risk="high",
        encrypt=True
    ))
    # 包管理器列表
    pkg_managers = [
        ("npm", "npm list -g --depth=0 --json > /tmp/npm_global.json"),
        ("pnpm", "pnpm list -g --depth=0 --json > /tmp/pnpm_global.json"),
        ("bun", "bun pm list -g --json > /tmp/bun_global.json"),
        ("yarn", "yarn global list --json > /tmp/yarn_global.json")
    ]
    for mgr, cmd in pkg_managers:
        modules.append(Module(
            id=f"user.{username}.{mgr}",
            name=f"{mgr} 全局包列表",
            type=ModuleType.GEN_LIST,
            source="",
            dest="",
            pre_cmd=cmd,
            post_cmd=f"{mgr} install -g $(cat /tmp/{mgr}_global_list.txt)"
        ))
    return modules

def get_all_modules() -> List[Module]:
    """获取所有可用模块（系统 + 所有用户）"""
    modules = get_system_modules()
    # 扫描 /home 下的用户目录（排除 root 等）
    for user_dir in Path("/home").iterdir():
        if user_dir.is_dir() and user_dir.name not in ["lost+found", "snap"]:
            modules.extend(get_user_modules(user_dir.name))
    return modules

# ==================== 配置管理 ====================
def load_config() -> Dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}

def save_config(config: Dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(config, f)

# ==================== 交互式选择器 ====================
def interactive_select_modules(modules: List[Module]) -> List[Module]:
    """使用 rich 树形选择器让用户勾选模块"""
    # 构建树
    tree = Tree("📦 选择要传输的数据 (空格切换选中，回车确认)")
    # 按类别组织
    sys_node = tree.add("系统数据与软件")
    user_node = tree.add("用户文件与内包")

    # 存储每个模块对应的选中状态
    selected_ids = set()

    # 用于递归添加
    def add_module_to_tree(parent, mod: Module, depth=0):
        # 显示名称，加上风险标记
        label = mod.name
        if mod.risk == "high":
            label += " ⚠️"
        if mod.encrypt:
            label += " 🔐"
        # 如果有子项，则作为可展开节点
        if mod.sub_items:
            node = parent.add(f"[{'x' if mod.id in selected_ids else ' '}] {label}")
            for sub in mod.sub_items:
                sub_mod = Module(
                    id=f"{mod.id}.{sub}",
                    name=sub,
                    type=mod.type,
                    source=str(Path(mod.source) / sub),
                    dest=str(Path(mod.dest) / sub),
                    risk=mod.risk,
                    encrypt=mod.encrypt
                )
                add_module_to_tree(node, sub_mod, depth+1)
        else:
            # 叶子节点，可勾选
            checkbox = f"[{'x' if mod.id in selected_ids else ' '}]"
            parent.add(f"{checkbox} {label}")
        return

    # 分类添加
    for mod in modules:
        if mod.id.startswith("sys.") or mod.id.startswith("pkg.") or mod.id.startswith("global."):
            add_module_to_tree(sys_node, mod)
        elif mod.id.startswith("user."):
            add_module_to_tree(user_node, mod)

    # 由于rich树不支持交互，我们使用简化的交互：先打印树，然后让用户输入要选中的id
    # 实际项目可用 prompt_toolkit 实现，这里使用多次 Prompt 方式
    console.print(tree)
    console.print("\n[bold yellow]交互选择说明：[/]")
    console.print("输入模块ID（如 sys.grub）可切换选中状态，输入 'done' 结束选择。")
    console.print("输入 'list' 查看所有模块ID。")

    all_ids = {mod.id for mod in modules}
    # 展开子项id也加入
    for mod in modules:
        if mod.sub_items:
            for sub in mod.sub_items:
                all_ids.add(f"{mod.id}.{sub}")

    while True:
        choice = Prompt.ask("请输入模块ID或命令", default="done")
        if choice.lower() == "done":
            break
        elif choice.lower() == "list":
            for mod in modules:
                console.print(f"  {mod.id}: {mod.name}")
            continue
        elif choice in all_ids:
            if choice in selected_ids:
                selected_ids.remove(choice)
                console.print(f"[red]取消选中 {choice}[/]")
            else:
                # 检查是否是高风险且未加密，需要确认
                mod = next((m for m in modules if m.id == choice), None)
                if mod and mod.risk == "high" and not mod.encrypt:
                    if not Confirm.ask(f"[bold red]高风险模块 {choice}，确认选中？[/]"):
                        continue
                selected_ids.add(choice)
                console.print(f"[green]选中 {choice}[/]")
        else:
            console.print(f"[red]未知模块ID: {choice}[/]")

    # 根据选中的id过滤模块（包括子项）
    final_modules = []
    for mod in modules:
        if mod.id in selected_ids:
            final_modules.append(mod)
        elif mod.sub_items:
            # 检查子项是否被选中
            for sub in mod.sub_items:
                sub_id = f"{mod.id}.{sub}"
                if sub_id in selected_ids:
                    # 创建一个新模块表示子项
                    sub_mod = Module(
                        id=sub_id,
                        name=f"{mod.name} - {sub}",
                        type=mod.type,
                        source=str(Path(mod.source) / sub),
                        dest=str(Path(mod.dest) / sub),
                        risk=mod.risk,
                        encrypt=mod.encrypt
                    )
                    final_modules.append(sub_mod)
    return final_modules

# ==================== GPG 加密处理 ====================
def get_gpg_public_key() -> Optional[str]:
    """交互式获取用于加密的公钥，返回密钥指纹"""
    console.print("[bold yellow]🔐 选择 GPG 公钥用于加密敏感数据[/]")
    # 列出已有的公钥
    try:
        result = subprocess.run(
            ["gpg", "--list-public-keys", "--with-colons", "--fingerprint"],
            capture_output=True, text=True, check=True
        )
        lines = result.stdout.splitlines()
        # 简单解析，提取fingerprint和uid
        keys = []
        current_fpr = None
        for line in lines:
            if line.startswith("fpr:"):
                parts = line.split(":")
                if len(parts) >= 10:
                    current_fpr = parts[9]
            elif line.startswith("uid:") and current_fpr:
                uid = ":".join(line.split(":")[9:])
                keys.append((current_fpr, uid))
                current_fpr = None
    except Exception as e:
        logger.warning(f"无法列出 GPG 公钥: {e}")
        keys = []

    if keys:
        console.print("可用的公钥：")
        for idx, (fpr, uid) in enumerate(keys, 1):
            console.print(f"  {idx}. {uid} (指纹: {fpr[:16]}...)")
        choice = IntPrompt.ask("选择现有公钥序号 (0 取消)", default=0)
        if choice > 0 and choice <= len(keys):
            return keys[choice-1][0]

    # 如果没有或用户选择生成
    if Confirm.ask("未选择现有公钥，是否生成临时密钥对？", default=True):
        return generate_temporary_gpg_key()
    else:
        # 手动指定公钥文件
        path = Prompt.ask("请输入公钥文件路径 (.asc 或 .pgp)")
        if path and Path(path).exists():
            # 导入公钥到临时 homedir
            temp_home = GPG_TEMP_HOME
            temp_home.mkdir(exist_ok=True)
            try:
                subprocess.run(
                    ["gpg", "--homedir", str(temp_home), "--import", path],
                    check=True, capture_output=True
                )
                # 获取指纹
                result = subprocess.run(
                    ["gpg", "--homedir", str(temp_home), "--list-public-keys", "--with-colons", "--fingerprint"],
                    capture_output=True, text=True, check=True
                )
                for line in result.stdout.splitlines():
                    if line.startswith("fpr:"):
                        fpr = line.split(":")[9]
                        return fpr
            except Exception as e:
                logger.error(f"导入公钥失败: {e}")
                return None
    return None

def generate_temporary_gpg_key() -> Optional[str]:
    """生成临时 GPG 密钥对，返回公钥指纹"""
    temp_home = GPG_TEMP_HOME
    temp_home.mkdir(exist_ok=True)
    # 生成配置文件
    batch_config = f"""
%echo Generating a temporary key
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: SoulTunnel Temporary
Name-Email: stu@temporary
Expire-Date: 0
%commit
%echo done
"""
    batch_file = temp_home / "batch.txt"
    batch_file.write_text(batch_config)
    try:
        subprocess.run(
            ["gpg", "--homedir", str(temp_home), "--batch", "--gen-key", str(batch_file)],
            check=True, capture_output=True
        )
        # 导出公钥
        pub_file = temp_home / "public_key.asc"
        subprocess.run(
            ["gpg", "--homedir", str(temp_home), "--armor", "--export", "SoulTunnel Temporary"],
            stdout=open(pub_file, 'w'), check=True
        )
        console.print(f"[green]临时密钥对生成成功！[/]")
        console.print(f"公钥已导出至: {pub_file}")
        console.print("[bold yellow]请将此公钥文件通过带外方式发送给目标端！[/]")
        # 获取指纹
        result = subprocess.run(
            ["gpg", "--homedir", str(temp_home), "--list-public-keys", "--with-colons", "--fingerprint"],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            if line.startswith("fpr:"):
                fpr = line.split(":")[9]
                return fpr
    except Exception as e:
        logger.error(f"生成临时密钥失败: {e}")
        return None
    return None

def encrypt_file_with_gpg(file_path: Path, fingerprint: str, output_path: Path) -> bool:
    """使用指定公钥加密文件，输出到 output_path.gpg"""
    temp_home = GPG_TEMP_HOME
    temp_home.mkdir(exist_ok=True)
    try:
        cmd = [
            "gpg", "--homedir", str(temp_home),
            "--recipient", fingerprint,
            "--encrypt", "--armor",
            "--output", str(output_path),
            str(file_path)
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except Exception as e:
        logger.error(f"加密失败: {e}")
        return False

def decrypt_file_with_gpg(encrypted_path: Path, output_path: Path) -> bool:
    """使用本地私钥解密 GPG 文件（接收端调用）"""
    try:
        # 使用默认 homedir（用户自己的密钥环）
        cmd = ["gpg", "--decrypt", "--output", str(output_path), str(encrypted_path)]
        subprocess.run(cmd, check=True)
        return True
    except Exception as e:
        logger.error(f"解密失败: {e}")
        return False

# ==================== 传输引擎 ====================
class Transport:
    def __init__(self, dst: str, user: str = None, mode: str = "lan", tunnel: str = "tailscale"):
        self.dst = dst
        self.user = user or getpass.getuser()
        self.mode = mode
        self.tunnel = tunnel
        self.ssh_cmd = self._build_ssh_cmd()

    def _build_ssh_cmd(self) -> str:
        if self.mode == "lan":
            return f"ssh -o StrictHostKeyChecking=no -l {self.user} {self.dst}"
        else:
            # 公网模式：依赖隧道工具提供可路由的地址
            # 实际上，隧道工具会创建虚拟网卡，直接使用隧道 IP
            # 这里我们假设 dst 已经是隧道可解析的地址（如 tailscale 的 IP 或 hostname）
            return f"ssh -o StrictHostKeyChecking=no -l {self.user} {self.dst}"

    def rsync(self, src: str, dst_path: str, options: List[str] = None) -> bool:
        """执行 rsync 同步"""
        options = options or ["-avzP"]
        cmd = ["rsync"] + options + ["-e", self.ssh_cmd, src, f"{self.user}@{self.dst}:{dst_path}"]
        logger.info(f"执行: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"rsync 失败: {e}")
            return False

    def exec_cmd(self, cmd: str) -> bool:
        """在远程主机执行命令（通过 ssh）"""
        full_cmd = f"ssh -l {self.user} {self.dst} '{cmd}'"
        try:
            subprocess.run(full_cmd, shell=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def send_file(self, local_path: Path, remote_path: str) -> bool:
        """发送单个文件（通过 scp 或 rsync）"""
        return self.rsync(str(local_path), remote_path, options=["-P"])

def get_transport(dst: str, user: str = None, mode: str = "auto", tunnel: str = "tailscale") -> Transport:
    """工厂方法：根据模式和目标返回传输对象"""
    if mode == "auto":
        # 尝试判断是否局域网：ping 私有IP或主机名
        # 简单检测：若 dst 是 IP 且以 192.168. 或 10. 开头，视为局域网
        if dst.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                           "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                           "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                           "172.30.", "172.31.")):
            mode = "lan"
        else:
            mode = "wan"  # 默认公网
    return Transport(dst, user, mode, tunnel)

# ==================== 发送端主流程 ====================
def send(args):
    """发送端逻辑"""
    console.print("[bold cyan]SoulTunnel 发送模式[/]")
    # 加载配置
    config = load_config()
    # 获取所有模块
    all_modules = get_all_modules()
    selected = []
    if args.preset:
        # 从预设文件加载
        with open(args.preset, 'r') as f:
            preset_ids = json.load(f)
        selected = [mod for mod in all_modules if mod.id in preset_ids]
    else:
        selected = interactive_select_modules(all_modules)

    if not selected:
        console.print("[red]未选择任何数据，退出。[/]")
        return

    # 检查是否有敏感模块需要加密
    encrypt_modules = [mod for mod in selected if mod.encrypt]
    gpg_fingerprint = None
    if encrypt_modules:
        console.print("[bold yellow]选中的模块包含敏感数据，必须加密传输。[/]")
        gpg_fingerprint = get_gpg_public_key()
        if not gpg_fingerprint:
            console.print("[red]无法获取 GPG 公钥，终止传输。[/]")
            return

    # 确定目标地址
    dst = args.dst
    user = args.user or getpass.getuser()
    mode = args.mode or "auto"
    tunnel = args.tunnel or DEFAULT_TUNNEL

    transport = get_transport(dst, user, mode, tunnel)

    # 准备临时目录用于打包加密
    tmp_dir = Path(tempfile.mkdtemp(prefix="stu_send_"))
    console.print(f"[dim]临时目录: {tmp_dir}[/]")

    # 对每个选中的模块执行同步
    success = True
    with Progress() as progress:
        task = progress.add_task("[green]正在传输...", total=len(selected))
        for mod in selected:
            progress.update(task, description=f"处理 {mod.id}")
            # 处理加密
            if mod.encrypt and gpg_fingerprint:
                # 打包源路径
                src_path = Path(mod.source)
                if not src_path.exists():
                    logger.warning(f"源路径不存在: {src_path}")
                    progress.advance(task)
                    continue
                # 创建 tar 包
                tar_name = f"{mod.id.replace('.', '_')}.tar.gz"
                tar_path = tmp_dir / tar_name
                try:
                    subprocess.run(["tar", "-czf", str(tar_path), "-C", str(src_path.parent), src_path.name],
                                   check=True, capture_output=True)
                except Exception as e:
                    logger.error(f"打包失败: {e}")
                    success = False
                    progress.advance(task)
                    continue
                # 加密
                enc_path = tmp_dir / f"{tar_name}.gpg"
                if not encrypt_file_with_gpg(tar_path, gpg_fingerprint, enc_path):
                    logger.error(f"加密失败: {mod.id}")
                    success = False
                    progress.advance(task)
                    continue
                # 传输加密文件到接收端的缓存目录
                remote_dir = f"{RECV_BASE_DIR}/{mod.id}/"
                if not transport.send_file(enc_path, remote_dir):
                    logger.error(f"传输失败: {mod.id}")
                    success = False
                # 同时传输一个 metadata 文件，注明需要解密
                meta = {"id": mod.id, "encrypted": True, "fingerprint": gpg_fingerprint}
                meta_file = tmp_dir / f"{mod.id}.meta"
                meta_file.write_text(json.dumps(meta))
                transport.send_file(meta_file, f"{RECV_BASE_DIR}/{mod.id}/")

            else:
                # 非加密模块：直接 rsync
                src = mod.source
                dest = mod.dest
                if mod.type == ModuleType.GEN_LIST:
                    # 在本地生成列表文件
                    list_file = tmp_dir / f"{mod.id}.list"
                    try:
                        subprocess.run(mod.pre_cmd, shell=True, check=True)
                        # 假设列表生成在 /tmp/ 下特定文件，这里需根据实际情况调整
                        # 简化：执行 pre_cmd，然后传输该文件，在目标端执行 post_cmd
                        # 我们约定 pre_cmd 生成 /tmp/{mod.id}.list
                        gen_file = Path(f"/tmp/{mod.id}.list")
                        if gen_file.exists():
                            shutil.copy(gen_file, list_file)
                            transport.send_file(list_file, f"{RECV_BASE_DIR}/{mod.id}/")
                            # 目标端执行安装命令
                            transport.exec_cmd(mod.post_cmd)
                        else:
                            logger.warning(f"未找到列表文件 {gen_file}")
                    except Exception as e:
                        logger.error(f"处理列表 {mod.id} 失败: {e}")
                        success = False
                elif mod.type == ModuleType.EXEC_CMD:
                    # 执行命令，假设 pre_cmd 采集信息，post_cmd 在目标端执行
                    # 简单起见，我们在本地执行 pre_cmd（如获取时区），然后通过参数传递
                    # 更鲁棒：将 pre_cmd 输出保存，传输给目标端，目标端解析后执行 post_cmd
                    # 这里简化实现，仅发送一个标记
                    transport.exec_cmd(mod.post_cmd)
                else:
                    # sync_dir / sync_file
                    # 如果有子项，只传输选中的子项
                    if mod.sub_items:
                        # 每个子项是单独模块，已展开为独立模块，所以这里直接传输 source
                        pass
                    if not transport.rsync(src, dest):
                        logger.error(f"传输失败: {mod.id}")
                        success = False
            progress.advance(task)

    console.print("[bold green]传输完成！[/]" if success else "[bold red]部分传输失败。[/]")

    # 清理临时目录
    shutil.rmtree(tmp_dir, ignore_errors=True)

# ==================== 接收端主流程 ====================
def receive(args):
    """接收端逻辑：检查 ~/.cache/stu_recv/，解密并安装"""
    console.print("[bold cyan]SoulTunnel 接收模式[/]")
    recv_dir = RECV_BASE_DIR
    if not recv_dir.exists():
        console.print("[yellow]没有待处理的数据。[/]")
        return

    # 扫描所有子目录
    items = [p for p in recv_dir.iterdir() if p.is_dir()]
    if not items:
        console.print("[yellow]没有待处理的数据。[/]")
        return

    # 显示待处理列表
    table = Table(title="待处理的传输包")
    table.add_column("模块ID", style="cyan")
    table.add_column("状态")
    for p in items:
        meta_file = p / f"{p.name}.meta"
        if meta_file.exists():
            meta = json.loads(meta_file.read_text())
            status = "🔐 已加密" if meta.get("encrypted") else "📦 未加密"
        else:
            status = "❓ 未知"
        table.add_row(p.name, status)
    console.print(table)

    # 让用户选择处理哪个模块
    choice = Prompt.ask("输入要处理的模块ID (或 'all' 处理全部, 'quit' 退出)", default="quit")
    if choice.lower() == "quit":
        return
    target_ids = []
    if choice.lower() == "all":
        target_ids = [p.name for p in items]
    else:
        target_ids = [choice]

    for mod_id in target_ids:
        mod_dir = recv_dir / mod_id
        if not mod_dir.exists():
            console.print(f"[red]模块 {mod_id} 不存在[/]")
            continue
        # 检查是否有元数据
        meta_file = mod_dir / f"{mod_id}.meta"
        if not meta_file.exists():
            console.print(f"[yellow]模块 {mod_id} 缺少元数据，跳过[/]")
            continue
        meta = json.loads(meta_file.read_text())
        if meta.get("encrypted"):
            # 需要解密
            enc_files = list(mod_dir.glob("*.gpg"))
            if not enc_files:
                console.print(f"[red]模块 {mod_id} 标记为加密但未找到 .gpg 文件[/]")
                continue
            # 解密
            for enc_file in enc_files:
                output_file = enc_file.with_suffix('')  # 去掉 .gpg
                console.print(f"[yellow]解密 {enc_file.name} ...[/]")
                if decrypt_file_with_gpg(enc_file, output_file):
                    # 解压 tar
                    if output_file.suffix == '.gz':
                        extract_dir = mod_dir / "extracted"
                        extract_dir.mkdir(exist_ok=True)
                        try:
                            subprocess.run(["tar", "-xzf", str(output_file), "-C", str(extract_dir)],
                                           check=True)
                            console.print(f"[green]解压成功到 {extract_dir}[/]")
                            # 尝试安装：如果是系统配置，可能需要 sudo
                            # 检查文件是否包含 /etc 等，提示用户
                            if Confirm.ask(f"是否将解压的文件安装到系统？(可能需要 sudo)", default=False):
                                # 使用 rsync 或 cp 复制到实际位置
                                # 这里简单提示用户手动安装
                                console.print("[yellow]请手动检查并执行安装，例如：")
                                console.print(f"  sudo rsync -av {extract_dir}/ /")
                        except Exception as e:
                            logger.error(f"解压失败: {e}")
                    else:
                        console.print(f"[yellow]未知归档格式: {output_file}")
                else:
                    console.print(f"[red]解密失败 {enc_file.name}[/]")
        else:
            # 未加密，直接复制或提示
            console.print(f"[green]模块 {mod_id} 未加密，可以直接使用。[/]")
            # 可在此实现自动安装

    # 清理已处理的包（可选）
    if Confirm.ask("是否删除已处理的临时文件？", default=True):
        for mod_id in target_ids:
            shutil.rmtree(recv_dir / mod_id, ignore_errors=True)

# ==================== 主命令解析 ====================
def main():
    parser = argparse.ArgumentParser(description="SoulTunnel - Linux 设备间数据对拷工具")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # send 子命令
    send_parser = subparsers.add_parser("send", help="发送数据到目标设备")
    send_parser.add_argument("--dst", required=True, help="目标设备地址（IP或主机名）")
    send_parser.add_argument("--user", help="远程用户名")
    send_parser.add_argument("--mode", choices=["lan", "wan", "auto"], default="auto",
                             help="传输模式 (默认 auto)")
    send_parser.add_argument("--tunnel", choices=SUPPORTED_TUNNELS, default=DEFAULT_TUNNEL,
                             help="公网隧道后端 (默认 tailscale)")
    send_parser.add_argument("--preset", help="预设配置文件路径 (JSON)")
    send_parser.add_argument("--dry-run", action="store_true", help="仅预览不执行")
    send_parser.add_argument("--verbose", action="store_true", help="显示详细日志")

    # receive 子命令
    recv_parser = subparsers.add_parser("receive", help="接收并处理传入的数据")
    recv_parser.add_argument("--dry-run", action="store_true", help="仅显示待处理项")
    recv_parser.add_argument("--verbose", action="store_true", help="显示详细日志")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.command == "send":
        if args.dry_run:
            console.print("[yellow]Dry-run 模式，仅显示将要执行的模块[/]")
            # 显示选中的模块
            all_modules = get_all_modules()
            if args.preset:
                with open(args.preset, 'r') as f:
                    preset_ids = json.load(f)
                selected = [mod for mod in all_modules if mod.id in preset_ids]
            else:
                selected = interactive_select_modules(all_modules)
            for mod in selected:
                console.print(f"  {mod.id} ({mod.name})")
            return
        send(args)
    elif args.command == "receive":
        if args.dry_run:
            recv_dir = RECV_BASE_DIR
            if recv_dir.exists():
                items = [p for p in recv_dir.iterdir() if p.is_dir()]
                console.print("[yellow]待处理的模块：[/]")
                for p in items:
                    console.print(f"  {p.name}")
            else:
                console.print("[yellow]没有待处理数据[/]")
            return
        receive(args)

if __name__ == "__main__":
    main()
