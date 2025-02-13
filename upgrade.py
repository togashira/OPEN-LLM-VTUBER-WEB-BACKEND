#!/usr/bin/env python3
import os
import sys
import ctypes
import shutil
import locale
import platform
import subprocess
from merge_configs import merge_configs
from datetime import datetime


# Define basic terminal color codes
class Colors:
    """Cross-platform terminal color support"""

    def __init__(self):
        self.use_colors = sys.platform != "win32" or os.environ.get("TERM")

    def red(self, text):
        return f"\033[91m{text}\033[0m" if self.use_colors else text

    def green(self, text):
        return f"\033[92m{text}\033[0m" if self.use_colors else text

    def yellow(self, text):
        return f"\033[93m{text}\033[0m" if self.use_colors else text

    def cyan(self, text):
        return f"\033[96m{text}\033[0m" if self.use_colors else text


# Initialize colors
colors = Colors()

# 语言字典 / Language dictionary
TEXTS = {
    "zh": {
        "welcome_message": "Auto-Upgrade Script v.0.1.0\nOpen-LLM-VTuber 升级脚本 - 此脚本仍在实验阶段，可能无法按预期工作。",
        "lang_select": "请选择语言/Please select language (zh/en):",
        "invalid_lang": "无效的语言选择，使用英文作为默认语言",
        "not_git_repo": "错误：当前目录不是git仓库。请进入 Open-LLM-VTuber 目录后再运行此脚本。\n当然，更有可能的是你下载的Open-LLM-VTuber不包含.git文件夹 (如果你是透过下载压缩包而非使用 git clone 命令下载的话可能会造成这种情况)，这种情况下目前无法用脚本升级。",
        "backup_user_config": "正在备份 {user_conf} 到 {backup_conf}",
        "no_config": "警告：未找到conf.yaml文件",
        "copy_default_config": "正在从模板复制默认配置",
        "uncommitted": "发现未提交的更改，正在暂存...",
        "stash_error": "错误：无法暂存更改",
        "changes_stashed": "更改已暂存",
        "pulling": "正在从远程仓库拉取更新...",
        "pull_error": "错误：无法拉取更新",
        "restoring": "正在恢复暂存的更改...",
        "conflict_warning": "警告：恢复暂存的更改时发生冲突",
        "manual_resolve": "请手动解决冲突",
        "stash_list": "你可以使用 'git stash list' 查看暂存的更改",
        "stash_pop": "使用 'git stash pop' 恢复更改",
        "upgrade_complete": "升级完成！",
        "check_config": "1. 请检查conf.yaml是否需要更新",
        "resolve_conflicts": "2. 如果有配置文件冲突，请手动解决",
        "check_backup": "3. 检查备份的配置文件以确保没有丢失重要设置",
        "git_not_found": "错误：未检测到 Git。请先安装 Git:\nWindows: https://git-scm.com/download/win\nmacOS: brew install git\nLinux: sudo apt install git",
        "operation_preview": """
此脚本将执行以下操作：
1. 备份当前的 conf.yaml 配置文件
2. 暂存所有未提交的更改 (git stash)
3. 从远程仓库拉取最新代码 (git pull)
4. 尝试恢复之前暂存的更改 (git stash pop)

是否继续？(y/N): """,
        "abort_upgrade": "升级已取消",
        "merged_config_success": "新增配置项已合并:",
        "merged_config_none": "未发现新增配置项。",
        "merge_failed": "配置合并失败: {error}",
    },
    "en": {
        "welcome_message": "Auto-Upgrade Script v.0.1.0\nOpen-LLM-VTuber upgrade script - This script is highly experimental and may not work as expected.",
        "lang_select": "请选择语言/Please select language (zh/en):",
        "invalid_lang": "Invalid language selection, using English as default",
        "not_git_repo": "Error: Current directory is not a git repository. Please run this script inside the Open-LLM-VTuber directory.\nAlternatively, it is likely that the Open-LLM-VTuber you downloaded does not contain the .git folder (this can happen if you downloaded a zip archive instead of using git clone), in which case you cannot upgrade using this script.",
        "backup_user_config": "Backing up {user_conf} to {backup_conf}",
        "no_config": "Warning: conf.yaml not found",
        "copy_default_config": "Copying default configuration from template",
        "uncommitted": "Found uncommitted changes, stashing...",
        "stash_error": "Error: Unable to stash changes",
        "changes_stashed": "Changes stashed",
        "pulling": "Pulling updates from remote repository...",
        "pull_error": "Error: Unable to pull updates",
        "restoring": "Restoring stashed changes...",
        "conflict_warning": "Warning: Conflicts occurred while restoring stashed changes",
        "manual_resolve": "Please resolve conflicts manually",
        "stash_list": "Use 'git stash list' to view stashed changes",
        "stash_pop": "Use 'git stash pop' to restore changes",
        "upgrade_complete": "Upgrade complete!",
        "check_config": "1. Please check if conf.yaml needs updating",
        "resolve_conflicts": "2. Resolve any config file conflicts manually",
        "check_backup": "3. Check backup config to ensure no important settings are lost",
        "git_not_found": "Error: Git not found. Please install Git first:\nWindows: https://git-scm.com/download/win\nmacOS: brew install git\nLinux: sudo apt install git",
        "operation_preview": """
This script will perform the following operations:
1. Backup current conf.yaml configuration file
2. Stash all uncommitted changes (git stash)
3. Pull latest code from remote repository (git pull)
4. Attempt to restore previously stashed changes (git stash pop)

Continue? (y/N): """,
        "abort_upgrade": "Upgrade aborted",
        "merged_config_success": "Merged new configuration items:",
        "merged_config_none": "No new configuration items found.",
        "merge_failed": "Configuration merge failed: {error}",
    },
}


def get_system_language():
    """Get system language using a combination of methods."""

    # Try to get the current locale
    current_locale = locale.getlocale(locale.LC_ALL)[0]
    if current_locale:
        lang = current_locale.split("_")[0]
        if lang.startswith("zh"):
            return "zh"

    # If locale.getlocale() fails, use platform-specific APIs
    os_name = platform.system()

    if os_name == "Windows":
        try:
            # Use Windows API to get the UI language
            windll = ctypes.windll.kernel32
            ui_lang = windll.GetUserDefaultUILanguage()
            lang_code = locale.windows_locale.get(ui_lang)
            if lang_code:
                lang = lang_code.split("_")[0]
                if lang.startswith("zh"):
                    return "zh"
        except Exception:
            pass

    elif os_name == "Darwin":  # macOS
        try:
            # Use defaults command to get the AppleLocale
            result = subprocess.run(
                ["defaults", "read", "-g", "AppleLocale"],
                capture_output=True,
                text=True,
            )
            lang = result.stdout.strip().split("_")[0]
            if lang.startswith("zh"):
                return "zh"
        except Exception:
            pass

    elif os_name == "Linux":
        # Check the LANG environment variable
        lang = os.environ.get("LANG")
        if lang:
            lang = lang.split("_")[0]
            if lang.startswith("zh"):
                return "zh"

    # Fallback to using locale.getpreferredencoding()
    encoding = locale.getpreferredencoding()
    if encoding.lower() in ("cp936", "gbk", "big5"):
        return "zh"

    return "en"


def select_language():
    """Select language based on command-line argument or system language"""
    if len(sys.argv) > 1 and sys.argv[1].lower() in ["zh", "en"]:
        return sys.argv[1].lower()
    return get_system_language()


def run_command(command):
    """Run shell command and return result"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return (
            False,
            f"Command failed with error code {e.returncode}\nError: {e.stderr}",
        )
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


def check_git_installed():
    """Check if Git is installed"""
    command = "where git" if sys.platform == "win32" else "which git"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.returncode == 0
    except subprocess.SubprocessError:
        return False


def upgrade_config(user_config_path: str, default_config_path: str, lang: str = "en"):
    log_path = f"./logs/upgrade_{datetime.now().strftime('%Y-%m-%d-%H-%M')}.log"
    return merge_configs(
        user_config_path, default_config_path, log_path=log_path, lang=lang
    )


def main():
    global texts
    print(colors.cyan(TEXTS["en"]["welcome_message"]))

    lang = select_language()
    texts = TEXTS[lang]

    # Check if Git is installed
    if not check_git_installed():
        print(colors.red(texts["git_not_found"]))
        sys.exit(1)

    # Show operation preview and request confirmation
    response = input(colors.yellow(texts["operation_preview"])).lower()
    if response != "y":
        print(colors.yellow(texts["abort_upgrade"]))
        sys.exit(0)

    # Check if inside a git repository
    success, error_msg = run_command("git rev-parse --is-inside-work-tree")
    if not success:
        print(colors.red(texts["not_git_repo"]))
        print(colors.red(f"Error details: {error_msg}"))
        sys.exit(1)

    # Check if there are uncommitted changes
    success, changes = run_command("git status --porcelain")
    if not success:
        print(colors.red(f"Failed to check git status: {changes}"))
        sys.exit(1)
    has_changes = bool(changes.strip())

    if has_changes:
        print(colors.yellow(texts["uncommitted"]))
        success, output = run_command("git stash")
        if not success:
            print(colors.red(texts["stash_error"]))
            print(colors.red(f"Error details: {output}"))
            sys.exit(1)
        print(colors.green(texts["changes_stashed"]))

    # Update code
    print(colors.cyan(texts["pulling"]))
    success, output = run_command("git pull")
    if not success:
        print(colors.red(texts["pull_error"]))
        print(colors.red(f"Error details: {output}"))
        if has_changes:
            print(colors.yellow(texts["restoring"]))
            success, restore_output = run_command("git stash pop")
            if not success:
                print(colors.red(f"Failed to restore changes: {restore_output}"))
        sys.exit(1)

    # After successful pull and before restoring stashed changes:
    # Backup and merge configuration
    user_conf = "conf.yaml"
    backup_conf = "conf.yaml.backup"
    default_template = (
        "config_templates/conf.ZH.default.yaml"
        if lang == "zh"
        else "config_templates/conf.default.yaml"
    )

    if os.path.exists(user_conf):
        print(
            colors.cyan(
                texts["backup_user_config"].format(
                    user_conf=user_conf, backup_conf=backup_conf
                )
            )
        )
        shutil.copy2(user_conf, backup_conf)
        # Merge configurations using merge_configs.py module
        try:
            new_keys = upgrade_config(user_conf, default_template, lang=lang)
            if new_keys:
                print(colors.green(texts["merged_config_success"]))
                for key in new_keys:
                    print(colors.green(f"  - {key}"))
            else:
                print(colors.green(texts["merged_config_none"]))
        except Exception as e:
            print(colors.red(texts["merge_failed"].format(error=e)))
    else:
        print(colors.yellow(texts["no_config"]))
        print(colors.yellow(texts["copy_default_config"]))
        shutil.copy2(default_template, user_conf)

    # Restore stashed changes
    if has_changes:
        print(colors.yellow(texts["restoring"]))
        success, output = run_command("git stash pop")
        if not success:
            print(colors.red(texts["conflict_warning"]))
            print(colors.red(f"Error details: {output}"))
            print(colors.yellow(texts["manual_resolve"]))
            print(colors.cyan(texts["stash_list"]))
            print(colors.cyan(texts["stash_pop"]))
            sys.exit(1)

    print(colors.green("\n" + texts["upgrade_complete"]))
    print(colors.cyan(texts["check_config"]))
    print(colors.cyan(texts["resolve_conflicts"]))
    print(colors.cyan(texts["check_backup"]))


if __name__ == "__main__":
    main()
