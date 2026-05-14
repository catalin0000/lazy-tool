import sys
import subprocess


class Color:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def color_text(text: str, color: str) -> str:
    """Wrap text in an ANSI color code, stripping it if output is not a terminal."""
    return f"{color}{text}{Color.END}" if sys.stdout.isatty() else text


def is_tool_installed(tool):
    """Check if a system command is available via `which`."""
    try:
        if subprocess.run(['which', tool], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).returncode == 0:
            return True
        return False
    except:
        return False
