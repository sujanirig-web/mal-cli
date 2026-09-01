"""
Terminal output formatting.
"""

import sys
from typing import List, Tuple, Union

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback if colorama not installed
    class Fore:
        RED = ''
        GREEN = ''
        YELLOW = ''
        BLUE = ''
        MAGENTA = ''
        CYAN = ''
        WHITE = ''
        RESET = ''
    class Style:
        BRIGHT = ''
        DIM = ''
        NORMAL = ''


class Terminal:
    @staticmethod
    def print_header(text: str):
        print(f"\n{Fore.CYAN}{Style.BRIGHT}=== {text} ==={Style.RESET_ALL}")

    @staticmethod
    def print_subheader(text: str):
        print(f"\n{Fore.BLUE}{Style.BRIGHT}--- {text} ---{Style.RESET_ALL}")

    @staticmethod
    def print_key_value(key: str, value: str):
        print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL} {value}")

    @staticmethod
    def print(text: str):
        print(text)

    @staticmethod
    def print_error(text: str):
        print(f"{Fore.RED}ERROR: {text}{Style.RESET_ALL}")

    @staticmethod
    def print_warning(text: str):
        print(f"{Fore.YELLOW}WARNING: {text}{Style.RESET_ALL}")

    @staticmethod
    def print_success(text: str):
        print(f"{Fore.GREEN}{text}{Style.RESET_ALL}")

    @staticmethod
    def print_table(headers: List[str], rows: List[Tuple], colorize_risk: bool = False, risk_col: int = 2):
        # Compute column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))

        # Print header
        header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
        print(f"{Fore.CYAN}{header_line}{Style.RESET_ALL}")
        print("  ".join("-" * w for w in col_widths))

        # Print rows
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                text = str(cell)
                if colorize_risk and i == risk_col:  # Risk level column
                    if "CRITICAL" in text:
                        text = f"{Fore.RED}{text}{Style.RESET_ALL}"
                    elif "HIGH" in text:
                        text = f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
                    elif "MEDIUM" in text:
                        text = f"{Fore.MAGENTA}{text}{Style.RESET_ALL}"
                    else:
                        text = f"{Fore.GREEN}{text}{Style.RESET_ALL}"
                cells.append(text.ljust(col_widths[i]))
            print("  ".join(cells))