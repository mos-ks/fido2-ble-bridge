"""Terminal questions for `fido2-ble-bridge setup`, behind a protocol tests can script."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol


class Console(Protocol):
    def say(self, text: str = "") -> None: ...

    def ask(self, prompt: str) -> str:
        """One line of input; an empty string when there is no input (end of file)."""


class TerminalConsole:
    def say(self, text: str = "") -> None:
        print(text, flush=True)

    def ask(self, prompt: str) -> str:
        try:
            return input(prompt)
        except EOFError:
            print(flush=True)
            return ""


def device_name(name: str | None, limit: int = 40) -> str:
    """A Bluetooth device name, safe to print.

    The name comes from radio advertisements, so anyone nearby picks it. Every character that
    is not printable (escape sequences, carriage returns, bidi overrides) becomes "?", so a name
    cannot rewrite the terminal or forge lines of a list, and long names are cut short.
    """
    cleaned = "".join(char if char.isprintable() else "?" for char in name or "")
    return cleaned[:limit] or "(no name)"


def confirm(console: Console, question: str, *, default: bool) -> bool:
    answer = console.ask(f"{question} {'[Y/n]' if default else '[y/N]'} ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def choose(console: Console, question: str, options: Sequence[str]) -> int | None:
    """The index of the option picked, or None when the answer is empty or not an option."""
    for number, option in enumerate(options, 1):
        console.say(f"    {number}) {option}")
    answer = console.ask(f"{question} [1-{len(options)}, Enter to stop] ").strip()
    if answer.isdigit() and 1 <= int(answer) <= len(options):
        return int(answer) - 1
    return None
