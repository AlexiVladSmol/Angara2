#!/usr/bin/env python3
"""PTY harness for the M11 terminal panel: render, search, resize, quit."""

import argparse
import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time


def read_until(fd, marker, timeout):
    output = b""
    deadline = time.monotonic() + timeout
    while marker not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timeout waiting for {marker!r}; got {output[-4000:]!r}")
        ready, _, _ = select.select([fd], [], [], min(remaining, 0.5))
        if not ready:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        output += chunk
    return output


def read_rest(fd, timeout):
    output = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        output += chunk
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--mode", choices=["connected", "disconnected"], required=True)
    args = parser.parse_args()

    os.environ["TERM"] = "xterm-256color"
    pid, master = pty.fork()
    if pid == 0:
        try:
            os.execv(args.binary, [args.binary, "tui", "--socket", args.socket])
        except OSError as error:
            print(f"exec failed: {error}", file=sys.stderr)
            os._exit(127)

    output = b""
    reaped = False
    try:
        fcntl.ioctl(
            master,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", 32, 120, 0, 0),
        )
        try:
            os.kill(pid, signal.SIGWINCH)
        except OSError:
            pass
        output += read_until(master, b"Angara", 15)
        if args.mode == "connected":
            output += read_until(master, "Пользователи".encode(), 10)
            os.write(master, b"4")
            time.sleep(0.4)
            os.write(master, b"/")
            time.sleep(0.2)
            os.write(master, b"ali")
            time.sleep(0.2)
            os.write(master, b"\r")
            time.sleep(0.4)
            # Resize to the narrow layout and then back to the wide layout.
            for columns, rows in [(80, 24), (132, 40), (90, 30)]:
                fcntl.ioctl(
                    master,
                    termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, columns, 0, 0),
                )
                try:
                    os.kill(pid, signal.SIGWINCH)
                except OSError:
                    pass
                time.sleep(0.4)
            output += read_until(master, b"?", 10)
            os.write(master, b"?")
            time.sleep(0.4)
            os.write(master, b"\x1b")
            time.sleep(0.2)
        else:
            output += read_until(master, "нет связи".encode(), 10)
        os.write(master, b"q")
        time.sleep(0.5)
        output += read_rest(master, 5)
        _, status = os.waitpid(pid, 0)
        reaped = True
        code = os.waitstatus_to_exitcode(status)
    finally:
        try:
            os.close(master)
        except OSError:
            pass
        if not reaped and os.waitpid(pid, os.WNOHANG) == (0, 0):
            os.kill(pid, 9)
            os.waitpid(pid, 0)

    text = output.decode("utf-8", "replace")
    if code != 0:
        print(f"tui exited {code}: {text[-4000:]!r}", file=sys.stderr)
        return 3
    if "Angara" not in text:
        print(f"missing header: {text[-4000:]!r}", file=sys.stderr)
        return 4
    if args.mode == "connected":
        if "Пользователи" not in text:
            print(f"missing users screen: {text[-4000:]!r}", file=sys.stderr)
            return 5
        if "\x1b[?1049l" not in text and "\x1b[?1049h" not in text:
            print(f"alternate screen not used: {text[-2000:]!r}", file=sys.stderr)
            return 6
    else:
        if "нет связи" not in text:
            print(f"missing disconnected banner: {text[-4000:]!r}", file=sys.stderr)
            return 7
    print("TUI_PTY_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
