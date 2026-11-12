#!/usr/bin/env python3
"""PTY harness for `angara users hash` no-echo and confirmation behavior."""

import argparse
import os
import pty
import re
import select
import sys
import time


def read_until(fd: int, marker: bytes, timeout: float) -> bytes:
    output = b""
    deadline = time.monotonic() + timeout
    while marker not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timeout waiting for {marker!r}; got {output!r}")
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            continue
        chunk = os.read(fd, 4096)
        if not chunk:
            raise EOFError(f"EOF waiting for {marker!r}; got {output!r}")
        output += chunk
    return output


def read_rest(fd: int, timeout: float) -> bytes:
    output = b""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        output += chunk
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--expect-success", action="store_true")
    args = parser.parse_args()

    os.environ["TERM"] = "dumb"
    pid, master = pty.fork()
    if pid == 0:
        try:
            os.execv(args.binary, [args.binary, "users", "hash"])
        except OSError as error:
            print(f"exec failed: {error}", file=sys.stderr)
            os._exit(127)

    output = b""
    reaped = False
    try:
        output += read_until(master, b"Password:", 10)
        time.sleep(0.5)
        os.write(master, args.password.encode("utf-8") + b"\n")
        output += read_until(master, b"Confirm password:", 10)
        time.sleep(0.5)
        os.write(master, args.confirm.encode("utf-8") + b"\n")
        output += read_rest(master, 30)
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
    if args.password in text or args.confirm in text:
        print(f"password echoed in PTY output: {text!r}", file=sys.stderr)
        return 4

    phcs = re.findall(
        r"\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+", text
    )
    if args.expect_success:
        if code != 0 or len(phcs) != 1:
            print(
                f"expected one PHC and exit 0: code={code} output={text!r}",
                file=sys.stderr,
            )
            return 5
        print("PTY_OK")
        return 0
    if code != 1 or phcs:
        print(
            f"expected confirmation failure and no PHC: code={code} output={text!r}",
            file=sys.stderr,
        )
        return 6
    print("PTY_MISMATCH_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
