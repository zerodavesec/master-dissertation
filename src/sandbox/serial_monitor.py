"""
This is the script that creates a Pipe and hooks it to the serial COM1 port in
the host machine. This allowes for the Sandboxed VM to send collected logs to the
Serial COM1 port, and this script writes them in JSONL format to a plaintext file
in the host's filesystem. The name of the log will change upon each execution.

Safeguards: The VM will never start if the Pipe is not setup by this Python script.
"""

import pathlib

import pywintypes
import win32file
import win32pipe
import win32security

PIPE_NAME = r"\\.\pipe\sandbox_logs"
OUTPUT_FILE = r"D:\Dissertation\logs\benign.jsonl"
file_path = pathlib.Path(OUTPUT_FILE)
file_path.touch(exist_ok=True)


def get_unrestricted_sa():
    sa = win32security.SECURITY_ATTRIBUTES()
    sd = win32security.SECURITY_DESCRIPTOR()
    sd.SetSecurityDescriptorDacl(1, None, 0)  # type: ignore
    # (1, None, 0), NULL DACL = unrestricted access for all
    sa.SECURITY_DESCRIPTOR = sd
    return sa


def main():
    while True:
        pipe = win32pipe.CreateNamedPipe(
            PIPE_NAME,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_BYTE
            | win32pipe.PIPE_READMODE_BYTE
            | win32pipe.PIPE_WAIT,
            1,
            65536,
            65536,
            0,
            get_unrestricted_sa(),
        )

        print(f"[+] Waiting for VM to connect on {PIPE_NAME} ...")
        win32pipe.ConnectNamedPipe(pipe, None)
        print("[+] VM connected. Collecting logs...")

        buffer = b""
        try:
            with open(OUTPUT_FILE, "ab") as f:
                while True:
                    try:
                        _, data = win32file.ReadFile(pipe, 65536)
                    except pywintypes.error as e:
                        print(
                            f"[-] VM disconnected ({e.strerror}). Waiting for reconnect..."
                        )
                        break

                    buffer += data
                    while b"\r\n" in buffer:
                        line, buffer = buffer.split(b"\r\n", 1)
                        f.write(line + b"\n")
                        f.flush()
        finally:
            win32file.CloseHandle(pipe)


if __name__ == "__main__":
    main()
