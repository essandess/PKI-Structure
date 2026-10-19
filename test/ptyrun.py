"""ptyrun.py PWFILE CMD...: run CMD on a pty; answer its 'Installer password'
prompt from PWFILE and its 'Secret LABEL' prompts from PTY_SECRET
(PTY_SECRET_AGAIN for the confirmation, default the same)."""
import os
import pty
import re
import select
import sys

pwfile, *cmd = sys.argv[1:]
with open(pwfile) as fh:
    pw = fh.readline().rstrip("\n")
s1 = os.environ.get("PTY_SECRET", "")
s2 = os.environ.get("PTY_SECRET_AGAIN", s1)
pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)
buf = b""
log = b""
while True:
    ready, _, _ = select.select([fd], [], [], 120)
    if not ready:
        os.kill(pid, 9)
        sys.exit(124)
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    log += data
    buf += data
    while b"Installer password" in buf:
        buf = buf.split(b"Installer password", 1)[1]
        os.write(fd, (pw + "\n").encode())
    while True:
        m = re.search(rb"Secret [^\n]*?: ", buf)
        if not m:
            break
        buf = buf[m.end():]
        ans = s2 if b"(again)" in m.group(0) else s1
        os.write(fd, (ans + "\n").encode())
_, status = os.waitpid(pid, 0)
sys.stdout.write(log.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(status))
