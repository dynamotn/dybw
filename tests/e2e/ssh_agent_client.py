#!/usr/bin/env python3
"""A minimal SSH agent client (draft-miller-ssh-agent) for the requests no OpenSSH tool makes: a sign request for a
key the agent does not list (a key of a locked profile).

    python3 ssh_agent_client.py SOCKET PUBFILE DATAFILE

asks the agent at SOCKET to sign DATAFILE with the key of PUBFILE (an OpenSSH public key line) and prints the
signature blob in hex; exit 1 on SSH_AGENT_FAILURE.
"""

import base64
import socket
import struct
import sys

SIGN_REQUEST, SIGN_RESPONSE = 13, 14


def string(b):
    return struct.pack(">I", len(b)) + b


def recv(c, n):
    out = b""
    while len(out) < n:
        part = c.recv(n - len(out))
        if not part:
            raise EOFError("the agent closed the connection")
        out += part
    return out


def sign(path, blob, data):
    with socket.socket(socket.AF_UNIX) as c:
        c.settimeout(60)  # the user may be asked to unlock, then to confirm
        c.connect(path)
        c.sendall(string(bytes([SIGN_REQUEST]) + string(blob) + string(data) + struct.pack(">I", 0)))
        (n,) = struct.unpack(">I", recv(c, 4))
        reply = recv(c, n)
    if reply[0] != SIGN_RESPONSE:
        return None
    (n,) = struct.unpack(">I", reply[1:5])
    return reply[5:5 + n]


def main(path, pubfile, datafile):
    blob = base64.b64decode(open(pubfile).read().split()[1])
    sig = sign(path, blob, open(datafile, "rb").read())
    if sig is None:
        return 1
    print(sig.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
