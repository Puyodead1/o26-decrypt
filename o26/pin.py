"""eToken user-PIN derivation of kdu.dll (don_session_create / login_user).

PIN = SHA1(secret || serial.ljust(16, ' '))[:16], zero bytes replaced by 1, 2, 3, ...

`secret` is stored in kdu.dll as a 128-character [0-9A-Z] string, decoded with a SHA-1-keyed, shuffled base32
whose key comes from a "seed" string (kdu.dll sub_18000E470 / sub_18000E970 / sub_18000F110 / sub_18000EDA0).
There are two secret sets: login tries set 0, and if that works kdu re-PINs the token to set 1 (sub_180004110),
so a token is on one or the other.

Nothing secret is stored here: extract_secrets() reads both encoded strings out of the user's own kdu.dll, where
each sits right before its seed string. The seeds are plain counting sequences.
"""
import hashlib
import re
import struct

SEEDS = ("12345678901234567890123456789012",   # set 0 (factory)
         "0123456789:;<=>?@ABCDEFGHIJKLMNO")   # set 1 (after kdu re-PINs the token)
SEED_GAP = 0x88                                 # encoded string -> its seed string in kdu.dll


def _sha1(*parts):
    h = hashlib.sha1()
    for p in parts:
        h.update(p)
    return h.digest()


class _Shuffler:
    def __init__(self, seed):
        h1 = _sha1(seed)
        h2 = _sha1(h1, seed)
        h3 = _sha1(h2, seed)
        self.chain = _sha1(h1[:16] + h2[:16])
        self.counter = struct.unpack(">I", h3[12:16])[0]
        self.buf = b""
        self.alpha = bytearray(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    def _block(self):
        self.counter = (self.counter + 1) & 0xFFFFFFFF
        self.chain = _sha1(self.chain, struct.pack(">I", self.counter))
        return self.chain

    def shuffle(self):
        n = len(self.alpha)
        for _ in range(2):
            for p in range(n):
                if len(self.buf) < 4:
                    self.buf += self._block()
                r = struct.unpack(">I", self.buf[:4])[0]
                self.buf = self.buf[4:]
                j = int(r * (n * 2.328306436538696e-10))
                self.alpha[p], self.alpha[j] = self.alpha[j], self.alpha[p]


def decode(seed, text):
    """Decode one encoded secret; ValueError if `text` wasn't encoded with `seed`."""
    s = _Shuffler(seed.encode())
    out = bytearray(144)
    bit = 0
    for ch in text.encode():
        s.shuffle()
        v = s.alpha.find(ch)
        if v < 0 or v > 32:
            raise ValueError("not encoded with this seed")
        if v == 32:
            return bytes(out[:bit >> 3])
        for k in range(5):
            if v >> k & 1:
                out[(bit + k) >> 3] |= 1 << ((bit + k) & 7)
        bit += 5
    return bytes(out[:bit >> 3])


def extract_secrets(kdu):
    """Both PIN secrets from a decrypted kdu.dll, as [set 0, set 1] (None where not found)."""
    found = [None, None]
    for m in re.finditer(rb"(?<![0-9A-Z])[0-9A-Z]{128}(?![0-9A-Z])", kdu):
        after = kdu[m.start() + SEED_GAP:m.start() + SEED_GAP + 32]
        for i, seed in enumerate(SEEDS):
            if after == seed.encode():
                try:
                    found[i] = decode(seed, m.group().decode())
                except ValueError:
                    pass
    return found


def user_pin(secret, serial):
    """The user PIN kdu.dll logs in with, for a token serial number."""
    s = serial.encode()
    pin = bytearray(_sha1(secret + s + b" " * max(0, 16 - len(s)))[:16])
    n = 0
    for i in range(15):
        if pin[i] == 0:
            n += 1
            pin[i] = n
    return bytes(pin)
