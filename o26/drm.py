"""Layer 2: the DRM file system of O26-001/contents (kdm.dll / kdu.dll), decrypted offline.

Stored paths: HMAC-SHA1(key = SHA1(cn || "test"), name) as "h/h/h/<37 hex>", cn = the license certificate CN
("O26-001"). file.inf (the file table) stores the same 20-byte digest as each file's dst_path.

Encryption-info header (big-endian): u8 algo, u8 mode, u32 ?, u32 key_bits, u32 iv_len, iv, payload.
(6, 3) = AES-CTR with a full 128-bit big-endian counter.

keyring.dat (v1, big-endian; each {offset, length} pair is relative to the field itself):
  0x8c entry count n, 0x90 PKCS#7 whose content is n * SHA1(CEK), 0x98 RSA-wrapped master key (unwrapped on the
  license dongle -> 32 bytes), 0xa0 encryption info of the KEK stream, 0xa8 n * 20-byte entries
  {kek off, kek len, ecek off, ecek count, ecek unit}. KEKs are one AES-CTR stream under the master key;
  CEK i = ECEK i decrypted with KEK i. file.inf is encrypted with CEK 0.

kdm.dll itself is a CMS EnvelopedData whose content key is RSA-wrapped to the same dongle.
No key is stored here: the master key and kdm.dll's key come from the user's dongle.
"""
import hashlib
import hmac
import os
import struct

import kbinxml
from asn1crypto import cms
from Crypto.Cipher import AES

from . import layer1

CN = "O26-001"


def drm_path(name, cn=CN):
    key = hashlib.sha1(cn.encode() + b"test").digest()
    return _digest_path(hmac.new(key, name.encode(), hashlib.sha1).digest())


def _digest_path(d):
    h = d.hex()
    return f"{h[0]}/{h[1]}/{h[2]}/{h[3:]}"


def _be32(b, off):
    return struct.unpack_from(">I", b, off)[0]


def _field(b, off):
    return b[off + _be32(b, off):off + _be32(b, off) + _be32(b, off + 4)]


def _info(b):
    """Encryption-info header -> (key_bits, iv, payload offset)."""
    if (b[0], b[1]) != (6, 3):
        raise ValueError(f"unsupported algo/mode {b[0]}/{b[1]}")
    bits, ivlen = _be32(b, 6), _be32(b, 10)
    return bits, b[14:14 + ivlen], 14 + ivlen


def _ctr(key, iv, data, block=0):
    ivn = (int.from_bytes(iv, "big") + block) % (1 << 128)
    return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=ivn.to_bytes(16, "big")).decrypt(data)


def wrapped_master_key(keyring):
    """The RSA-wrapped master key in keyring.dat (what the dongle has to decrypt)."""
    return _field(keyring, 0x98)


def kdm_envelope(data):
    """(wrapped content key, decrypt function) of kdm.dll's CMS envelope."""
    env = cms.ContentInfo.load(data)["content"]
    wrapped = env["recipient_infos"][0].chosen["encrypted_key"].native
    eci = env["encrypted_content_info"]
    iv = eci["content_encryption_algorithm"]["parameters"].native
    ct = eci["encrypted_content"].native

    def decrypt(key):
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        return pt[:-pt[-1]]
    return wrapped, decrypt


class Keyring:
    def __init__(self, kr, master):
        hdr = _be32(kr, 0)
        self.n = _be32(kr, 0x8c)
        self.hashes = cms.ContentInfo.load(_field(kr, 0x90))["content"]["encap_content_info"]["content"].native
        _, iv, _ = _info(_field(kr, 0xa0))
        base = 0xa8 + _be32(kr, 0xa8)
        self.ceks = []
        for i in range(self.n):
            e = 0xa8 + 20 * i
            koff = e + _be32(kr, e)
            kek = _ctr(master, iv, kr[koff:koff + _be32(kr, e + 4)], (koff - base) // 16)
            eoff, count, unit = hdr + _be32(kr, e + 8), _be32(kr, e + 12), _be32(kr, e + 16)
            if count != 1:
                self.ceks.append(None)  # play-count limited key; not used by O26
                continue
            ecek = kr[eoff:eoff + unit]
            _, eiv, p = _info(ecek)
            self.ceks.append(_ctr(kek, eiv, ecek[p:]))

    def check(self, i):
        c = self.ceks[i]
        return c is not None and hashlib.sha1(c).digest() == self.hashes[20 * i:20 * i + 20]


def decrypt_file(data, cek):
    bits, iv, p = _info(data)
    return _ctr(cek[:bits // 8], iv, data[p:])


def decrypt_contents(src, master, out, kdm_key=None, log=print):
    """Decrypt the whole O26-001/contents tree into `out` (the game folder). Returns the number of files."""
    kr = Keyring(open(os.path.join(src, drm_path("keyring.dat")), "rb").read(), master)
    good = sum(kr.check(i) for i in range(kr.n))
    log(f"keyring: {kr.n} file keys, {good} verified against the signed hash list")
    if not kr.check(0):
        raise ValueError("file key 0 doesn't verify: wrong master key")
    inf = decrypt_file(open(os.path.join(src, drm_path("file.inf")), "rb").read(), kr.ceks[0])
    doc = kbinxml.KBinXML(inf).xml_doc
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, "file.inf.xml"), "wb").write(kbinxml.KBinXML(inf).to_text().encode())
    seed = layer1.seed_from_pe(open(os.path.join(src, "modules", "bootstrap.exe"), "rb").read())
    done = missing = 0
    for f in doc.iter("file"):
        dirs = [a.get("name") for a in f.iterancestors("dir")][::-1]
        name = f.get("name")
        size = int(f.findtext("orig_size"))
        if f.find("key_idx") is None:      # not DRM'd: stored under its own name
            path, idx = os.path.join(src, *dirs, name), None
        else:
            path = os.path.join(src, _digest_path(bytes.fromhex(f.findtext("dst_path").replace(" ", ""))))
            idx = int(f.findtext("key_idx"))
        if not os.path.exists(path):
            log(f"  missing: {'/'.join(dirs + [name])}")
            missing += 1
            continue
        data = open(path, "rb").read()
        if idx is not None:
            data = decrypt_file(data, kr.ceks[idx])[:size]
        elif layer1.is_encrypted(data):
            data = layer1.decrypt(data, seed)
        elif name == "kdm.dll" and data[:2] == b"\x30\x83" and kdm_key:
            data = kdm_envelope(data)[1](kdm_key)
        o = os.path.join(out, *dirs, name)
        os.makedirs(os.path.dirname(o), exist_ok=True)
        open(o, "wb").write(data)
        done += 1
    log(f"wrote {done} files to {out}" + (f" ({missing} missing)" if missing else ""))
    return done
