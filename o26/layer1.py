"""Layer 1: Konami "eapki" bootstrap encryption (loader files, reversed from bootstrap.exe sub_14000F6D0).

Encrypted blob layout:
  [0]      0x00
  [1..4]   check bytes: b[1]^b[3] == 'O', b[2]^b[4] == 'D'
  [3..66]  64-byte SHA-512 of the plaintext; the first 16 bytes double as the IV
  [19..34] key salt (overlaps the hash)
  [67..]   ciphertext

key       = SHA1(authenticode_stream(bootstrap.exe) || blob[19:35])[:16]
plaintext = AES-128-CTR(key, initial_counter=blob[3:19]).decrypt(blob[67:])

No key is stored anywhere: it comes from the user's own bootstrap.exe.
"""
import hashlib
import struct

from Crypto.Cipher import AES


def is_encrypted(b):
    return len(b) >= 0x43 and b[0] == 0 and (b[1] ^ b[3]) == 0x4F and (b[2] ^ b[4]) == 0x44


def _authenticode_chunks(pe):
    """Byte ranges hashed by bootstrap.exe sub_1400123A0 (PE32+ only)."""
    nt = struct.unpack_from("<i", pe, 0x3C)[0]
    fh, opt = nt + 4, nt + 24
    nsec = struct.unpack_from("<H", pe, fh + 2)[0]
    size_of_opt = struct.unpack_from("<H", pe, fh + 16)[0]
    sect = opt + size_of_opt
    size_of_headers = struct.unpack_from("<I", pe, opt + 0x3C)[0]
    ndirs = struct.unpack_from("<I", pe, opt + 0x6C)[0]

    yield pe[0:opt + 0x40]                     # up to CheckSum
    yield pe[opt + 0x44:opt + 0x70]            # rest of optional header (no dirs)
    for i in range(ndirs):                     # data dirs, skipping SECURITY
        if i != 4:
            yield pe[opt + 0x70 + i * 8:opt + 0x78 + i * 8]
    yield pe[sect:size_of_headers]             # section table .. end of headers

    secs, end = [], size_of_headers
    for i in range(nsec):
        raw_size, raw_ptr = struct.unpack_from("<II", pe, sect + i * 40 + 16)
        secs.append((raw_ptr, raw_size))
        end = max(end, raw_ptr + raw_size)
    for ptr, size in sorted(secs):
        yield pe[ptr:ptr + size]

    cert_off, cert_size = struct.unpack_from("<II", pe, opt + 0x70 + 4 * 8)
    if cert_off:
        yield pe[end:cert_off]
        yield pe[cert_off + cert_size:]
    else:
        yield pe[end:]


def seed_from_pe(pe_bytes):
    """The SHA-1 state every layer-1 key starts from."""
    h = hashlib.sha1()
    for c in _authenticode_chunks(pe_bytes):
        h.update(c)
    return h


def decrypt(blob, seed):
    if not is_encrypted(blob):
        raise ValueError("not a layer-1 encrypted blob")
    h = seed.copy()
    h.update(blob[19:35])
    pt = AES.new(h.digest()[:16], AES.MODE_CTR, initial_value=blob[3:19], nonce=b"").decrypt(blob[67:])
    if hashlib.sha512(pt).digest() != blob[3:67]:
        raise ValueError("SHA-512 mismatch (wrong bootstrap.exe?)")
    return pt


def read_file(path, seed):
    """Read a file, decrypting it if it's layer-1 encrypted."""
    data = open(path, "rb").read()
    return decrypt(data, seed) if is_encrypted(data) else data
