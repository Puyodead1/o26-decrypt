# Technical notes

| Module | |
|---|---|
| `o26/layer1.py` | loader encryption |
| `o26/pin.py` | dongle PIN derivation, finding its secrets in `kdu.dll` |
| `o26/token.py` | the license dongle through PKCS#11 |
| `o26/drm.py` | the DRM file system of `contents\` |

## Install layout

`O26-001\loader\` holds the loader (`modules\bootstrap.exe`, `kdu.dll`, …), partly layer-1 encrypted, listed in a
kbinxml `allfiles.lst`. `O26-001\contents\` holds the game: about 1400 files stored under hashed paths and encrypted
with per-file keys, plus a few plain or layer-1 files.

## Layer 1 (bootstrap.exe sub_14000F6D0)

```
[0] 0x00   [1..4] check: b[1]^b[3] == 'O', b[2]^b[4] == 'D'
[3..66] SHA-512 of the plaintext (first 16 bytes = IV)   [19..34] key salt   [67..] ciphertext
key       = SHA1(authenticode_stream(bootstrap.exe) || blob[19:35])[:16]
plaintext = AES-128-CTR(key, initial_counter = blob[3:19])
```

The authenticode stream is the PE hashed the way bootstrap.exe sub_1400123A0 does it (CheckSum and the security
directory skipped).

## Dongle PIN (kdu.dll)

```
PIN = SHA1(secret || serial.ljust(16, ' '))[:16], zero bytes replaced by 1, 2, 3, …
```

`secret` is stored as a 128-character `[0-9A-Z]` string, decoded with a SHA-1-keyed shuffled base32
(sub_18000E470 / E970 / F110 / EDA0) whose key comes from a seed string stored 0x88 bytes after it. There are two
sets: set 0 (seed `1234…`) is the factory PIN, and kdu re-PINs the token to set 1 (seed `0123…:;<=>?…`) after the
first good login with set 0 (sub_180004110).

## Dongle

The license token's certificate has OU `e-AMUSEMENT/License`. Its RSA key decrypts (`CKM_RSA_PKCS`, as kdm.dll's
`kdu_25` does):

- the master key: 128 bytes in `keyring.dat` → 32 bytes
- kdm.dll's content key: `kdm.dll` is a CMS EnvelopedData (AES-128-CBC) → 16 bytes

PKCS#11 flags: `CKF_USER_PIN_COUNT_LOW` only means "a wrong PIN since the last good login" (expected after set 0
fails on a re-PINned token); `CKF_USER_PIN_FINAL_TRY` / `CKF_USER_PIN_LOCKED` are where the tool refuses to go on.

## DRM file system (kdm.dll / kdu.dll)

- Stored path: `HMAC-SHA1(key = SHA1(cn || "test"), name)` as `h/h/h/<37 hex>`, cn = the license certificate CN
  (`O26-001`).
- Encryption-info header (big-endian): `u8 algo, u8 mode, u32 ?, u32 key_bits, u32 iv_len, iv, payload`;
  `(6, 3)` = AES-CTR with a full 128-bit big-endian counter.
- `keyring.dat` (v1, big-endian; `{offset, length}` pairs are relative to the field itself): `0x8c` entry count n,
  `0x90` PKCS#7 whose content is n × SHA1(CEK), `0x98` RSA-wrapped master key, `0xa0` encryption info of the KEK
  stream, `0xa8` n × 20-byte entries `{kek off, kek len, ecek off, ecek count, ecek unit}`. The KEKs are one AES-CTR
  stream under the master key; CEK i = ECEK i decrypted with KEK i. The signed hash list verifies every CEK.
- `file.inf` (kbinxml, encrypted with CEK 0) lists every file: name, directory, `dst_path` (the 20-byte digest of
  its stored path), `key_idx`, `orig_size`. Files without `key_idx` are stored under their own name (plain, layer 1,
  or `kdm.dll`'s CMS envelope).
