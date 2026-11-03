# o26-decrypt

Decrypts a **Disney Tsum Tsum** arcade (Konami, model `O26`) game install for preservation, using **the cabinet's
own files and its own license dongle**. The output is a plain game folder you can run with
[o26-tsumtsum](https://github.com/Puyodead1/o26-tsumtsum).

**No keys, secrets or game files are included.** Everything is derived at run time from what you provide:

| What | Comes from |
|---|---|
| Loader decryption key | your `bootstrap.exe` |
| Dongle PIN | your `kdu.dll` (the secrets are read out of it) plus your dongle's serial number |
| Master key and kdm.dll key | **your license dongle** decrypts them; the private key never leaves the dongle |
| Per-file keys | your `keyring.dat`, unlocked with the master key |

Without the original cabinet's game drive and its license dongle, this tool can't do anything.

## Requirements

- **The game folder** `O26-001` from the cabinet's game drive (the `D:` drive on the cabinet), with both `loader\`
  and `contents\` in it. Copy it from the drive or from a disk image of it.
- **The license dongle**: the SafeNet eToken whose certificate says `e-AMUSEMENT/License`. The other dongle (the
  account dongle, `e-AMUSEMENT/Game`) isn't used. It can be plugged in too; the tool never logs into it.
- **SafeNet Authentication Client (SAC)**, for the dongle's PKCS#11 driver (`eTPKCS11.dll`). **SAC 8.x and 9.x are
  both known to work.** Newer releases have dropped some older eToken models. Install it before plugging in the dongle.
- **Python 3.10+**, 64-bit, then:

  ```
  pip install -r requirements.txt
  ```

## Usage

**1. Check the game folder.** This needs no dongle.

```
python o26decrypt.py check D:\O26-001
```

It checks that the needed files are there, decrypts `kdu.dll` and looks for the PIN secrets in it. Expected:

```
files: ok
PIN secrets in kdu.dll: set 0 found, set 1 found
```

**2. Look at the dongles.** This never logs in, so it can't affect the PIN.

```
python o26decrypt.py token
```

It lists every dongle with its serial, its certificates and its PIN state. `PIN ok` or `wrong attempts recorded` is
fine. Don't continue if the license dongle shows `final try left` or `PIN LOCKED`.

**3. Decrypt.**

```
python o26decrypt.py run D:\O26-001 C:\TsumTsum\game
```

The dongle unwraps the keys, the keys are saved to `C:\TsumTsum\game\o26_keys.txt`, and every file is decrypted
into `C:\TsumTsum\game` (`modules\`, `prop\`, `data\`, `arkdata\`, …). This takes a few minutes for about 2 GB.

To decrypt again later without the dongle, pass the saved keys:

```
python o26decrypt.py run D:\O26-001 C:\TsumTsum\game --master <hex> --kdm <hex>
```

If SAC's PKCS#11 library isn't at `C:\Windows\System32\eTPKCS11.dll`, pass `--lib <path to eTPKCS11.dll>`.

**4. Run it.** Follow [o26-tsumtsum](https://github.com/Puyodead1/o26-tsumtsum): add spice2x, `libacioEx.dll`,
`launch.bat` and the server.

## Dongle safety

eTokens lock themselves after too many wrong PINs, so the tool is careful:

- It only ever logs into the license dongle, which it identifies by reading its certificate without logging in.
- It tries nothing if the dongle is down to its final try or locked, and it stops the moment it reports either.
- It tries at most the two PINs the game itself would use, once each. The cabinet's software moves a dongle from
  PIN set 0 to set 1 the first time it logs in, so one of them is normally rejected: `PIN set 0: not accepted`
  followed by `logged in with PIN set 1` is fine.
- It never changes the PIN.

## Troubleshooting

| Message | Meaning |
|---|---|
| `can't load ...eTPKCS11.dll` | SAC isn't installed, or it's installed elsewhere (use `--lib`) |
| `no license dongle ... found` | The dongle isn't plugged in, isn't recognised by SAC, or is the account dongle |
| `PIN secrets ... NOT found` | `kdu.dll` is from a different game version than this tool knows |
| `neither PIN set was accepted` | The dongle's PIN was changed by something else; stop here, don't retry |
| `the dongle didn't unwrap the master key` | The dongle belongs to a different game or cabinet |
| `file key 0 doesn't verify` | The `--master` key is wrong, or isn't for this install |

## Disclaimer

For preserving a game you own, on hardware you own. Not affiliated with Konami or Disney. Don't share the decrypted
game or your `o26_keys.txt`.
