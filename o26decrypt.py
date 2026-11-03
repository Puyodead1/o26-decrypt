r"""Decrypt a Disney Tsum Tsum (Konami O26) game install, using its own files and its own license dongle.

  python o26decrypt.py check <O26-001>            check the install, find the PIN secrets (no dongle needed)
  python o26decrypt.py token [--lib DLL]          list dongles and their PIN state (never logs in)
  python o26decrypt.py run <O26-001> <out>        decrypt everything into <out> (needs the license dongle)
        [--lib DLL] [--master HEX] [--kdm HEX]

<O26-001> is the game folder from the cabinet's game drive (it has loader\ and contents\).
See README.md.
"""
import argparse
import os
import sys

from o26 import drm, layer1, pin, token

KEYS_FILE = "o26_keys.txt"


class Install:
    """The paths of an O26-001 folder, checked."""

    def __init__(self, root):
        self.root = root
        self.loader = os.path.join(root, "loader")
        self.contents = os.path.join(root, "contents")
        self.bootstrap = os.path.join(self.loader, "modules", "bootstrap.exe")
        self.kdu = os.path.join(self.loader, "modules", "kdu.dll")
        self.keyring = os.path.join(self.contents, drm.drm_path("keyring.dat"))
        self.kdm = os.path.join(self.contents, "modules", "kdm.dll")

    def problems(self):
        need = [(self.bootstrap, "loader\\modules\\bootstrap.exe"), (self.kdu, "loader\\modules\\kdu.dll"),
                (os.path.join(self.contents, "modules", "bootstrap.exe"), "contents\\modules\\bootstrap.exe"),
                (self.keyring, "contents\\" + drm.drm_path("keyring.dat").replace("/", "\\") + " (keyring.dat)"),
                (os.path.join(self.contents, drm.drm_path("file.inf")), "contents\\...\\file.inf")]
        return [label for path, label in need if not os.path.exists(path)]

    def secrets(self):
        seed = layer1.seed_from_pe(open(self.bootstrap, "rb").read())
        return pin.extract_secrets(layer1.read_file(self.kdu, seed))


def cmd_check(a):
    inst = Install(a.install)
    bad = inst.problems()
    for p in bad:
        print(f"missing: {p}")
    if bad:
        sys.exit("this doesn't look like a complete O26-001 folder (it needs loader\\ and contents\\)")
    print("files: ok")
    secrets = inst.secrets()
    print(f"PIN secrets in kdu.dll: set 0 {'found' if secrets[0] else 'NOT found'}, "
          f"set 1 {'found' if secrets[1] else 'NOT found'}")
    if not any(secrets):
        sys.exit("can't continue without the PIN secrets")
    print(f"kdm.dll: {'found' if os.path.exists(inst.kdm) else 'not found (fine: the game runs without it)'}")
    print("ready: plug in the license dongle and run 'o26decrypt.py token', then 'o26decrypt.py run'")


def cmd_token(a):
    tokens = token.list_tokens(a.lib)
    if not tokens:
        sys.exit("no dongle found (plugged in? SafeNet Authentication Client installed?)")
    for t in tokens:
        kind = "LICENSE dongle" if t["license"] else "other dongle (not used)"
        print(f"slot {t['slot']}: {kind}, serial {t['serial']}, {t['model']}, {token.describe(t['flags'])}")
        for c in t["certs"]:
            print(f"    {c['subject']}  valid {c['valid'][0]:%Y-%m-%d} .. {c['valid'][1]:%Y-%m-%d}")
    if not any(t["license"] for t in tokens):
        sys.exit("no license dongle (certificate OU e-AMUSEMENT/License) among them")


def cmd_run(a):
    inst = Install(a.install)
    bad = inst.problems()
    if bad:
        sys.exit("missing: " + ", ".join(bad) + " (run 'check' first)")
    master = bytes.fromhex(a.master) if a.master else None
    kdm_key = bytes.fromhex(a.kdm) if a.kdm else None
    if not master:
        secrets = inst.secrets()
        if not any(secrets):
            sys.exit("PIN secrets not found in kdu.dll")
        wrapped = {"master": drm.wrapped_master_key(open(inst.keyring, "rb").read())}
        if os.path.exists(inst.kdm):
            wrapped["kdm"] = drm.kdm_envelope(open(inst.kdm, "rb").read())[0]
        print("asking the license dongle to unwrap the keys...")
        keys = token.unwrap(secrets, wrapped, a.lib)
        master = keys.get("master")
        kdm_key = keys.get("kdm")
        if not master:
            sys.exit("the dongle didn't unwrap the master key (wrong dongle for this install?)")
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, KEYS_FILE), "w") as f:
            f.write(f"master {master.hex()}\n")
            if kdm_key:
                f.write(f"kdm {kdm_key.hex()}\n")
        print(f"keys saved to {os.path.join(a.out, KEYS_FILE)} (re-run with --master/--kdm without the dongle; "
              f"keep this file to yourself)")
    try:
        drm.decrypt_contents(inst.contents, master, a.out, kdm_key)
    except ValueError as e:
        sys.exit(str(e))
    print("done. The game folder is", a.out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check the install and find the PIN secrets (no dongle)")
    c.add_argument("install", help="the O26-001 folder")
    c.set_defaults(func=cmd_check)
    t = sub.add_parser("token", help="list dongles and their PIN state (never logs in)")
    t.add_argument("--lib", default=token.DEFAULT_LIB, help="SAC's PKCS#11 library (default %(default)s)")
    t.set_defaults(func=cmd_token)
    r = sub.add_parser("run", help="decrypt the install (needs the license dongle unless --master is given)")
    r.add_argument("install", help="the O26-001 folder")
    r.add_argument("out", help="output folder (becomes the game folder)")
    r.add_argument("--lib", default=token.DEFAULT_LIB, help="SAC's PKCS#11 library (default %(default)s)")
    r.add_argument("--master", help="master key (hex) from an earlier run, instead of the dongle")
    r.add_argument("--kdm", help="kdm.dll key (hex) from an earlier run")
    r.set_defaults(func=cmd_run)
    a = ap.parse_args()
    try:
        a.func(a)
    except token.TokenError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
