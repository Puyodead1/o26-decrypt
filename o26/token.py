"""The cabinet's license dongle (SafeNet eToken, certificate OU "e-AMUSEMENT/License") through PKCS#11.

Needs SafeNet Authentication Client (SAC), which installs eTPKCS11.dll. The RSA private key never leaves the token:
the token decrypts the wrapped keys for us (CKM_RSA_PKCS), exactly like kdm.dll does on the cabinet.

Safety, because eTokens lock after repeated wrong user PINs:
  - only the license token is logged into (found by its certificate, read without logging in);
  - nothing is tried if the token reports FINAL_TRY / LOCKED, and it stops as soon as it does (COUNT_LOW only
    means "a wrong PIN since the last good login", which is expected after the first of the two PINs fails);
  - at most the two PINs kdu.dll itself would use are tried, one attempt each;
  - the PIN is never changed.
"""
import PyKCS11
from asn1crypto import x509

DEFAULT_LIB = r"C:\Windows\System32\eTPKCS11.dll"
LICENSE_OU = "e-AMUSEMENT/License"
STOP_FLAGS = PyKCS11.CKF_USER_PIN_FINAL_TRY | PyKCS11.CKF_USER_PIN_LOCKED


class TokenError(Exception):
    pass


def _load(lib):
    p11 = PyKCS11.PyKCS11Lib()
    try:
        p11.load(lib)
    except PyKCS11.PyKCS11Error as e:
        raise TokenError(f"can't load {lib} ({e}); is SafeNet Authentication Client installed?")
    return p11


def _certs(p11, slot):
    """Public certificates on a token, read without logging in."""
    out = []
    sess = p11.openSession(slot)
    try:
        for o in sess.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]):
            c = x509.Certificate.load(bytes(sess.getAttributeValue(o, [PyKCS11.CKA_VALUE])[0]))
            t = c["tbs_certificate"]
            out.append({
                "subject": t["subject"].human_friendly,
                "issuer": t["issuer"].human_friendly,
                "ou": str(t["subject"].native.get("organizational_unit_name")),
                "valid": (t["validity"]["not_before"].native, t["validity"]["not_after"].native),
            })
    finally:
        sess.closeSession()
    return out


def describe(flags):
    if flags & PyKCS11.CKF_USER_PIN_LOCKED:
        return "PIN LOCKED"
    if flags & PyKCS11.CKF_USER_PIN_FINAL_TRY:
        return "PIN: final try left"
    if flags & PyKCS11.CKF_USER_PIN_COUNT_LOW:
        return "PIN: wrong attempts recorded"
    return "PIN ok"


def list_tokens(lib=DEFAULT_LIB):
    """[{slot, serial, label, model, flags, certs, license}] for every token present. Never logs in."""
    return _tokens(_load(lib))


def _tokens(p11):
    out = []
    for slot in p11.getSlotList(tokenPresent=True):
        ti = p11.getTokenInfo(slot)
        certs = _certs(p11, slot)
        out.append({
            "slot": slot, "serial": ti.serialNumber.rstrip(" \0"), "label": ti.label.strip(),
            "model": ti.model.strip(), "flags": ti.flags, "certs": certs,
            "license": any(LICENSE_OU in c["ou"] for c in certs),
        })
    return out


def unwrap(secrets, wrapped, lib=DEFAULT_LIB, log=print):
    """Log into the license token and RSA-decrypt each blob of `wrapped` ({name: bytes}) with its private key.

    `secrets` = [set 0, set 1] from pin.extract_secrets. Returns {name: plaintext} for the blobs that decrypted.
    """
    from . import pin
    p11 = _load(lib)
    tokens = [t for t in _tokens(p11) if t["license"]]
    if not tokens:
        raise TokenError("no license dongle (certificate OU e-AMUSEMENT/License) found")
    tok = tokens[0]
    slot = tok["slot"]
    if tok["flags"] & STOP_FLAGS:
        raise TokenError(f"license dongle reports '{describe(tok['flags'])}'; not trying any PIN")
    if tok["flags"] & PyKCS11.CKF_USER_PIN_COUNT_LOW:
        log("  note: the dongle has a wrong PIN attempt recorded already (a good login clears it)")
    for idx in (0, 1):
        if secrets[idx] is None:
            continue
        sess = p11.openSession(slot)
        try:
            sess.login(list(pin.user_pin(secrets[idx], tok["serial"])))
        except PyKCS11.PyKCS11Error as e:
            sess.closeSession()
            log(f"  PIN set {idx}: not accepted ({e})")
            if p11.getTokenInfo(slot).flags & STOP_FLAGS:
                raise TokenError("the dongle is down to its final PIN try or locked; stopping")
            continue
        log(f"  logged in with PIN set {idx}")
        try:
            out = {}
            keys = sess.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
            for name, blob in wrapped.items():
                for k in keys:
                    try:
                        out[name] = bytes(sess.decrypt(k, blob, PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS)))
                        break
                    except PyKCS11.PyKCS11Error:
                        continue
            return out
        finally:
            sess.logout()
            sess.closeSession()
    raise TokenError("neither PIN set was accepted")
