#!/opt/agi-venv/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import re
import requests
from difflib import SequenceMatcher
from impacket.ldap import ldap, ldapasn1

# ----------------- LDAP CONFIG -----------------
try:
    SCOPE_SUBTREE = getattr(ldap, 'SC_SUBTREE', 2)
except Exception:
    SCOPE_SUBTREE = 2

AD_HOST   = os.getenv('AD_HOST', '192.168.0.7')
AD_BASEDN = os.getenv('AD_BASEDN', 'DC=Lancelotech,DC=local')
AD_DOMAIN = os.getenv('AD_DOMAIN', 'Lancelotech')
AD_USER   = os.getenv('AD_USER', 'ivr')
AD_PASS   = os.getenv('AD_PASS', 'Aa123456@@')

PHONE_PREF = ['telephoneNumber', 'ipPhone', 'mobile', 'homePhone', 'otherTelephone', 'pager']
ATTRS = list(dict.fromkeys(PHONE_PREF + [
    'displayName', 'givenName', 'sn', 'name',
    'sAMAccountName', 'userPrincipalName', 'cn',
    'mail', 'distinguishedName', 'objectClass'
]))

# ----------------- ASR CONFIG -----------------
ASR_URL = os.getenv('ASR_URL', 'http://192.168.0.4:8000/stt/transcribe')
MAX_CHARS = 2000

# ----------------- AGI HELPERS -----------------
def agi_read_env():
    env = {}
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            break
        if ":" in line:
            k, v = line.split(":", 1)
            env[k.strip()] = v.strip()
    return env

def agi_set_var(name, value):
    if value is None:
        value = ""
    safe = str(value).replace("\n", " ").replace("\r", " ")
    print(f'SET VARIABLE {name} "{safe}"')
    sys.stdout.flush()

# ----------------- ASR -----------------
def transcribe(path: str):
    """Send file to your ASR server and return (text, language, confidence)."""
    files = {"audio": open(path, "rb")}
    data = {}

    lang_hint = os.getenv("ASR_LANG_HINT", "").strip()
    if lang_hint:
        data["language"] = lang_hint

    r = requests.post(
        ASR_URL,
        files=files,
        data=data,
        headers={"Accept": "application/json"},
        timeout=30
    )
    r.raise_for_status()

    js = r.json()
    text = (js.get("text") or "").strip()[:MAX_CHARS]
    lang = js.get("language") or ""
    conf = js.get("confidence")

    return text, lang, conf

# ----------------- LDAP -----------------
def escape_filter_value(s):
    out = []
    for ch in s:
        if ch in ['*', '(', ')', '\\', '\x00']:
            out.append('\\' + format(ord(ch), '02x'))
        else:
            out.append(ch)
    return ''.join(out)

def entry_to_dict(entry):
    out = {}
    for attr in entry['attributes']:
        name = str(attr['type'])
        vals = []
        for v in attr['vals']:
            if isinstance(v, bytes):
                vals.append(v.decode('utf-8', 'ignore'))
            else:
                vals.append(str(v))
        out[name] = vals
    return out

def first(attrs, key):
    v = attrs.get(key)
    return v[0] if v else ''

def best_phone(attrs):
    """Return the first available phone field."""
    for k in PHONE_PREF:
        v = attrs.get(k)
        if v:
            return v[0]
    return ""

def build_filter(query):
    """LDAP filter using recognized speech."""
    q = escape_filter_value(query)
    contains = f"*{q}*"

    return (
        f"(&(|(&(objectClass=user)(!(objectClass=computer)))(objectClass=contact))"
        f"(|(sAMAccountName={q})(userPrincipalName={q})(cn={q})(displayName={q})"
        f"(givenName={q})(sn={q})(name={q})(cn={contains})(displayName={contains})"
        f"(givenName={contains})(sn={contains})(name={contains})))"
    )

def do_search(conn, flt):
    try:
        return conn.search(searchFilter=flt, attributes=ATTRS, sizeLimit=999)
    except Exception:
        try:
            return conn.search(flt, ATTRS)
        except Exception:
            return conn.search(flt)

def choose_best_match(entries, query):
    q = query.lower()
    ranked = []

    for it in entries:
        attrs = entry_to_dict(it)
        classes = [c.lower() for c in attrs.get("objectClass", [])]

        is_user = 1 if "user" in classes and "computer" not in classes else 0
        is_contact = 1 if "contact" in classes else 0
        phone = best_phone(attrs)
        has_phone = 1 if phone else 0

        sAM = first(attrs, 'sAMAccountName').lower()
        upn = first(attrs, 'userPrincipalName').lower()
        cn  = first(attrs, 'cn').lower()
        disp= first(attrs, 'displayName').lower()

        exact_user = 2 if (sAM == q or upn == q) else 0
        exact_name = 1 if (cn == q or disp == q) else 0

        score = (is_user, 0 if is_contact else 1, exact_user, exact_name, has_phone)
        ranked.append((score, it, attrs))

    ranked.sort(key=lambda x: x[0], reverse=True)

    if not ranked:
        return None, None

    return ranked[0][1], ranked[0][2]

def ldap_lookup(query_text):
    """Return LDAP attributes and DN for the recognized text."""
    query = query_text.strip()
    if not query:
        return None, ""

    conn = ldap.LDAPConnection(f'ldap://{AD_HOST}', AD_BASEDN)
    conn.login(AD_USER, AD_PASS, AD_DOMAIN)

    flt = build_filter(query)
    resp = do_search(conn, flt)
    entries = [it for it in resp if isinstance(it, ldapasn1.SearchResultEntry)]

    if not entries:
        return None, ""

    chosen, attrs = choose_best_match(entries, query)
    if not chosen:
        chosen = entries[0]
        attrs = entry_to_dict(chosen)

    dn = str(chosen['objectName'])
    return attrs, dn

# ----------------- MAIN -----------------
def main():
    agi_read_env()

    for v in [
        "ASR", "ASR_LANG", "ASR_CONFIDENCE",
        "AD_PHONE", "AD_DN", "AD_DISPLAYNAME", "AD_MAIL", "AD_MATCHES",
        "ASR_NUMBER"
    ]:
        agi_set_var(v, "")

    if len(sys.argv) < 2:
        agi_set_var("ASR", "ERROR: missing audio")
        return

    audio = sys.argv[1]
    if not os.path.exists(audio):
        agi_set_var("ASR", f"ERROR: File not found {audio}")
        return

    try:
        # --- ASR ---
        text, lang, conf = transcribe(audio)
        agi_set_var("ASR", text)
        agi_set_var("ASR_LANG", lang)
        if conf is not None:
            agi_set_var("ASR_CONFIDENCE", str(conf))

        # --- LDAP ---
        attrs, dn = ldap_lookup(text)

        if not attrs:
            agi_set_var("AD_MATCHES", "0")
            return

        phone = best_phone(attrs)
        display = first(attrs, "displayName") or first(attrs, "cn")
        mail = first(attrs, "mail")

        agi_set_var("AD_MATCHES", "1")
        agi_set_var("AD_PHONE", phone)
        agi_set_var("AD_DN", dn)
        agi_set_var("AD_DISPLAYNAME", display)
        agi_set_var("AD_MAIL", mail)
        agi_set_var("ASR_NUMBER", phone)

    except Exception as e:
        agi_set_var("ASR", f"ERROR: {e}")

if __name__ == "__main__":
    main()

