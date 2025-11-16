#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from impacket.ldap import ldap, ldapasn1

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

def agi_read_env():
    while True:
        line = sys.stdin.readline()
        if not line or line.strip() == '':
            break

def agi_set_var(name, value):
    value = '' if value is None else str(value)
    print(f'SET VARIABLE {name} "{value}"')
    sys.stdout.flush()
    sys.stdin.readline()

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
    for k in PHONE_PREF:
        v = attrs.get(k)
        if v:
            return v[0] if isinstance(v, (list, tuple)) else str(v)
    return ''

def build_filter(query, mode='both'):
    q = escape_filter_value(query)
    contains = f'*{q}*'
    user_block = '(&(objectClass=user)(!(objectClass=computer)))'
    contact_block = '(objectClass=contact)'
    if mode == 'users':
        who = user_block
    elif mode == 'contacts':
        who = contact_block
    else:
        who = f'(|{user_block}{contact_block})'
    fields = (
        '(|'
        f'(sAMAccountName={q})'
        f'(userPrincipalName={q})'
        f'(cn={q})'
        f'(displayName={q})'
        f'(givenName={q})'
        f'(sn={q})'
        f'(name={q})'
        f'(cn={contains})'
        f'(displayName={contains})'
        f'(givenName={contains})'
        f'(sn={contains})'
        f'(name={contains})'
        ')'
    )
    return f'(&{who}{fields})'

def choose_best_match(items, query):
    q = query.lower()
    ranked = []
    for it in items:
        attrs = entry_to_dict(it)
        classes = [c.lower() for c in attrs.get('objectClass', [])]
        is_user = 1 if 'user' in classes and 'computer' not in classes else 0
        is_contact = 1 if 'contact' in classes else 0
        sAM  = first(attrs, 'sAMAccountName').lower()
        upn  = first(attrs, 'userPrincipalName').lower()
        cn   = first(attrs, 'cn').lower()
        disp = first(attrs, 'displayName').lower()
        has_phone  = 1 if best_phone(attrs) else 0
        exact_user = 2 if (sAM == q or upn == q) else 0
        exact_name = 1 if (cn == q or disp == q) else 0
        score = (is_user, 0 if is_contact else 1, exact_user, exact_name, has_phone)
        ranked.append((score, it, attrs))
    ranked.sort(key=lambda t: t[0], reverse=True)
    if not ranked:
        return None, None
    return ranked[0][1], ranked[0][2]

def do_search(conn, flt, attrs):
    try:
        return conn.search(searchFilter=flt, attributes=attrs, sizeLimit=999)
    except Exception:
        try:
            return conn.search(flt, attrs)
        except Exception:
            return conn.search(flt)

def main():
    agi_read_env()
    args = sys.argv[1:]
    if not args:
        for v in ['AD_PHONE', 'AD_DN', 'AD_DISPLAYNAME', 'AD_MAIL', 'AD_MATCHES']:
            agi_set_var(v, '')
        return

    query = args[0]

    try:
        conn = ldap.LDAPConnection(f'ldap://{AD_HOST}', AD_BASEDN)
        conn.login(AD_USER, AD_PASS, AD_DOMAIN)

        flt = build_filter(query)
        resp = do_search(conn, flt, ATTRS)
        entries = [it for it in resp if isinstance(it, ldapasn1.SearchResultEntry)]
        agi_set_var('AD_MATCHES', str(len(entries)))

        if not entries:
            for v in ['AD_PHONE', 'AD_DN', 'AD_DISPLAYNAME', 'AD_MAIL']:
                agi_set_var(v, '')
            return

        chosen, attrs = choose_best_match(entries, query)
        if not chosen:
            chosen = entries[0]
            attrs = entry_to_dict(chosen)

        dn    = str(chosen['objectName'])
        phone = best_phone(attrs)
        dname = first(attrs, 'displayName') or first(attrs, 'cn')
        mail  = first(attrs, 'mail')

        agi_set_var('AD_PHONE', phone)
        agi_set_var('AD_DN', dn)
        agi_set_var('AD_DISPLAYNAME', dname)
        agi_set_var('AD_MAIL', mail)

    except Exception:
        for v in ['AD_PHONE', 'AD_DN', 'AD_DISPLAYNAME', 'AD_MAIL', 'AD_MATCHES']:
            agi_set_var(v, '')

if __name__ == '__main__':
    main()
