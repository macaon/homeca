"""Persisted interface and OIDC configuration; no CA issuance logic."""
import base64
import json
import os
import ssl
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from authlib.integrations.starlette_client import OAuth
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import HTTPException
from . import ca
from .store import db


def saved(key):
    with db() as c:
        value = ca.setting(c, key)
    return json.loads(value) if value is not None else None


def save(key, value):
    with db() as c:
        ca.set_setting(c, key, json.dumps(value))


def cipher():
    # Derive a separate encryption key from the existing master key; backups stay unchanged.
    return Fernet(base64.urlsafe_b64encode(ca.derived_secret(b'homeca oidc configuration v1')))


def normalize_issuer(value):
    value = value.strip().rstrip('/')
    suffix = '/.well-known/openid-configuration'
    return value[:-len(suffix)] if value.endswith(suffix) else value


def oidc_options():
    value = saved('oidc_config')
    if value is not None:
        return value
    issuer = normalize_issuer(os.environ.get('HOMECA_OIDC_ISSUER', ''))
    client = os.environ.get('HOMECA_OIDC_CLIENT_ID', '')
    secret_file = os.environ.get('HOMECA_OIDC_CLIENT_SECRET_FILE')
    allowed = os.environ.get('HOMECA_OIDC_ADMIN_MATCH', '')
    return {'enabled':bool(issuer and client and secret_file and allowed), 'issuer':issuer,
            'client_id':client, 'allowed_users':allowed, 'secret_enc':''}


def secret_value(value):
    if value['secret_enc']:
        return cipher().decrypt(value['secret_enc'].encode()).decode()
    path = os.environ.get('HOMECA_OIDC_CLIENT_SECRET_FILE')
    return Path(path).read_text().strip() if path and saved('oidc_config') is None else ''


def trust_entries():
    return saved('trusted_certificates') or []


@lru_cache(maxsize=4)
def provider(serialized):
    value = json.loads(serialized)
    context = ssl.create_default_context()
    # Retain the deployment's CA file as well as the shared UI trust store.
    path = os.environ.get('HOMECA_OIDC_CA_FILE')
    if path:
        context.load_verify_locations(cafile=path)
    for cert in trust_entries():
        context.load_verify_locations(cadata=cert['pem'])
    registry = OAuth()
    registry.register('oidc', server_metadata_url=value['issuer']+'/.well-known/openid-configuration',
                      client_id=value['client_id'], client_secret=secret_value(value),
                      client_kwargs={'scope':'openid profile email', 'code_challenge_method':'S256', 'verify':context})
    return registry


def runtime():
    value = oidc_options()
    return (provider(json.dumps(value, sort_keys=True)) if value['enabled'] else None), value


def update_oidc(body):
    old = oidc_options()
    value = body.model_dump(exclude={'client_secret'})
    value['issuer'] = normalize_issuer(value['issuer'])
    value['client_id'] = value['client_id'].strip()
    value['allowed_users'] = value['allowed_users'].strip()
    secret = body.client_secret or secret_value(old)
    parsed = urlsplit(value['issuer'])
    if value['enabled']:
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise HTTPException(400, 'Issuer must be an HTTPS URL')
        if not value['client_id'] or not secret or not value['allowed_users']:
            raise HTTPException(400, 'Client ID, secret and allowed administrator identities are required')
    value['secret_enc'] = cipher().encrypt(secret.encode()).decode() if secret else ''
    save('oidc_config', value)
    provider.cache_clear()


def public_trust():
    return [{k:v for k,v in entry.items() if k != 'pem'} for entry in trust_entries()]


def add_trust(name, encoded):
    try:
        raw = base64.b64decode(encoded, validate=True)
        if b'PRIVATE KEY' in raw:
            raise ValueError('Private keys are never accepted')
        certs = x509.load_pem_x509_certificates(raw) if b'-----BEGIN CERTIFICATE' in raw else [x509.load_der_x509_certificate(raw)]
        if not certs:
            raise ValueError('No certificates found')
    except ValueError:
        raise HTTPException(400, 'Upload public PEM or DER certificates, never private keys')
    with db() as c:
        entries = json.loads(ca.setting(c, 'trusted_certificates') or '[]')
        fingerprints = {entry['fingerprint'] for entry in entries}
        added = 0
        for cert in certs:
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            if fingerprint in fingerprints:
                continue
            entries.append({'name':name.strip(), 'fingerprint':fingerprint, 'subject':cert.subject.rfc4514_string(),
                            'expires':cert.not_valid_after_utc.isoformat(),
                            'pem':cert.public_bytes(serialization.Encoding.PEM).decode()})
            fingerprints.add(fingerprint)
            added += 1
        ca.set_setting(c, 'trusted_certificates', json.dumps(entries))
    provider.cache_clear()
    return added
