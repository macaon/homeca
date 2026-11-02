"""Interface/OIDC migration tests against an isolated database, never the live CA."""
import base64
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from app import main, ca, store, preferences, pki
from cryptography.hazmat.primitives import serialization


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    main.SESSIONS.clear()
    preferences.provider.cache_clear()
    client = TestClient(main.app)
    assert client.post('/api/setup', json={'username':'owner','password':'test-only-password-123'}).status_code == 200
    yield client
    main.SESSIONS.clear()
    preferences.provider.cache_clear()


def test_settings_auth_and_login_theme(client):
    anonymous = TestClient(main.app)
    assert anonymous.get('/api/settings').status_code == 401
    assert anonymous.put('/api/settings/interface', json={'theme':'dark'}).status_code == 401
    assert anonymous.get('/api/settings/trust').status_code == 401
    assert anonymous.get('/api/state').json()['ui']['theme'] == 'auto'
    assert client.put('/api/settings/interface', json={'theme':'dark'}).status_code == 200
    assert 'data-theme="dark"' in anonymous.get('/').text
    assert anonymous.get('/api/state').json()['ui']['theme'] == 'dark'
    assert client.put('/api/settings/interface', json={'theme':'invalid'}).status_code == 400
    client.put('/api/settings/interface', json={'theme':'auto'})
    assert '<html lang="en">' in anonymous.get('/').text


def test_oidc_discovery_secret_retention_and_explicit_admins(client):
    config={'enabled':True,'issuer':'https://id.example.net/realm/.well-known/openid-configuration/',
            'client_id':'homeca','client_secret':'test-only-provider-secret','allowed_users':'owner'}
    response=client.put('/api/settings/oidc',json=config)
    assert response.status_code == 200
    value=response.json()['settings']
    assert value['oidc']['issuer']=='https://id.example.net/realm'
    assert value['oidc_secret_configured']
    assert 'test-only-provider-secret' not in response.text
    saved=preferences.oidc_options()
    assert preferences.secret_value(saved)=='test-only-provider-secret'
    assert saved['secret_enc']!='test-only-provider-secret'
    config.update(client_secret='',client_id='updated')
    assert client.put('/api/settings/oidc',json=config).status_code==200
    assert preferences.secret_value(preferences.oidc_options())=='test-only-provider-secret'
    config['allowed_users']=''
    assert client.put('/api/settings/oidc',json=config).status_code==400
    config.update(allowed_users='owner',issuer='http://id.example.net')
    assert client.put('/api/settings/oidc',json=config).status_code==400


def test_environment_config_migrates_on_first_save(client, monkeypatch, tmp_path):
    secret=tmp_path/'oidc-secret';secret.write_text('existing-test-secret')
    monkeypatch.setenv('HOMECA_OIDC_ISSUER','https://id.example.net')
    monkeypatch.setenv('HOMECA_OIDC_CLIENT_ID','existing-client')
    monkeypatch.setenv('HOMECA_OIDC_CLIENT_SECRET_FILE',str(secret))
    monkeypatch.setenv('HOMECA_OIDC_ADMIN_MATCH','owner')
    assert preferences.oidc_options()['enabled']
    response=client.put('/api/settings/oidc',json={'enabled':True,'issuer':'https://id.example.net','client_id':'existing-client','allowed_users':'owner'})
    assert response.status_code==200
    assert preferences.secret_value(preferences.oidc_options())=='existing-test-secret'
    secret.unlink()
    assert preferences.secret_value(preferences.oidc_options())=='existing-test-secret'


def test_trust_rejects_private_keys(client):
    encoded=base64.b64encode(b'-----BEGIN PRIVATE KEY-----\nnot-a-certificate').decode()
    assert client.post('/api/settings/trust',json={'name':'bad','certificate':encoded}).status_code==400
    assert client.get('/api/settings/trust').json()==[]


def test_oidc_failure_is_login_feedback(client, monkeypatch):
    def broken():
        raise RuntimeError('CERTIFICATE_VERIFY_FAILED secret-do-not-leak')
    monkeypatch.setattr(preferences,'runtime',broken)
    response=client.get('/login/oidc',follow_redirects=False)
    assert response.status_code==307
    assert response.headers['location']=='/?sso_error=tls'
    assert 'secret-do-not-leak' not in response.text

@pytest.mark.parametrize('claims,allowed,success', [
    ({'sub':'1','preferred_username':'owner'},'owner',True),
    ({'sub':'2','preferred_username':'stranger'},'owner',False),
    ({'sub':'3','email':'owner@example.net','email_verified':False},'owner@example.net',False),
    ({'sub':'3','email':'owner@example.net','email_verified':True},'owner@example.net',True),
    ({'preferred_username':'owner'},'owner',False),
])
def test_oidc_callback_requires_valid_subject_and_allowed_identity(client,monkeypatch,claims,allowed,success):
    from fastapi.responses import RedirectResponse
    options={'enabled':True,'issuer':'https://id.example.net','client_id':'test','secret_enc':'test','allowed_users':allowed}
    class OIDC:
        async def authorize_redirect(self,request,callback):
            return RedirectResponse('https://id.example.net/authorize')
        async def authorize_access_token(self,request):
            return {'userinfo':claims}
    monkeypatch.setattr(preferences,'runtime',lambda:(SimpleNamespace(oidc=OIDC()),options))
    browser=TestClient(main.app)
    assert browser.get('/login/oidc',follow_redirects=False).status_code==307
    response=browser.get('/auth/callback',follow_redirects=False)
    assert response.headers['location']==('/' if success else '/?sso_error=failed')
    assert browser.get('/api/state').json()['logged_in']==success


def test_oidc_callback_rejects_configuration_change(client,monkeypatch):
    from fastapi.responses import RedirectResponse
    options={'enabled':True,'issuer':'https://id.example.net','client_id':'test','secret_enc':'test','allowed_users':'owner'}
    class OIDC:
        async def authorize_redirect(self,request,callback):
            return RedirectResponse('https://id.example.net/authorize')
        async def authorize_access_token(self,request):
            raise AssertionError('Do not exchange a code after provider changes')
    monkeypatch.setattr(preferences,'runtime',lambda:(SimpleNamespace(oidc=OIDC()),options))
    browser=TestClient(main.app)
    browser.get('/login/oidc',follow_redirects=False)
    options['issuer']='https://different.example.net'
    assert browser.get('/auth/callback',follow_redirects=False).headers['location']=='/?sso_error=failed'
    assert not browser.get('/api/state').json()['logged_in']


def test_date_format_is_per_account_and_validated(client):
    assert client.get('/api/state').json()['date_format'] == 'auto'
    assert client.put('/api/preferences', json={'date_format':'iso'}).json() == {'date_format':'iso'}
    assert client.get('/api/state').json()['date_format'] == 'iso'
    assert client.put('/api/preferences', json={'date_format':'klingon'}).status_code == 422
    assert TestClient(main.app).get('/api/preferences').status_code == 401
