"""Administrator migration, session revocation and SSO account isolation."""
import secrets
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app import main, store, accounts

PASSWORD='test-administrator-password'
@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(store,'DATA',tmp_path)
    main.SESSIONS.clear()
    c=TestClient(main.app)
    assert c.post('/api/setup',json={'username':'owner','password':PASSWORD}).status_code==200
    yield c
    main.SESSIONS.clear()


def login(username,password=PASSWORD):
    c=TestClient(main.app)
    assert c.post('/api/login',json={'username':username,'password':password}).status_code==200
    return c


def test_migrate_recovery_account_and_keep_credentials(client):
    with store.db() as c:
        c.execute('DELETE FROM users')
        original=main.setting(c,'admin_hash')
    assert login('owner').get('/api/users').json()==[{'username':'owner','local':True,'primary':True,'admin':True}]
    with store.db() as c:assert main.setting(c,'admin_hash')==original


def test_management_requires_auth_and_hides_passwords(client):
    anonymous=TestClient(main.app)
    for method,path,body in [('GET','/api/users',None),('POST','/api/users',{'username':'two','password':PASSWORD}),('PUT','/api/users/owner/password',{'password':PASSWORD}),('DELETE','/api/users/owner',None)]:
        assert anonymous.request(method,path,json=body).status_code==401
    assert client.post('/api/users',json={'username':'two','password':PASSWORD}).status_code==200
    assert client.post('/api/users',json={'username':'two','password':PASSWORD}).status_code==409
    text=client.get('/api/users').text
    assert PASSWORD not in text and 'salt' not in text and 'subject' not in text
    assert login('two').get('/api/settings').status_code==200


def test_own_password_preserves_recovery_and_other_sessions(client):
    client.post('/api/users',json={'username':'two','password':PASSWORD})
    two=login('two');other=login('two')
    assert two.post('/api/password',json={'current':PASSWORD,'new':'different-test-password'}).status_code==200
    assert two.get('/api/settings').status_code==200
    assert other.get('/api/settings').status_code==401
    assert client.get('/api/settings').status_code==200
    assert login('owner').get('/api/settings').status_code==200
    login('two','different-test-password')
    with store.db() as c:assert main.setting(c,'admin_user')=='owner'


def test_reset_and_removal_revoke_only_target_and_protect_recovery(client):
    client.post('/api/users',json={'username':'two','password':PASSWORD})
    two=login('two')
    assert client.delete('/api/users/owner').status_code==400
    assert two.delete('/api/users/owner').status_code==400
    assert two.delete('/api/users/two').status_code==400
    assert client.put('/api/users/two/password',json={'password':'new-test-password-123'}).status_code==200
    assert two.get('/api/settings').status_code==401
    two=login('two','new-test-password-123')
    assert client.delete('/api/users/two').status_code==200
    assert two.get('/api/settings').status_code==401
    assert client.get('/api/settings').status_code==200


def test_named_sso_accounts_and_subject_conflicts(client):
    options={'issuer':'https://id.example.net','allowed_users':'owner, sso'}
    with store.db() as c:
        assert accounts.sso_user(c,{'sub':'owner-sub','preferred_username':'owner'},options)=='owner'
        assert accounts.sso_user(c,{'sub':'sso-sub','preferred_username':'sso'},options)=='sso'
    with store.db() as c:
        with pytest.raises(HTTPException):accounts.sso_user(c,{'sub':'other-sub','preferred_username':'owner'},options)
    with store.db() as c:
        with pytest.raises(HTTPException):accounts.sso_user(c,{'sub':'owner-sub','preferred_username':'owner'},{**options,'issuer':'https://different.example.net'})
    users=client.get('/api/users').json()
    assert next(u for u in users if u['username']=='sso')['local'] is False
    with store.db() as c:assert not accounts.check_password(c,'sso',PASSWORD)


def test_removed_sso_cannot_reprovision_from_allowlist(client):
    options={'issuer':'https://id.example.net','allowed_users':'sso'}
    claims={'sub':'sso-sub','preferred_username':'sso'}
    with store.db() as c:accounts.sso_user(c,claims,options)
    assert client.delete('/api/users/sso').status_code==200
    with store.db() as c:
        with pytest.raises(HTTPException):accounts.sso_user(c,claims,options)
    assert client.post('/api/users',json={'username':'sso','password':PASSWORD}).status_code==200
    with store.db() as c:assert accounts.sso_user(c,claims,options)=='sso'


def test_sso_email_must_be_verified_and_legacy_mapping_explicit(client):
    options={'issuer':'https://id.example.net','allowed_users':'owner@example.net'}
    with store.db() as c:
        with pytest.raises(HTTPException):accounts.sso_user(c,{'sub':'1','email':'owner@example.net'},options)
    with store.db() as c:
        assert accounts.sso_user(c,{'sub':'1','email':'owner@example.net','email_verified':True},options,'owner@example.net')=='owner'
