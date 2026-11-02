"""The audit log: who did what, never secrets, administrators only, bounded."""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from app import apitokens, auditlog, main, store

PASSWORD = 'test-administrator-password'


def reset_guards():
    for g in (main.guard, apitokens.token_guard):
        g.failures.clear(), g.blocked.clear(), g.audited.clear()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    main.SESSIONS.clear()
    reset_guards()
    c = TestClient(main.app)
    assert c.post('/api/setup', json={'username': 'owner', 'password': PASSWORD}).status_code == 200
    yield c
    main.SESSIONS.clear()


def entries(client):
    response = client.get('/api/audit?limit=200')
    assert response.status_code == 200
    return response.json()['entries']


def actions(client):
    return [e['action'] for e in reversed(entries(client))]


def test_accounts_and_settings_are_recorded_without_secrets(client):
    other = TestClient(main.app)
    other.post('/api/login', json={'username': 'owner', 'password': 'wrong password value'})
    client.post('/api/users', json={'username': 'two', 'password': PASSWORD + '-two'})
    client.put('/api/users/two/password', json={'password': PASSWORD + '-reset'})
    client.put('/api/settings/oidc', json={'enabled': False, 'client_secret': 'test-secret-value'})
    client.put('/api/settings/interface', json={'theme': 'dark'})
    client.delete('/api/users/two')
    assert actions(client) == ['Administrator created', 'Sign-in failed', 'User added', 'Password reset',
                               'OIDC settings changed', 'Interface settings changed', 'User removed']
    assert {e['actor'] for e in entries(client)} == {'owner'}
    text = str(entries(client))
    for secret in (PASSWORD, 'wrong password value', 'test-secret-value'):
        assert secret not in text


def test_sign_in_and_password_change_are_recorded(client):
    two = TestClient(main.app)
    client.post('/api/users', json={'username': 'two', 'password': PASSWORD + '-two'})
    assert two.post('/api/login', json={'username': 'two', 'password': PASSWORD + '-two'}).status_code == 200
    assert two.post('/api/password', json={'current': PASSWORD + '-two', 'new': 'a-different-password'}).status_code == 200
    log = [(e['actor'], e['action']) for e in entries(client)]
    assert ('two', 'Signed in') in log and ('two', 'Password changed') in log
    assert 'a-different-password' not in str(entries(client))


def test_certificate_lifecycle_and_key_downloads(client):
    root = client.post('/api/certs', json={'kind': 'root', 'subject': {'cn': 'Test Root'}, 'days': 3650}).json()['id']
    inter = client.post('/api/certs', json={'kind': 'intermediate', 'parent_id': root, 'subject': {'cn': 'Test Intermediate'},
                                            'days': 1000, 'path_len': 0}).json()['id']
    leaf = client.post('/api/certs', json={'kind': 'leaf', 'parent_id': inter, 'subject': {'cn': 'host.example'},
                                           'sans': ['host.example'], 'days': 90}).json()['id']
    assert client.get(f'/api/certs/{leaf}/download?format=pem').status_code == 200  # public material: not recorded
    assert client.get(f'/api/certs/{leaf}/download?format=key').status_code == 200
    assert client.get(f'/api/certs/{leaf}/download?format=p12&pw_p12=x').status_code == 200
    assert client.get(f'/api/certs/{leaf}/download?format=bogus').status_code == 400  # nothing was delivered
    renewed = client.post(f'/api/certs/{leaf}/renew').json()['id']
    client.post(f'/api/certs/{leaf}/revoke', json={'reason': 'superseded'})
    client.delete(f'/api/certs/{leaf}')
    assert actions(client)[1:] == ['Certificate created'] * 3 + ['Private key downloaded', 'PKCS#12 bundle downloaded',
                                                                  'Certificate renewed', 'Certificate revoked', 'Certificate deleted']
    log = {e['action']: e for e in entries(client)}
    assert log['Certificate revoked']['target'] == 'host.example' and 'superseded' in log['Certificate revoked']['detail']
    assert f'replaced by {renewed}' in log['Certificate renewed']['detail']
    text = str(entries(client))
    assert 'PRIVATE KEY' not in text and 'BEGIN' not in text


def test_acme_ca_selection_is_recorded(client):
    client.post('/api/acme/ca', json={'id': None})
    assert actions(client)[-1] == 'ACME issuing CA changed'


def test_audit_is_for_signed_in_administrators_only_and_paginates(client):
    for n in range(5):
        auditlog.audit('owner', 'Event', str(n))
    page = client.get('/api/audit?limit=3').json()
    assert [e['target'] for e in page['entries']] == ['4', '3', '2'] and page['more']
    older = client.get('/api/audit?limit=3&before=%d' % page['entries'][-1]['id']).json()
    assert [e['target'] for e in older['entries']][:2] == ['1', '0']
    assert TestClient(main.app).get('/api/audit').status_code == 401


def test_audit_is_bounded_and_failed_sign_ins_are_throttled(client):
    with patch.object(auditlog, 'AUDIT_ROWS', 3):
        for n in range(10):
            auditlog.audit('owner', 'Event', str(n))
    assert [e['target'] for e in entries(client)] == ['9', '8', '7']
    other = TestClient(main.app)
    for _ in range(4):
        other.post('/api/login', json={'username': 'owner', 'password': 'wrong'})
    assert sum(e['action'] == 'Sign-in failed' for e in entries(client)) == 1


def test_recording_inside_an_open_write_transaction_does_not_lock(client):
    with store.db() as c:
        c.execute("INSERT OR REPLACE INTO settings VALUES ('probe','1')")  # holds the write lock
        auditlog.audit('system', 'Inside transaction', c=c)
    assert 'Inside transaction' in actions(client)


def test_events_are_also_emitted_as_json_lines(client, capsys):
    import json
    capsys.readouterr()
    auditlog.audit('alice', 'Something happened', 'thing', 'detail')
    event = json.loads(capsys.readouterr().out)
    assert (event['actor'], event['action'], event['target'], event['detail'], event['app']) == ('alice', 'Something happened', 'thing', 'detail', 'homeca')
    assert event['ts'].startswith('20')
