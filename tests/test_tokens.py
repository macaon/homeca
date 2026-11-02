"""Read-only API tokens and the summary endpoint they exist for."""
import pytest
from fastapi.testclient import TestClient
from app import apitokens, main, store

PASSWORD = 'test-administrator-password'


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    monkeypatch.setattr(main.time, 'sleep', lambda _: None)
    main.SESSIONS.clear()
    apitokens.INVALID.clear()
    c = TestClient(main.app)
    assert c.post('/api/setup', json={'username': 'owner', 'password': PASSWORD}).status_code == 200
    yield c
    main.SESSIONS.clear()


def make_token(client, name='HomeDash', **extra):
    response = client.post('/api/tokens', json={'name': name, 'scope': 'read', **extra})
    assert response.status_code == 200, response.text
    return response.json()['token']


def bearer(token):
    return {'Authorization': 'Bearer ' + token}


def build_pki(client, leaf_days=90):
    root = client.post('/api/certs', json={'kind': 'root', 'subject': {'cn': 'Test Root'}, 'days': 3650}).json()['id']
    inter = client.post('/api/certs', json={'kind': 'intermediate', 'parent_id': root, 'subject': {'cn': 'Test Intermediate'},
                                            'days': 1000, 'path_len': 0}).json()['id']
    leaf = client.post('/api/certs', json={'kind': 'leaf', 'parent_id': inter, 'subject': {'cn': 'host.example'},
                                           'sans': ['host.example'], 'days': leaf_days}).json()['id']
    return root, inter, leaf


def test_token_is_shown_once_and_stored_only_as_a_hash(client):
    token = make_token(client)
    assert token.startswith('homeca_') and len(token) > 40
    with store.db() as c:
        assert token not in str(c.execute('SELECT * FROM api_tokens').fetchall()[0]['token_hash'])
        assert all(token not in str(tuple(row)) for row in c.execute('SELECT * FROM api_tokens'))
    listing = client.get('/api/tokens').json()
    assert token not in str(listing) and listing['tokens'][0]['owner'] == 'owner'
    assert [s['id'] for s in listing['scopes']] == ['read']
    assert client.post('/api/tokens', json={'name': 'HomeDash', 'scope': 'read'}).status_code == 409
    assert client.post('/api/tokens', json={'name': 'x', 'scope': 'update'}).status_code == 400


def test_token_opens_the_summary_and_nothing_else(client):
    root, inter, leaf = build_pki(client)
    token = make_token(client)
    anonymous = TestClient(main.app)
    assert anonymous.get('/api/summary').status_code == 401
    assert anonymous.get('/api/summary', headers=bearer(token)).status_code == 200
    for method, path in [('GET', '/api/certs'), ('GET', f'/api/certs/{leaf}'), ('GET', f'/api/certs/{leaf}/download?format=key'),
                         ('GET', '/api/audit'), ('GET', '/api/tokens'), ('GET', '/api/users'), ('GET', '/api/settings'),
                         ('POST', f'/api/certs/{leaf}/revoke'), ('DELETE', f'/api/certs/{leaf}'), ('POST', '/api/tokens'),
                         ('DELETE', '/api/tokens/anything'), ('POST', '/api/acme/ca')]:
        response = anonymous.request(method, path, headers=bearer(token), json={'name': 'x', 'scope': 'read', 'reason': 'unspecified', 'id': None})
        assert response.status_code == 401, (method, path, response.status_code)


def test_a_bad_bearer_never_falls_back_to_the_session(client):
    assert client.get('/api/summary').status_code == 200  # the session alone works
    assert client.get('/api/summary', headers=bearer('homeca_wrong')).status_code == 401


def test_summary_counts_and_attention_follow_the_ui_rule(client):
    root, inter, leaf = build_pki(client, leaf_days=10)
    token = make_token(client)
    summary = client.get('/api/summary', headers=bearer(token)).json()
    assert (summary['roots'], summary['intermediates'], summary['active_leaves'], summary['expiring'],
            summary['expired'], summary['revoked']) == (1, 1, 1, 1, 0, 0)
    assert [(x['cn'], x['status']) for x in summary['attention']] == [('host.example', 'expiring')]
    assert {a['cn'] for a in summary['authorities']} == {'Test Root', 'Test Intermediate'}
    assert all(not a['crl_overdue'] and a['days_left'] > 900 for a in summary['authorities'])
    assert summary['acme'] == {'enabled': False, 'ca': None}
    # renewing supersedes the old leaf: it stops counting and stops needing attention
    client.post(f'/api/certs/{leaf}/renew')
    client.post(f'/api/certs/{leaf}/revoke', json={'reason': 'superseded'})
    summary = client.get('/api/summary', headers=bearer(token)).json()
    assert (summary['expiring'], summary['revoked']) == (1, 1) and len(summary['attention']) == 1
    # nothing that identifies or could reproduce a certificate or key leaves the server
    text = str(summary)
    for forbidden in ('BEGIN', 'PRIVATE', 'sans', 'serial', 'key_enc', 'cert_pem'):
        assert forbidden not in text


def test_overdue_crl_is_reported(client):
    root, inter, leaf = build_pki(client)
    with store.db() as c:
        c.execute("UPDATE certs SET crl_next='2000-01-01T00:00:00+00:00' WHERE id=?", (inter,))
    summary = client.get('/api/summary').json()
    assert {a['cn']: a['crl_overdue'] for a in summary['authorities']} == {'Test Root': False, 'Test Intermediate': True}


def test_expiry_revocation_and_owner_removal_end_a_token(client):
    client.post('/api/users', json={'username': 'two', 'password': PASSWORD + '-two'})
    two = TestClient(main.app)
    two.post('/api/login', json={'username': 'two', 'password': PASSWORD + '-two'})
    keep, expiring, revoked, owned = (make_token(client, 'keep'), make_token(client, 'short', expires_days=1),
                                      make_token(client, 'gone'), make_token(two, 'two-token'))
    anonymous = TestClient(main.app)
    with store.db() as c:
        c.execute("UPDATE api_tokens SET expires='2000-01-01T00:00:00+00:00' WHERE name='short'")
    token_id = next(t['id'] for t in client.get('/api/tokens').json()['tokens'] if t['name'] == 'gone')
    assert client.delete('/api/tokens/' + token_id).status_code == 200
    status = lambda token: anonymous.get('/api/summary', headers=bearer(token)).status_code  # noqa: E731
    assert (status(keep), status(expiring), status(revoked), status(owned)) == (200, 401, 401, 200)
    assert client.delete('/api/users/two').status_code == 200
    assert status(owned) == 401
    with store.db() as c:
        assert c.execute("SELECT count(*) FROM api_tokens WHERE owner='two'").fetchone()[0] == 0


def test_invalid_tokens_are_throttled_but_valid_ones_are_not(client):
    token = make_token(client)
    anonymous = TestClient(main.app)
    codes = [anonymous.get('/api/summary', headers=bearer('homeca_wrong')).status_code for _ in range(12)]
    assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]
    assert anonymous.get('/api/summary', headers=bearer(token)).status_code == 200


def test_token_use_is_tracked_and_lifecycle_is_audited_without_the_token(client):
    token = make_token(client, expires_days=30)
    assert client.get('/api/tokens').json()['tokens'][0]['last_used'] is None
    TestClient(main.app).get('/api/summary', headers=bearer(token))
    listing = client.get('/api/tokens').json()['tokens'][0]
    assert listing['last_used'] and listing['expires'] and not listing['expired']
    client.delete('/api/tokens/' + listing['id'])
    log = client.get('/api/audit?limit=50').json()['entries']
    assert [e['action'] for e in reversed(log)][1:] == ['API token created', 'API token revoked']
    assert token not in str(log) and 'expires in 30 days' in str(log)
