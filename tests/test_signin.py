"""Sign-in limits, and which client address HomeCA believes behind a reverse proxy."""
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app import apitokens, home_security, main, store

PASSWORD = 'test-administrator-password'
WRONG = 'a wrong password value'


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    main.SESSIONS.clear()
    for g in (main.guard, apitokens.token_guard):
        g.failures.clear(), g.blocked.clear(), g.audited.clear()
    c = TestClient(main.app)
    assert c.post('/api/setup', json={'username': 'owner', 'password': PASSWORD}).status_code == 200
    yield c
    main.SESSIONS.clear()


def login(client, password=WRONG, user='owner', headers=None):
    return client.post('/api/login', json={'username': user, 'password': password}, headers=headers or {}).status_code


def log(client):
    return client.get('/api/audit?limit=200').json()['entries']


def test_ten_failures_block_further_attempts_until_the_window_passes(client):
    other = TestClient(main.app)
    assert [login(other) for _ in range(12)] == [401] * 10 + [429] * 2
    assert login(other, PASSWORD) == 429  # even the right password while blocked
    assert login(other, WRONG, user='someone-else') == 401  # other accounts are untouched
    assert sum(e['action'] == 'Sign-in blocked' for e in log(client)) == 1  # announced once
    main.guard.failures.clear()
    assert login(other, PASSWORD) == 200


def test_login_no_longer_sleeps_a_thread(client):
    with patch('time.sleep') as sleep:
        login(TestClient(main.app))
    sleep.assert_not_called()


def test_a_stolen_session_cannot_guess_the_current_password(client):
    codes = [client.post('/api/password', json={'current': WRONG, 'new': 'another-test-password'}).status_code for _ in range(12)]
    assert codes == [403] * 10 + [429] * 2
    assert main.SESSIONS  # the session itself survives; only guessing is stopped
    assert any(e['action'] == 'Password change refused' for e in log(client))


def test_the_real_client_is_used_only_behind_a_trusted_proxy(client):
    proxy = TestClient(main.app, client=('172.28.0.1', 50000))
    with patch.object(main.guard, 'networks', ()):  # nothing trusted: rotating the header gains nothing
        assert [login(proxy, headers={'X-Forwarded-For': f'198.51.100.{n}'}) for n in range(11)] == [401] * 10 + [429]
    main.guard.failures.clear()
    with patch.object(main.guard, 'networks', home_security.parse_networks('172.28.0.1')):
        assert [login(proxy, headers={'X-Forwarded-For': '198.51.100.7'}) for _ in range(11)] == [401] * 10 + [429]
        assert login(proxy, PASSWORD, headers={'X-Forwarded-For': '192.0.2.44'}) == 200  # the administrator is not locked out
        assert [e['detail'] for e in log(client) if e['action'] == 'Signed in'][0] == '192.0.2.44'
        stranger = TestClient(main.app, client=('203.0.113.9', 50000))  # not a proxy: its header is ignored
        assert [login(stranger, headers={'X-Forwarded-For': '192.0.2.44'}) for _ in range(11)] == [401] * 10 + [429]


def test_invalid_token_throttle_follows_the_same_rule(client):
    token = client.post('/api/tokens', json={'name': 'HomeDash', 'scope': 'read'}).json()['token']
    anonymous = TestClient(main.app)
    bearer = lambda t: {'Authorization': 'Bearer ' + t}  # noqa: E731
    assert [anonymous.get('/api/summary', headers=bearer('homeca_wrong')).status_code for _ in range(12)] == [401] * 10 + [429] * 2
    assert anonymous.get('/api/summary', headers=bearer(token)).status_code == 200  # a valid token is never throttled
