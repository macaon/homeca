"""Shared login protection for Home* apps: vendor unchanged. It limits failed sign-ins and finds the real client address.

Create one guard at start-up and call it around every password check:

    guard = LoginGuard(parse_networks(os.environ.get('HOMEAPP_TRUSTED_PROXIES', '')),
                       on_block=lambda username, source: audit(username, 'Sign-in blocked', detail=source))
    guard.check(request, username)            # before verifying the password; raises HTTP 429 once the limit is reached
    if not password_ok:
        if guard.fail(request, username):     # True at most once a minute per source: write the audit entry then
            audit(username, 'Sign-in failed', detail=guard.source(request))
        raise HTTPException(401, 'Incorrect username or password')
    guard.success(request, username)

Behind a reverse proxy every request arrives from the proxy's address. List the proxy's address or network in the app's
trusted-proxies setting and the guard reads the real client from X-Forwarded-For, but only for requests that come from
a listed proxy. Everyone else's header is ignored, so it cannot be used to pick a source address. With nothing listed
the connection address is used, which is always safe but makes everyone behind one proxy share a limit.
"""
import ipaddress
import time

from fastapi import HTTPException


def parse_networks(text):
    """'10.0.0.0/8, 172.28.0.1' -> networks. A typo raises ValueError so it fails at start-up, not silently."""
    return tuple(ipaddress.ip_network(part.strip(), strict=False) for part in str(text or '').replace(';', ',').split(',') if part.strip())


def _inside(address, networks):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip.version == network.version and ip in network for network in networks)


def client_ip(request, networks=()):
    """The connection address, or, when that is a trusted proxy, the nearest address in X-Forwarded-For that is not."""
    peer = request.client.host if request.client else ''
    if not networks or not _inside(peer, networks):
        return peer
    hops = [hop.strip() for hop in request.headers.get('x-forwarded-for', '').split(',') if hop.strip()]
    for hop in reversed(hops):  # the proxies we trust append to the right; anything left of them is the client's claim
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            return peer  # malformed: trust nothing in this header
        if not _inside(hop, networks):
            return hop
    return hops[0] if hops else peer  # every hop is one of our proxies: the client is the first of them


class LoginGuard:
    """Counts failed sign-ins per source and username (`limit`) and per source overall (`per_source`) inside `window`
    seconds. Successful sign-ins are never counted, and clear that username's failures."""

    def __init__(self, networks=(), limit=10, per_source=30, window=300, audit_gap=60, on_block=None, clock=time.monotonic):
        self.networks, self.limit, self.per_source, self.window, self.audit_gap = tuple(networks), limit, per_source, window, audit_gap
        self.on_block, self.clock = on_block, clock
        self.failures, self.blocked, self.audited = {}, {}, {}

    def source(self, request):
        return client_ip(request, self.networks)

    @staticmethod
    def _name(username):
        return str(username).strip().casefold()[:100]

    def _recent(self, key, now):
        recent = [t for t in self.failures.get(key, ()) if now - t < self.window]
        if recent:
            self.failures[key] = recent
        else:
            self.failures.pop(key, None)
        return recent

    def _bound(self):
        if len(self.failures) + len(self.blocked) + len(self.audited) > 50000:  # a flood of distinct names must not grow memory without limit
            self.failures.clear(), self.blocked.clear(), self.audited.clear()

    def check(self, request, username):
        now, source, name = self.clock(), self.source(request), self._name(username)
        if len(self._recent(('user', source, name), now)) >= self.limit or len(self._recent(('source', source), now)) >= self.per_source:
            if self.on_block and now - self.blocked.get((source, name), -self.window) >= self.window:
                self.blocked[(source, name)] = now  # announce the block once, not on every refused attempt
                self.on_block(str(username)[:100], source)
            raise HTTPException(429, 'Too many attempts. Try again in five minutes.', headers={'Retry-After': str(self.window)})

    def fail(self, request, username):
        """Record a failed attempt. True when it should also be written to the audit log (once per source per `audit_gap`)."""
        now, source = self.clock(), self.source(request)
        self._bound()
        for key in (('user', source, self._name(username)), ('source', source)):
            self.failures[key] = self._recent(key, now) + [now]
        if now - self.audited.get(source, -self.audit_gap) >= self.audit_gap:
            self.audited[source] = now
            return True
        return False

    def success(self, request, username):
        self.failures.pop(('user', self.source(request), self._name(username)), None)
