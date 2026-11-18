"""Model routing with per-provider circuit breakers and ordered fallback. Providers here are mocks."""
from .policy import PROVIDER_CEILING, rank


class ProviderError(Exception):
    pass


class NoRoute(Exception):
    pass


def tokens(text):
    return max(1, len(text.split()))  # lab estimate; a real gateway reads the provider's usage field


class Provider:
    def __init__(self, name, kind, in_per_1k, out_per_1k, fail=False):
        self.name, self.kind, self.in_per_1k, self.out_per_1k, self.fail = name, kind, in_per_1k, out_per_1k, fail

    def complete(self, prompt):
        if self.fail:
            raise ProviderError(self.name)
        return f"[{self.name}] ok"


class Breaker:
    """Opens after 3 straight failures, lets one probe through after 30 seconds."""

    def __init__(self, threshold=3, cooldown=30):
        self.threshold, self.cooldown, self.fails, self.opened = threshold, cooldown, 0, None

    def allow(self, now):
        return self.opened is None or now - self.opened >= self.cooldown

    def ok(self):
        self.fails, self.opened = 0, None

    def fail(self, now):
        self.fails += 1
        if self.fails >= self.threshold:
            self.opened = now


class Router:
    def __init__(self, providers):
        self.providers = providers
        self.breakers = {p.name: Breaker() for p in providers}

    def candidates(self, classification):
        ok = [p for p in self.providers if rank(PROVIDER_CEILING[p.kind]) >= rank(classification)]
        # confidential data prefers self-hosted, everything else the cheapest
        return sorted(ok, key=lambda p: (0 if classification == "confidential" and p.kind == "selfhosted" else 1, p.in_per_1k))

    def route(self, prompt, classification, now):
        tried = []
        for p in self.candidates(classification):
            b = self.breakers[p.name]
            if not b.allow(now):
                tried.append((p.name, "circuit_open"))
                continue
            try:
                text = p.complete(prompt)
            except ProviderError:
                b.fail(now)
                tried.append((p.name, "error"))
                continue
            b.ok()
            tried.append((p.name, "ok"))
            return p, text, tried
        raise NoRoute(tried)
