"""Rate limits per principal and monthly budgets per team."""


class TokenBucket:
    def __init__(self, per_minute, burst):
        self.rate, self.burst, self.level, self.t = per_minute / 60.0, burst, burst, None

    def take(self, now):
        if self.t is not None:
            self.level = min(self.burst, self.level + (now - self.t) * self.rate)
        self.t = now
        if self.level >= 1:
            self.level -= 1
            return True
        return False


class Budgets:
    """ok under 80%, warn from 80%, deny at 100%."""

    def __init__(self, limits):
        self.limits, self.spent = dict(limits), {}

    def check(self, team):
        lim = self.limits.get(team)
        if lim is None:
            return "deny"
        used = self.spent.get(team, 0.0)
        return "deny" if used >= lim else "warn" if used >= 0.8 * lim else "ok"

    def add(self, team, usd):
        self.spent[team] = self.spent.get(team, 0.0) + usd

    def report(self):
        """Spend against budget per team, for the monthly cost review."""
        return [{"team": t, "spent_usd": round(self.spent.get(t, 0.0), 4), "limit_usd": lim,
                 "used_pct": round(100 * self.spent.get(t, 0.0) / lim, 1), "state": self.check(t)}
                for t, lim in sorted(self.limits.items())]
