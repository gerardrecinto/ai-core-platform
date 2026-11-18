"""Approved skill and tool registry. A tool runs only if it was approved by someone other than its owner,
the caller's role is allowed, the data class fits, and the manifest digest still matches the approved one."""
import hashlib
import json

from . import policy

REQUIRED = {"name", "version", "description", "allowed_roles", "data_class_max", "entrypoint"}


class RegistryError(Exception):
    pass


def digest(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Registry:
    def __init__(self, audit):
        self.items, self.audit = {}, audit

    def submit(self, manifest, owner):
        if set(manifest) != REQUIRED or manifest["data_class_max"] not in policy.CLASSES:
            raise RegistryError("invalid manifest")
        k = (manifest["name"], manifest["version"])
        if k in self.items:
            raise RegistryError("version exists, publish a new version")
        d = digest(manifest)
        self.items[k] = {"manifest": dict(manifest), "digest": d, "owner": owner, "status": "pending", "approver": None}
        self.audit.record(owner, "registry.submit", f"{k[0]}@{k[1]}:{d[:12]}")
        return d

    def _gate(self, reviewer, roles, key):
        if "ai-admin" not in roles:
            raise RegistryError("reviewer needs ai-admin")
        it = self.items.get(key)
        if not it:
            raise RegistryError("unknown tool")
        if it["owner"] == reviewer:
            raise RegistryError("owner cannot approve own tool")
        return it

    def approve(self, name, version, reviewer, roles):
        it = self._gate(reviewer, roles, (name, version))
        it["status"], it["approver"] = "approved", reviewer
        self.audit.record(reviewer, "registry.approve", f"{name}@{version}")

    def revoke(self, name, version, reviewer, roles):
        it = self._gate(reviewer, roles, (name, version))
        it["status"] = "revoked"
        self.audit.record(reviewer, "registry.revoke", f"{name}@{version}")

    def resolve(self, name, version, caller, roles, data_class, pin=None):
        it = self.items.get((name, version))
        if not it or it["status"] != "approved":
            raise RegistryError("not approved")
        m = it["manifest"]
        if digest(m) != it["digest"] or (pin and pin != it["digest"]):
            raise RegistryError("digest mismatch")
        if not set(roles) & set(m["allowed_roles"]):
            raise RegistryError("role not allowed")
        if policy.rank(data_class) > policy.rank(m["data_class_max"]):
            raise RegistryError("data class too high for this tool")
        self.audit.record(caller, "tool.call", f"{name}@{version}:{it['digest'][:12]}")
        return m

    def approved(self):
        return [i["manifest"] for i in self.items.values() if i["status"] == "approved"]
