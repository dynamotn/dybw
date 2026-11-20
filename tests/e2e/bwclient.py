"""Independent Bitwarden client used to check what bwss writes.

It shares no code with bwss: key derivation, EncString handling and the REST
calls are re-implemented here on python-cryptography.
"""

import base64
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

b64e = lambda b: base64.b64encode(b).decode()
b64d = base64.b64decode


def http(method, url, body=None, headers=None, form=False):
    data = None
    headers = dict(headers or {})
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            text = r.read().decode()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {url}: HTTP {e.code} {e.read().decode()[:300]}") from None
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text



def stretch(master):
    enc = HKDFExpand(hashes.SHA256(), 32, b"enc").derive(master)
    mac = HKDFExpand(hashes.SHA256(), 32, b"mac").derive(master)
    return enc + mac


def encrypt(plain: bytes, key: bytes) -> str:
    iv = os.urandom(16)
    p = padding.PKCS7(128).padder()
    data = p.update(plain) + p.finalize()
    e = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).encryptor()
    ct = e.update(data) + e.finalize()
    mac = hmac.new(key[32:], iv + ct, hashlib.sha256).digest()
    return f"2.{b64e(iv)}|{b64e(ct)}|{b64e(mac)}"


def rsa_encrypt(public_key: str, plain: bytes) -> str:
    """A type 4 EncString (RSA-OAEP SHA-1) for the base64 DER public key: how an organization key is shared."""
    pub = serialization.load_der_public_key(b64d(public_key))
    oaep = asym.OAEP(mgf=asym.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    return f"4.{b64e(pub.encrypt(plain, oaep))}"


def decrypt(enc: str, key: bytes) -> bytes:
    ty, rest = enc.split(".", 1)
    assert ty == "2", ty
    iv, ct, mac = (b64d(x) for x in rest.split("|"))
    assert hmac.compare_digest(hmac.new(key[32:], iv + ct, hashlib.sha256).digest(), mac), "bad MAC"
    d = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).decryptor()
    padded = d.update(ct) + d.finalize()
    u = padding.PKCS7(128).unpadder()
    return u.update(padded) + u.finalize()


class Account:
    def __init__(self, server):
        self.server = server.rstrip("/")
        self.email = f"e2e-{uuid.uuid4().hex[:8]}@example.com"
        self.password = f"pw {uuid.uuid4()} ✓"
        self.iterations = 600_000
        master = hashlib.pbkdf2_hmac("sha256", self.password.encode(), self.email.encode(), self.iterations, 32)
        self.master_hash = b64e(hashlib.pbkdf2_hmac("sha256", master, self.password.encode(), 1, 32))
        self.user_key = os.urandom(64)
        self.org_keys = {}
        stretched = stretch(master)
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        pkcs8 = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        self.public_key = b64e(pub)
        token = http(
            "POST",
            f"{self.server}/identity/accounts/register/send-verification-email",
            {"email": self.email, "name": "e2e", "receiveMarketingEmails": False},
        )
        http(
            "POST",
            f"{self.server}/identity/accounts/register/finish",
            {
                "email": self.email,
                "emailVerificationToken": token.strip('"') if isinstance(token, str) else token,
                "masterPasswordHash": self.master_hash,
                "masterPasswordHint": None,
                "userSymmetricKey": encrypt(self.user_key, stretched),
                "userAsymmetricKeys": {"publicKey": b64e(pub), "encryptedPrivateKey": encrypt(pkcs8, self.user_key)},
                "kdf": 0,
                "kdfIterations": self.iterations,
            },
        )
        self._login()
        key = http("POST", f"{self.server}/api/accounts/api-key", {"masterPasswordHash": self.master_hash}, self._auth())
        self.client_secret = key.get("apiKey") or key.get("ApiKey")
        claims = json.loads(b64d(self.token.split(".")[1] + "=="))
        self.user_id = claims["sub"]
        self.client_id = f"user.{self.user_id}"

    def _login(self):
        res = http(
            "POST",
            f"{self.server}/identity/connect/token",
            {
                "grant_type": "password",
                "username": self.email,
                "password": self.master_hash,
                "scope": "api offline_access",
                "client_id": "web",
                "deviceType": "9",
                "deviceIdentifier": str(uuid.uuid4()),
                "deviceName": "e2e",
            },
            form=True,
        )
        self.token = res["access_token"]

    def _auth(self):
        # Vaultwarden hides SSH key items from clients older than 2024.12.
        return {"Authorization": f"Bearer {self.token}", "Bitwarden-Client-Version": "2025.1.0"}

    def sync(self):
        return http("GET", f"{self.server}/api/sync?excludeDomains=true", headers=self._auth())

    def folder_id(self, name):
        for f in self.sync()["folders"]:
            if decrypt(f["name"], self.user_key).decode() == name:
                return f["id"]
        return http("POST", f"{self.server}/api/folders", {"name": encrypt(name.encode(), self.user_key)}, self._auth())["id"]

    def _cipher(self, cipher_id):
        for x in self.sync()["ciphers"]:
            if x["id"] == cipher_id:
                return x
        raise KeyError(f"no cipher with id {cipher_id}")

    def _dec(self, c):
        base = self.org_keys[c["organizationId"]] if c.get("organizationId") else self.user_key
        key = decrypt(c["key"], base) if c.get("key") else base
        return lambda v: decrypt(v, key).decode() if v else None

    def _view(self, c):
        d = self._dec(c)
        fields = [(d(f["name"]), d(f["value"])) for f in (c.get("fields") or [])]
        login = c.get("login") or {}
        return {
            "id": c["id"],
            "name": d(c["name"]),
            "password": d(login.get("password")),
            "username": d(login.get("username")),
            "uris": [d(u["uri"]) for u in (login.get("uris") or [])],
            "notes": d(c.get("notes")),
            "fields": dict(fields),
            "field_list": fields,
            "history": [d(h["password"]) for h in (c.get("passwordHistory") or [])],
            "deleted": bool(c.get("deletedDate")),
            "folder": c.get("folderId"),
            "type": c["type"],
            "field_types": {d(f["name"]): f["type"] for f in (c.get("fields") or [])},
        }

    def items(self, folder):
        """Decrypted view of the live items in a folder: {name: {...}}."""
        fid = self.folder_id(folder)
        out = {}
        for c in self.sync()["ciphers"]:
            if c.get("folderId") != fid or c.get("deletedDate"):
                continue
            v = self._view(c)
            out[v["name"]] = v
        return out

    def item(self, cipher_id):
        """Decrypted view of one item, trashed or not."""
        return self._view(self._cipher(cipher_id))

    def fields(self, cipher_id):
        return self.item(cipher_id)["field_list"]

    def _enc_fields(self, c, fields):
        k = self.user_key if not c.get("key") else decrypt(c["key"], self.user_key)
        # Keep each field's original type (hidden stays hidden); new fields are text.
        d = self._dec(c)
        types = {d(f["name"]): f["type"] for f in (c.get("fields") or [])}
        return [{"type": types.get(n, 0), "name": encrypt(n.encode(), k), "value": encrypt(v.encode(), k)} for n, v in fields]

    def _put(self, cipher_id, change):
        c = self._cipher(cipher_id)
        body = {k: v for k, v in c.items() if k not in ("id", "revisionDate", "creationDate", "deletedDate", "object", "edit", "viewPassword", "permissions", "collectionIds", "attachments", "organizationUseTotp", "data")}
        change(c, body)
        body["lastKnownRevisionDate"] = c["revisionDate"]
        body["encryptedFor"] = self.user_id
        return http("PUT", f"{self.server}/api/ciphers/{cipher_id}", body, self._auth())

    def _new(self, folder, type_, name, notes, login, fields, extra=None, reprompt=0, history=None, item_key=None):
        k = item_key or self.user_key
        body = {
            "type": type_,
            "folderId": self.folder_id(folder) if folder else None,
            "organizationId": None,
            "name": encrypt(name.encode(), k),
            "notes": encrypt(notes.encode(), k) if notes else None,
            "favorite": False,
            "reprompt": reprompt,
            "fields": self._new_fields(fields, k),
            "passwordHistory": [
                {"password": encrypt(p.encode(), k), "lastUsedDate": d} for p, d in (history or [])
            ],
            "encryptedFor": self.user_id,
        }
        if item_key:
            body["key"] = encrypt(item_key, self.user_key)
        if type_ == 1:
            body["login"] = login
        elif type_ == 2:
            body["secureNote"] = {"type": 0}
        else:
            body.update(extra)
        return http("POST", f"{self.server}/api/ciphers", body, self._auth())

    def add_login(self, folder, name, password, fields=None, username=None, uri=None, notes=None, reprompt=0, history=None,
                  totp=None, uris=None, item_key=None):
        """Add a login; `folder` may be None for no folder. `uris` is [(uri, match type or None)]; `item_key` (64
        bytes) gives the item its own key."""
        k = item_key or self.user_key
        uris = [(uri, None)] if uri else uris
        login = {
            "username": encrypt(username.encode(), k) if username else None,
            "password": encrypt(password.encode(), k) if password is not None else None,
            "uris": [{"uri": encrypt(u.encode(), k), "match": m} for u, m in uris] if uris else None,
            "totp": encrypt(totp.encode(), k) if totp else None,
        }
        return self._new(folder, 1, name, notes, login, fields, reprompt=reprompt, history=history, item_key=item_key)

    @staticmethod
    def _new_fields(fields, k):
        """`fields` is {name: value} (text fields) or [(type, name, value, linked id or None)]."""
        if isinstance(fields, dict):
            fields = [(0, n, v, None) for n, v in fields.items()]
        return [{"type": t, "name": encrypt(n.encode(), k), "value": encrypt(v.encode(), k) if v is not None else None,
                 "linkedId": linked} for t, n, v, linked in (fields or [])]

    def trash(self, cipher_id):
        """Move an item to the trash (a soft delete)."""
        return http("PUT", f"{self.server}/api/ciphers/{cipher_id}/delete", None, self._auth())

    def add_typed(self, folder, type_, name, key, payload, notes=None, fields=None):
        """Add a card (3, key "card"), identity (4, "identity") or SSH key (5, "sshKey") with string `payload`."""
        enc = {n: encrypt(v.encode(), self.user_key) for n, v in payload.items()}
        return self._new(folder, type_, name, notes, None, fields, extra={key: enc})

    def ssh_public(self, cipher_id):
        """The public key of an SSH key item, decrypted from the vault."""
        c = self._cipher(cipher_id)
        return self._dec(c)(c["sshKey"]["publicKey"])

    def add_note(self, folder, name, notes, fields=None):
        return self._new(folder, 2, name, notes, None, fields)

    def set_fields(self, cipher_id, fields):
        def change(c, body):
            body["fields"] = self._enc_fields(c, fields)
        return self._put(cipher_id, change)

    def remove_field(self, cipher_id, name):
        return self.set_fields(cipher_id, [(n, v) for n, v in self.fields(cipher_id) if n != name])

    def set_password(self, cipher_id, password):
        def change(c, body):
            body["login"]["password"] = encrypt(password.encode(), self.user_key)
        return self._put(cipher_id, change)

    def clone(self, cipher_id):
        """Duplicate an item the way "Clone item" does: same content, new id."""
        c = self._cipher(cipher_id)
        body = {k: v for k, v in c.items() if k not in ("id", "revisionDate", "creationDate", "deletedDate", "object", "edit", "viewPassword", "permissions", "collectionIds", "attachments", "organizationUseTotp", "data", "passwordHistory")}
        body["encryptedFor"] = self.user_id
        return http("POST", f"{self.server}/api/ciphers", body, self._auth())["id"]

    def folder_named(self, name):
        """The id of the folder `name`, or None; unlike folder_id, it never makes one."""
        for f in self.sync()["folders"]:
            if decrypt(f["name"], self.user_key).decode() == name:
                return f["id"]
        return None

    def cipher(self, cipher_id):
        """One cipher as /sync sends it, encrypted."""
        return self._cipher(cipher_id)

    def create_org(self, name):
        """A new organization this account owns (with its default collection); returns its id."""
        org_key = os.urandom(64)
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        pkcs8 = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        org = http("POST", f"{self.server}/api/organizations", {
            "name": name,
            "billingEmail": self.email,
            "collectionName": encrypt(b"Default", org_key),
            "key": rsa_encrypt(self.public_key, org_key),
            "keys": {"publicKey": b64e(pub), "encryptedPrivateKey": encrypt(pkcs8, org_key)},
            "planType": 0,
        }, self._auth())
        self.org_keys[org["id"]] = org_key
        return org["id"]

    def add_collection(self, org_id, name):
        body = {"name": encrypt(name.encode(), self.org_keys[org_id]), "groups": [], "users": [], "externalId": None}
        return http("POST", f"{self.server}/api/organizations/{org_id}/collections", body, self._auth())["id"]

    def add_member(self, org_id, member, collections):
        """Invite `member` (an Account) as a plain user with `collections` [(id, read_only)], then confirm it with the
        organization key sealed to its public key. With mail off, Vaultwarden accepts an existing user's invite."""
        access = [{"id": c, "readOnly": ro, "hidePasswords": False, "manage": False} for c, ro in collections]
        http("POST", f"{self.server}/api/organizations/{org_id}/users/invite", {
            "emails": [member.email], "type": 2, "collections": access, "groups": [], "accessAll": False,
            "permissions": {},
        }, self._auth())
        users = http("GET", f"{self.server}/api/organizations/{org_id}/users", headers=self._auth())["data"]
        (m,) = [u for u in users if u["email"].lower() == member.email.lower()]
        key = rsa_encrypt(member.public_key, self.org_keys[org_id])
        http("POST", f"{self.server}/api/organizations/{org_id}/users/{m['id']}/confirm", {"key": key}, self._auth())
        member.org_keys[org_id] = self.org_keys[org_id]

    def add_org_login(self, org_id, collection_id, name, password, username=None):
        k = self.org_keys[org_id]
        cipher = {
            "type": 1,
            "folderId": None,
            "organizationId": org_id,
            "name": encrypt(name.encode(), k),
            "notes": None,
            "favorite": False,
            "reprompt": 0,
            "fields": [],
            "passwordHistory": [],
            "encryptedFor": self.user_id,
            "login": {
                "username": encrypt(username.encode(), k) if username else None,
                "password": encrypt(password.encode(), k),
                "uris": None,
                "totp": None,
            },
        }
        body = {"cipher": cipher, "collectionIds": [collection_id]}
        return http("POST", f"{self.server}/api/ciphers/create", body, self._auth())["id"]
