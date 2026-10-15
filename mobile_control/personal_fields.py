"""Personal fields: encrypted at rest, clear only to permitted roles.

Configured on Mobile Configuration -> Personal Fields (child table
`Mobile Personal Field`). Nothing here does anything until a row exists.

At rest
    A `before_save` hook (registered on `*`) replaces the value of each
    configured field with ``enc:v1:<Fernet token>`` using the site
    encryption key (`frappe.utils.password.encrypt`). A hidden companion
    field ``<fieldname>_hash`` holds a keyed HMAC-SHA256 of the normalised
    value so exact-match search still works (`find_by_personal_value`).
    The hook is idempotent: a value that already carries the prefix is
    kept (after checking it decrypts), and re-saving an unchanged clear
    value keeps the old token so Version history does not churn.

Over the API
    `mobile_sync.get_docs_with_children` (the SDK's pull endpoint) and the
    Desk form `onload` replace the token with the clear value for users
    whose roles match the row's `roles_allowed`; everyone else gets the
    field blank. Every response that carries clear values writes one
    Access Log entry (per request and doctype, never per row, never with
    values).

Write-only users
    A user who cannot see the clear value receives it blank. If they save
    the document with the field still blank, the stored value is kept, so
    they cannot wipe data they were never shown. They can still set a new
    value.

Only Small Text / Text / Long Text fields are accepted (see
`ALLOWED_FIELDTYPES`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import frappe
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from frappe import _
from frappe.core.doctype.access_log.access_log import make_access_log
from frappe.utils import cstr
from frappe.utils.password import encrypt
from frappe.utils.password import get_encryption_key

PREFIX = "enc:v1:"
HASH_SUFFIX = "_hash"

# TEXT columns only. A Fernet token is ~1.33x the plaintext plus ~100
# characters of overhead; with the prefix, a 32-byte value (an 11-letter
# name in Devanagari is already 33 bytes of UTF-8) no longer fits a Data
# field's varchar(140). Raising the column length instead would need an
# ALTER TABLE on live tables and would still trip Data option validation
# (Phone / Email) on the ciphertext. Data -> Small Text is an allowed
# Customize Form change.
ALLOWED_FIELDTYPES = ("Small Text", "Text", "Long Text")

# Optional site_config key for the hash salt. Defaults to the site
# encryption key. Changing it invalidates every stored hash.
SALT_CONF_KEY = "mobile_control_personal_field_salt"

_CACHE_KEY = "mobile_control:personal_fields"
_LOCAL_KEY = "mobile_control_personal_fields"
_CACHE_TTL = 6 * 60 * 60


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def get_personal_field_config() -> dict[str, dict[str, list[str]]]:
	"""``{doctype: {fieldname: [roles_allowed]}}``. Empty when unconfigured.

	Memoised per request and cached in Redis, because the save hook runs
	for every document on the site.
	"""
	local_value = getattr(frappe.local, _LOCAL_KEY, None)
	if local_value is not None:
		return local_value
	value = frappe.cache.get_value(_CACHE_KEY)
	if value is None:
		value = _load_config()
		# Expiry is a safety net (e.g. a restored backup); saving Mobile
		# Configuration clears the key straight away.
		frappe.cache.set_value(_CACHE_KEY, value, expires_in_sec=_CACHE_TTL)
	setattr(frappe.local, _LOCAL_KEY, value)
	return value


def clear_personal_field_cache() -> None:
	frappe.cache.delete_value(_CACHE_KEY)
	if hasattr(frappe.local, _LOCAL_KEY):
		delattr(frappe.local, _LOCAL_KEY)


def _load_config() -> dict[str, dict[str, list[str]]]:
	if not frappe.db.table_exists("Mobile Personal Field"):
		return {}
	rows = frappe.get_all(
		"Mobile Personal Field",
		filters={"parenttype": "Mobile Configuration", "parentfield": "personal_fields"},
		fields=["doctype_name", "fieldname", "roles_allowed"],
		order_by="idx asc",
	)
	config: dict[str, dict[str, list[str]]] = {}
	for row in rows:
		if not row.doctype_name or not row.fieldname:
			continue
		config.setdefault(row.doctype_name, {})[row.fieldname.strip()] = parse_roles(row.roles_allowed)
	return config


def parse_roles(raw: str | None) -> list[str]:
	"""One role per line; blank lines and surrounding spaces ignored."""
	return [line.strip() for line in cstr(raw).splitlines() if line.strip()]


def can_view_clear(roles_allowed: list[str], user: str | None = None) -> bool:
	"""Blank `roles_allowed` means anyone who can read the document."""
	if not roles_allowed:
		return True
	return bool(set(frappe.get_roles(user)) & set(roles_allowed))


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------


def is_encrypted(value: Any) -> bool:
	return isinstance(value, str) and value.startswith(PREFIX)


def encrypt_value(plain: str) -> str:
	return PREFIX + encrypt(plain)


def decrypt_value(value: str) -> str:
	"""Raises `InvalidToken` when the token was not made with this site's key."""
	token = value[len(PREFIX) :]
	return Fernet(get_encryption_key().encode()).decrypt(token.encode()).decode()


def _try_decrypt(value: str) -> str | None:
	try:
		return decrypt_value(value)
	except (InvalidToken, ValueError):
		return None


def normalise(value: str) -> str:
	"""Whitespace collapsed, case folded. Nothing else (phone formats differ by app)."""
	return " ".join(cstr(value).split()).casefold()


def hash_value(value: str) -> str:
	salt = frappe.conf.get(SALT_CONF_KEY) or get_encryption_key()
	key = hashlib.sha256(b"mobile_control.personal_field.v1:" + cstr(salt).encode()).digest()
	return hmac.new(key, normalise(value).encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# doc_events
# ---------------------------------------------------------------------------


def encrypt_personal_fields(doc, method: str | None = None) -> None:
	"""`before_save` / `before_submit` / `before_update_after_submit` on `*`."""
	fields = get_personal_field_config().get(doc.doctype)
	if not fields:
		return

	before = doc.get_doc_before_save() if not doc.is_new() else None
	for fieldname, roles in fields.items():
		_encrypt_field(doc, before, fieldname, roles)


def _encrypt_field(doc, before, fieldname: str, roles: list[str]) -> None:
	value = doc.get(fieldname)
	old = before.get(fieldname) if before else None
	hash_field = fieldname + HASH_SUFFIX
	has_hash = bool(doc.meta.get_field(hash_field))

	if value in (None, ""):
		if is_encrypted(old) and not can_view_clear(roles):
			# Shown blank, saved blank: keep what is stored.
			doc.set(fieldname, old)
			return
		if has_hash:
			doc.set(hash_field, None)
		return

	value = cstr(value)
	if is_encrypted(value):
		if value == old and (not has_hash or doc.get(hash_field)):
			return
		plain = _try_decrypt(value)
		if plain is None:
			frappe.throw(
				_("{0} holds an encrypted value this site cannot read.").format(
					_(doc.meta.get_label(fieldname))
				),
				frappe.ValidationError,
			)
	else:
		plain = value
		if is_encrypted(old) and _try_decrypt(old) == plain:
			doc.set(fieldname, old)
		else:
			doc.set(fieldname, encrypt_value(plain))

	if has_hash:
		doc.set(hash_field, hash_value(plain))


def reveal_on_form_load(doc, method: str | None = None) -> None:
	"""Desk form `onload`: clear values for permitted users, blank for others."""
	if not get_personal_field_config().get(doc.doctype):
		return
	row = {fieldname: doc.get(fieldname) for fieldname in get_personal_field_config()[doc.doctype]}
	for key in list(row):
		row[key + HASH_SUFFIX] = doc.get(key + HASH_SUFFIX)
	reveal_rows(doc.doctype, [row], method="frappe.desk.form.load.getdoc", document=doc.name)
	for key, value in row.items():
		if doc.meta.get_field(key):
			doc.set(key, value)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def reveal_rows(
	doctype: str,
	rows: list[dict[str, Any]],
	method: str,
	document: str | None = None,
) -> None:
	"""Replace tokens in `rows` (in place) with clear values or blanks.

	Callers must already have checked read permission on every row.
	Writes one Access Log entry when any clear value is returned.
	"""
	fields = get_personal_field_config().get(doctype)
	if not fields or not rows:
		return

	revealed: list[str] = []
	for fieldname, roles in fields.items():
		allowed = can_view_clear(roles)
		hash_field = fieldname + HASH_SUFFIX
		returned = False
		for row in rows:
			if hash_field in row:
				# Keyed hashes are for server-side search only.
				row[hash_field] = None
			value = row.get(fieldname)
			if not allowed:
				if fieldname in row:
					row[fieldname] = None
				continue
			if is_encrypted(value):
				value = _try_decrypt(value)
				row[fieldname] = value
			if value not in (None, ""):
				returned = True
		if returned:
			revealed.append(fieldname)

	if revealed:
		make_access_log(
			doctype=doctype,
			document=document,
			method=method,
			filters=json.dumps({"fields": revealed, "documents": len(rows)}),
		)


@frappe.whitelist(methods=["GET", "POST"])
def find_by_personal_value(doctype: str, fieldname: str, value: str) -> list[str]:
	"""Names of `doctype` documents whose personal field equals `value`.

	Exact match after `normalise`. Needs read permission on the doctype and
	one of the field's `roles_allowed`; results honour the usual list
	permissions (user permissions, `if_owner`, ...).
	"""
	roles = (get_personal_field_config().get(doctype) or {}).get(fieldname)
	if roles is None:
		frappe.throw(
			_("{0} is not a personal field of {1}").format(fieldname, doctype), frappe.ValidationError
		)
	if not frappe.has_permission(doctype, "read") or not can_view_clear(roles):
		raise frappe.PermissionError(_("Not permitted to search {0} by {1}").format(doctype, fieldname))
	if not cstr(value).strip():
		return []
	return frappe.get_list(
		doctype,
		filters={fieldname + HASH_SUFFIX: hash_value(value)},
		pluck="name",
		limit_page_length=100,
	)


# ---------------------------------------------------------------------------
# Setup (called from Mobile Configuration)
# ---------------------------------------------------------------------------


def validate_rows(rows, configured_doctypes: set[str]) -> None:
	seen: set[tuple[str, str]] = set()
	for row in rows:
		doctype, fieldname = row.doctype_name, cstr(row.fieldname).strip()
		label = _("Personal Fields row {0}").format(row.idx)
		if (doctype, fieldname) in seen:
			frappe.throw(_("{0}: {1}.{2} is listed twice").format(label, doctype, fieldname))
		seen.add((doctype, fieldname))

		if doctype not in configured_doctypes:
			frappe.throw(_("{0}: {1} must also be listed under Forms Configuration").format(label, doctype))
		meta = frappe.get_meta(doctype)
		if meta.istable or meta.issingle:
			frappe.throw(
				_("{0}: {1} must be a regular (not child, not single) DocType").format(label, doctype)
			)
		df = meta.get_field(fieldname)
		if not df:
			frappe.throw(_("{0}: {1} has no field {2}").format(label, doctype, fieldname))
		if df.fieldtype not in ALLOWED_FIELDTYPES:
			frappe.throw(
				_(
					"{0}: {1}.{2} is {3}. Personal fields must be Small Text, Text or Long Text, because "
					"encrypted values are longer than a Data field holds. Change the field type with "
					"Customize Form first."
				).format(label, doctype, fieldname, df.fieldtype)
			)
		hash_df = meta.get_field(fieldname + HASH_SUFFIX)
		if hash_df and hash_df.fieldtype != "Data":
			frappe.throw(
				_("{0}: {1} already has a field {2} that is not a hash field").format(
					label, doctype, fieldname + HASH_SUFFIX
				)
			)
		for role in parse_roles(row.roles_allowed):
			if not frappe.db.exists("Role", role):
				frappe.throw(_("{0}: role {1} does not exist").format(label, role))
		row.fieldname = fieldname


def ensure_hash_field(doctype: str, fieldname: str) -> bool:
	"""Adds the hidden ``<fieldname>_hash`` Custom Field. Returns True if added."""
	hash_field = fieldname + HASH_SUFFIX
	meta = frappe.get_meta(doctype)
	if meta.has_field(hash_field):
		return False
	label = meta.get_label(fieldname) or fieldname
	frappe.get_doc(
		{
			"doctype": "Custom Field",
			"dt": doctype,
			"fieldname": hash_field,
			"label": f"{label} Hash",
			"fieldtype": "Data",
			"insert_after": fieldname,
			"hidden": 1,
			"read_only": 1,
			"no_copy": 1,
			"print_hide": 1,
			"report_hide": 1,
			"search_index": 1,
		}
	).insert(ignore_permissions=True)
	frappe.clear_cache(doctype=doctype)
	return True


def encrypt_existing_values(doctype: str, fieldname: str) -> int:
	"""Encrypts values saved before the field was configured. Returns rows changed.

	Writes with `update_modified=False`: the data does not change, only how
	it is stored, so devices need not re-pull.
	"""
	hash_field = fieldname + HASH_SUFFIX
	has_hash = frappe.get_meta(doctype).has_field(hash_field)
	names = frappe.get_all(
		doctype,
		filters=[[fieldname, "is", "set"], [fieldname, "not like", PREFIX + "%"]],
		pluck="name",
	)
	for name in names:
		plain = frappe.db.get_value(doctype, name, fieldname)
		if not plain or is_encrypted(plain):
			continue
		values = {fieldname: encrypt_value(plain)}
		if has_hash:
			values[hash_field] = hash_value(plain)
		frappe.db.set_value(doctype, name, values, update_modified=False)
	return len(names)
