from __future__ import annotations

from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase
from mobile_control import personal_fields as pf
from mobile_control.api.bulk_fetch import get_docs_with_children
from mobile_control.api.helpers.mobile_config import get_mobile_configuration_payload

DOCTYPE = "MC Personal Field Test"
VIEWER_ROLE = "MC Personal Viewer"
VIEWER = "mc-pf-viewer@example.com"
OTHER = "mc-pf-other@example.com"
# Fictional.
NAME = "Asha Devi"


def _ensure_doctype() -> None:
	if frappe.db.exists("DocType", DOCTYPE):
		return
	frappe.get_doc(
		{
			"doctype": "DocType",
			"name": DOCTYPE,
			"module": "Mobile Control",
			"custom": 1,
			"autoname": "hash",
			"fields": [
				{"fieldname": "full_name", "fieldtype": "Small Text", "label": "Full Name"},
				{"fieldname": "village", "fieldtype": "Data", "label": "Village"},
			],
			"permissions": [
				{"role": "System Manager", "read": 1, "write": 1, "create": 1, "delete": 1},
				{"role": "Mobile User", "read": 1, "write": 1, "create": 1},
			],
		}
	).insert(ignore_permissions=True)


def _ensure_user(email: str, roles: list[str]) -> None:
	if frappe.db.exists("User", email):
		return
	frappe.get_doc(
		{
			"doctype": "User",
			"email": email,
			"first_name": email.split("@")[0],
			"send_welcome_email": 0,
			"roles": [{"role": r} for r in roles],
		}
	).insert(ignore_permissions=True)


def _configure(rows: list[dict]) -> None:
	config = frappe.get_single("Mobile Configuration")
	config.set("table_lwis", [{"mobile_workspace_item": DOCTYPE}])
	config.set("personal_fields", rows)
	config.save(ignore_permissions=True)


class TestPersonalFields(IntegrationTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		_ensure_doctype()
		if not frappe.db.exists("Role", VIEWER_ROLE):
			frappe.get_doc({"doctype": "Role", "role_name": VIEWER_ROLE}).insert(ignore_permissions=True)
		_ensure_user(VIEWER, ["Mobile User", VIEWER_ROLE])
		_ensure_user(OTHER, ["Mobile User"])
		_configure([{"doctype_name": DOCTYPE, "fieldname": "full_name", "roles_allowed": VIEWER_ROLE}])

	def tearDown(self):
		frappe.set_user("Administrator")
		super().tearDown()

	def _new(self, full_name: str = NAME):
		return frappe.get_doc({"doctype": DOCTYPE, "full_name": full_name, "village": "Rampur"}).insert(
			ignore_permissions=True
		)

	def _stored(self, name: str) -> str:
		return frappe.db.get_value(DOCTYPE, name, "full_name")

	# --- at rest -----------------------------------------------------------

	def test_value_is_encrypted_on_insert(self):
		doc = self._new()
		stored = self._stored(doc.name)
		self.assertTrue(stored.startswith(pf.PREFIX))
		self.assertNotIn(NAME, stored)
		self.assertEqual(pf.decrypt_value(stored), NAME)
		# Other fields are untouched.
		self.assertEqual(frappe.db.get_value(DOCTYPE, doc.name, "village"), "Rampur")

	def test_hash_field_is_added_and_filled(self):
		self.assertTrue(frappe.get_meta(DOCTYPE).has_field("full_name_hash"))
		doc = self._new()
		self.assertEqual(frappe.db.get_value(DOCTYPE, doc.name, "full_name_hash"), pf.hash_value(NAME))
		self.assertEqual(pf.hash_value("  asha   DEVI "), pf.hash_value(NAME))
		self.assertNotEqual(pf.hash_value("Asha Devii"), pf.hash_value(NAME))

	def test_save_is_idempotent(self):
		doc = self._new()
		first = self._stored(doc.name)

		doc.reload()
		doc.village = "Sitapur"
		doc.save(ignore_permissions=True)
		self.assertEqual(self._stored(doc.name), first, "an encrypted value is not encrypted again")

		doc.reload()
		doc.full_name = NAME
		doc.save(ignore_permissions=True)
		self.assertEqual(self._stored(doc.name), first, "an unchanged clear value keeps its token")

		doc.reload()
		doc.full_name = "Meena Kumari"
		doc.save(ignore_permissions=True)
		self.assertEqual(pf.decrypt_value(self._stored(doc.name)), "Meena Kumari")

	def test_foreign_token_is_rejected(self):
		doc = self._new()
		doc.reload()
		doc.full_name = pf.PREFIX + "not-a-token"
		with self.assertRaises(frappe.ValidationError):
			doc.save(ignore_permissions=True)

	def test_backfill_encrypts_older_plain_values(self):
		doc = self._new()
		frappe.db.set_value(DOCTYPE, doc.name, "full_name", NAME, update_modified=False)
		pf.encrypt_existing_values(DOCTYPE, "full_name")
		self.assertEqual(pf.decrypt_value(self._stored(doc.name)), NAME)

	# --- over the API ------------------------------------------------------

	def test_permitted_user_pulls_clear_value_and_access_is_logged(self):
		doc = self._new()
		frappe.set_user(VIEWER)
		with patch("mobile_control.personal_fields.make_access_log") as log:
			rows = get_docs_with_children(DOCTYPE, [doc.name])
		self.assertEqual(rows[0]["full_name"], NAME)
		self.assertIsNone(rows[0]["full_name_hash"])
		log.assert_called_once()
		kwargs = log.call_args.kwargs
		self.assertEqual(kwargs["doctype"], DOCTYPE)
		self.assertNotIn(NAME, str(kwargs), "values are never logged")

	def test_other_user_pulls_blank_and_nothing_is_logged(self):
		doc = self._new()
		frappe.set_user(OTHER)
		with patch("mobile_control.personal_fields.make_access_log") as log:
			rows = get_docs_with_children(DOCTYPE, [doc.name])
		self.assertIsNone(rows[0]["full_name"])
		self.assertEqual(rows[0]["village"], "Rampur")
		log.assert_not_called()

	def test_user_without_access_cannot_clear_the_value(self):
		doc = self._new()
		first = self._stored(doc.name)
		frappe.set_user(OTHER)
		doc = frappe.get_doc(DOCTYPE, doc.name)
		doc.full_name = None
		doc.save()
		frappe.set_user("Administrator")
		self.assertEqual(self._stored(doc.name), first)

	def test_find_by_personal_value(self):
		doc = self._new()
		frappe.set_user(VIEWER)
		self.assertIn(doc.name, pf.find_by_personal_value(DOCTYPE, "full_name", " asha devi"))
		frappe.set_user(OTHER)
		with self.assertRaises(frappe.PermissionError):
			pf.find_by_personal_value(DOCTYPE, "full_name", NAME)
		with self.assertRaises(frappe.ValidationError):
			pf.find_by_personal_value(DOCTYPE, "village", "Rampur")

	def test_configuration_exposes_personal_fields(self):
		items = get_mobile_configuration_payload()["configuration"]
		item = next(i for i in items if i["mobile_workspace_item"] == DOCTYPE)
		self.assertEqual(item["personal_fields"], ["full_name"])

	# --- configuration -----------------------------------------------------

	def test_data_field_is_rejected(self):
		with self.assertRaises(frappe.ValidationError):
			_configure([{"doctype_name": DOCTYPE, "fieldname": "village"}])

	def test_unknown_field_is_rejected(self):
		with self.assertRaises(frappe.ValidationError):
			_configure([{"doctype_name": DOCTYPE, "fieldname": "no_such_field"}])

	def test_doctype_must_be_a_mobile_form(self):
		config = frappe.get_single("Mobile Configuration")
		config.set("table_lwis", [])
		config.set("personal_fields", [{"doctype_name": DOCTYPE, "fieldname": "full_name"}])
		with self.assertRaises(frappe.ValidationError):
			config.save(ignore_permissions=True)
