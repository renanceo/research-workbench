from __future__ import annotations

import unittest

from gate0.namespace import (
    InvalidCapability,
    NamespaceStore,
    ResourceNotFound,
    ResourceType,
    ReviewerGrant,
)


class NamespaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = NamespaceStore(b"gate0-test-signing-key-32-bytes-minimum")
        self.account_a = "acct_A"
        self.account_b = "acct_B"

    def test_every_resource_type_denies_cross_account_read_and_delete(self) -> None:
        for resource_type in ResourceType:
            with self.subTest(resource_type=resource_type):
                resource = self.store.create(self.account_a, resource_type)
                with self.assertRaisesRegex(ResourceNotFound, "^resource not found$"):
                    self.store.get(self.account_b, resource.resource_id)
                with self.assertRaisesRegex(ResourceNotFound, "^resource not found$"):
                    self.store.delete(self.account_b, resource.resource_id)
                self.assertEqual(resource, self.store.get(self.account_a, resource.resource_id))

    def test_missing_and_unauthorized_are_indistinguishable(self) -> None:
        document = self.store.create(self.account_a, ResourceType.DOCUMENT)
        errors = []
        for resource_id in (document.resource_id, "doc_nonexistent_opaque_id"):
            try:
                self.store.get(self.account_b, resource_id)
            except ResourceNotFound as exc:
                errors.append((type(exc), str(exc)))
        self.assertEqual(errors[0], errors[1])

    def test_task_cannot_bind_document_owned_by_another_account(self) -> None:
        diagnostic = self.store.create(self.account_a, ResourceType.DIAGNOSTIC)
        foreign_document = self.store.create(self.account_b, ResourceType.DOCUMENT)
        with self.assertRaises(ResourceNotFound):
            self.store.bind_diagnostic(self.account_a, diagnostic.resource_id, foreign_document.resource_id)

    def test_parent_resource_cannot_cross_account(self) -> None:
        foreign_document = self.store.create(self.account_b, ResourceType.DOCUMENT)
        with self.assertRaises(ResourceNotFound):
            self.store.create(self.account_a, ResourceType.PARSER_OUTPUT, foreign_document.resource_id)

    def test_retrieval_cache_is_account_namespaced(self) -> None:
        source_hash = "a" * 64
        self.assertNotEqual(
            self.store.retrieval_cache_key(self.account_a, source_hash),
            self.store.retrieval_cache_key(self.account_b, source_hash),
        )

    def test_resource_ids_are_opaque_and_nonsequential(self) -> None:
        first = self.store.create(self.account_a, ResourceType.DOCUMENT).resource_id
        second = self.store.create(self.account_a, ResourceType.DOCUMENT).resource_id
        self.assertNotEqual(first, second)
        self.assertGreaterEqual(len(first), 28)
        self.assertFalse(first.removeprefix("docu_").isdigit())

    def test_download_capability_is_account_bound_expiring_and_single_use(self) -> None:
        report = self.store.create(self.account_a, ResourceType.REPORT)
        capability = self.store.issue_download_capability(self.account_a, report.resource_id, 200)
        with self.assertRaises(InvalidCapability):
            self.store.consume_download_capability(self.account_b, capability, now=100)
        self.assertEqual(
            report,
            self.store.consume_download_capability(self.account_a, capability, now=100),
        )
        with self.assertRaises(InvalidCapability):
            self.store.consume_download_capability(self.account_a, capability, now=101)

        expired = self.store.issue_download_capability(self.account_a, report.resource_id, 200)
        with self.assertRaises(InvalidCapability):
            self.store.consume_download_capability(self.account_a, expired, now=200)

    def test_human_reviewer_grant_is_resource_and_action_scoped(self) -> None:
        report = self.store.create(self.account_a, ResourceType.REPORT)
        other = self.store.create(self.account_a, ResourceType.REPORT)
        grant = ReviewerGrant("reviewer_1", self.account_a, report.resource_id, frozenset({"read"}))
        self.assertEqual(report, self.store.review_get(grant, report.resource_id, "read"))
        with self.assertRaises(ResourceNotFound):
            self.store.review_get(grant, other.resource_id, "read")
        with self.assertRaises(ResourceNotFound):
            self.store.review_get(grant, report.resource_id, "delete")


if __name__ == "__main__":
    unittest.main()
