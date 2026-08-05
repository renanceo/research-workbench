from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from enum import Enum


class ResourceNotFound(LookupError):
    """Deliberately identical for missing and unauthorized resources."""


class InvalidCapability(PermissionError):
    pass


class ResourceType(str, Enum):
    DOCUMENT = "document"
    DIAGNOSTIC = "diagnostic"
    REPORT = "report"
    PARSER_OUTPUT = "parser_output"
    RETRIEVAL_NAMESPACE = "retrieval_namespace"
    HUMAN_REVIEW = "human_review"
    EXPORT = "export"


@dataclass(frozen=True)
class Resource:
    resource_id: str
    resource_type: ResourceType
    owner_account_id: str
    parent_id: str | None = None


@dataclass(frozen=True)
class ReviewerGrant:
    reviewer_id: str
    account_id: str
    resource_id: str
    actions: frozenset[str]


class NamespaceStore:
    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < 32:
            raise ValueError("signing_key must contain at least 32 bytes")
        self._signing_key = signing_key
        self._resources: dict[str, Resource] = {}
        self._consumed_capabilities: set[str] = set()

    def create(
        self,
        account_id: str,
        resource_type: ResourceType,
        parent_id: str | None = None,
    ) -> Resource:
        if parent_id is not None:
            self.get(account_id, parent_id)
        prefix = resource_type.value[:4]
        resource = Resource(
            resource_id=f"{prefix}_{secrets.token_urlsafe(18)}",
            resource_type=resource_type,
            owner_account_id=account_id,
            parent_id=parent_id,
        )
        self._resources[resource.resource_id] = resource
        return resource

    def get(self, account_id: str, resource_id: str) -> Resource:
        resource = self._resources.get(resource_id)
        if resource is None or not hmac.compare_digest(resource.owner_account_id, account_id):
            raise ResourceNotFound("resource not found")
        return resource

    def delete(self, account_id: str, resource_id: str) -> None:
        self.get(account_id, resource_id)
        del self._resources[resource_id]

    def bind_diagnostic(self, account_id: str, diagnostic_id: str, document_id: str) -> None:
        diagnostic = self.get(account_id, diagnostic_id)
        document = self.get(account_id, document_id)
        if diagnostic.resource_type != ResourceType.DIAGNOSTIC:
            raise ResourceNotFound("resource not found")
        if document.resource_type != ResourceType.DOCUMENT:
            raise ResourceNotFound("resource not found")

    def retrieval_cache_key(self, account_id: str, source_hash: str) -> str:
        material = f"retrieval\0{account_id}\0{source_hash}".encode()
        return hmac.new(self._signing_key, material, hashlib.sha256).hexdigest()

    def issue_download_capability(
        self,
        account_id: str,
        resource_id: str,
        expires_at: int,
    ) -> str:
        self.get(account_id, resource_id)
        nonce = secrets.token_urlsafe(12)
        body = f"{resource_id}.{expires_at}.{nonce}"
        signature = hmac.new(
            self._signing_key,
            f"{account_id}.{body}".encode(),
            hashlib.sha256,
        ).digest()
        encoded = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        return f"{body}.{encoded}"

    def consume_download_capability(
        self,
        account_id: str,
        capability: str,
        now: int | None = None,
    ) -> Resource:
        try:
            resource_id, expires_text, nonce, supplied = capability.split(".", 3)
            expires_at = int(expires_text)
        except (ValueError, TypeError):
            raise InvalidCapability("invalid or expired capability") from None
        body = f"{resource_id}.{expires_at}.{nonce}"
        expected = base64.urlsafe_b64encode(
            hmac.new(
                self._signing_key,
                f"{account_id}.{body}".encode(),
                hashlib.sha256,
            ).digest()
        ).decode().rstrip("=")
        current_time = int(time.time()) if now is None else now
        capability_hash = hashlib.sha256(capability.encode()).hexdigest()
        if (
            not hmac.compare_digest(expected, supplied)
            or current_time >= expires_at
            or capability_hash in self._consumed_capabilities
        ):
            raise InvalidCapability("invalid or expired capability")
        resource = self.get(account_id, resource_id)
        self._consumed_capabilities.add(capability_hash)
        return resource

    def review_get(self, grant: ReviewerGrant, resource_id: str, action: str) -> Resource:
        if resource_id != grant.resource_id or action not in grant.actions:
            raise ResourceNotFound("resource not found")
        return self.get(grant.account_id, resource_id)

