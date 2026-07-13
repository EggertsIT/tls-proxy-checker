"""Built-in TLS inspection compatibility profiles."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class InspectionProfile:
    """A documented proxy-to-server TLS capability set."""

    id: str
    name: str
    provider: str
    source_url: str
    reviewed_at: str
    tls_versions: tuple[str, ...]
    tls13_pfs: frozenset[str]
    ecdhe_pfs: frozenset[str]
    dhe_pfs: frozenset[str]
    rsa_no_pfs: frozenset[str]
    ecdsa_server_side_only: frozenset[str]

    @property
    def supported_ciphers(self) -> frozenset[str]:
        return self.tls13_pfs | self.ecdhe_pfs | self.dhe_pfs | self.rsa_no_pfs

    def cipher_status(self, cipher_name: str) -> str:
        if cipher_name in self.ecdsa_server_side_only:
            return "ecdsa_server_only"
        if cipher_name in self.rsa_no_pfs:
            return "no_pfs"
        if cipher_name in self.supported_ciphers:
            return "supported_pfs"
        return "not_supported"

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider,
            "source_url": self.source_url,
            "reviewed_at": self.reviewed_at,
            "tls_versions": list(self.tls_versions),
            "candidate_cipher_count": len(self.supported_ciphers),
        }


ZSCALER_ZIA_PROFILE = InspectionProfile(
    id="zscaler-zia",
    name="Zscaler ZIA documented TLS inspection profile",
    provider="Zscaler, Inc.",
    source_url=(
        "https://help.zscaler.com/zia/"
        "supported-cipher-suites-ssltls-inspection"
    ),
    reviewed_at="2026-07-13",
    tls_versions=("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"),
    tls13_pfs=frozenset(
        {
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
        }
    ),
    ecdhe_pfs=frozenset(
        {
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES256-SHA",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-SHA384",
            "ECDHE-ECDSA-AES128-SHA256",
            "ECDHE-ECDSA-AES256-SHA",
            "ECDHE-ECDSA-AES128-SHA",
        }
    ),
    dhe_pfs=frozenset(
        {
            "DHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-SHA256",
            "DHE-RSA-AES128-SHA256",
            "DHE-RSA-AES256-SHA",
            "DHE-RSA-AES128-SHA",
        }
    ),
    rsa_no_pfs=frozenset(
        {
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
            "AES256-SHA",
            "AES128-SHA",
        }
    ),
    ecdsa_server_side_only=frozenset(
        {
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-SHA384",
            "ECDHE-ECDSA-AES128-SHA256",
            "ECDHE-ECDSA-AES256-SHA",
            "ECDHE-ECDSA-AES128-SHA",
        }
    ),
)

INSPECTION_PROFILES = {ZSCALER_ZIA_PROFILE.id: ZSCALER_ZIA_PROFILE}
DEFAULT_PROFILE_ID = ZSCALER_ZIA_PROFILE.id


def get_inspection_profile(profile_id: str) -> InspectionProfile:
    """Return a configured profile by its stable identifier."""
    try:
        return INSPECTION_PROFILES[profile_id]
    except KeyError as error:
        raise ValueError(f"unknown inspection profile: {profile_id}") from error
