# Security architecture

The local boundary is the client-approved Intel TDX guest, measured launcher and digest-pinned Compose release. The proxy generates ephemeral keys and collects fresh hardware evidence directly through Linux TSM. Clients verify the hardware and release evidence and authenticate the Oak handshake before sending plaintext into the guest.

[The GCP TDX contract](GCP_TDX.md) specifies exact measurements, evidence fields and runtime permissions. There is no local KMS or evidence worker. Application dispatch stays inside the encrypted Oak channel; remote Phala inference retains independent attestation verification and an attested TLS key pin. Optional document services share the measured guest through Unix sockets.

No claim of an approved OS, successful hardware verification, reproducible guest image or live GCP deployment follows merely from building this container. Those claims require the approved measured guest and independent client verification described in the contract.
