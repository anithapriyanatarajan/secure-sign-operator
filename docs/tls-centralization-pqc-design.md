# Centralized TLS Security Profile & PQC Readiness — Design & Impact Analysis

## 0. Plain-language summary (start here)

**What is this change for?**

Today, every service we ship (Fulcio, Rekor, Trillian, CTlog, the database, Redis, …) decides on its own *how* to encrypt its network traffic — which TLS version and which ciphers to use. Mostly they just take whatever the underlying library defaults to. Nobody is checking that these match the customer's security policy.

OpenShift 4.22 says: **stop deciding this per-service.** The cluster admin sets the TLS policy in **one place** (the cluster's "TLS security profile"), and **every** service must read that one setting and obey it. This makes the whole platform consistent and, importantly, **ready for post-quantum cryptography** — the newer, quantum-resistant encryption only works on TLS 1.3, so once everything obeys the central policy, a customer can turn on stronger crypto everywhere by changing a single knob.

In short: **move TLS settings from "hardcoded in each service" to "read from the cluster's central policy."**

**What should the changes be? (in plain terms)**

1. **Read the cluster's TLS policy.** Add code to the operator that looks up the central setting (TLS version + cipher list) and turns it into a simple, reusable answer the rest of the operator can use.
2. **Add an on/off enforcement switch.** Honor the cluster's `legacy` vs `strict` mode. In `strict` mode, if we can't comply, we **stop and report an error** instead of quietly using insecure defaults.
3. **Push that policy into each service we *can* configure:**
   - **Redis** and the **managed database** — easy: just add the version/cipher settings to their config files.
   - The operator's own process — set its TLS version explicitly.
4. **Handle the services we *can't* fully configure** (Trillian, CTlog, Fulcio, Rekor — they're prebuilt upstream images that don't expose these knobs). Two options:
   - **(A)** add the missing knobs upstream (correct, but slow and across many repos), or
   - **(B)** put a small proxy in front of each that does the TLS for them (faster, ships in our repo).
   The doc recommends **(B) now, (A) later**.
5. **The internet-facing services** (Fulcio/Rekor/TSA/TUF web endpoints) already get their TLS from the OpenShift router, so for those we mostly just **verify** they're compliant — little or no code.
6. **Prove it.** Add tests that actually inspect the encryption on the wire and confirm each service only accepts what the policy allows — including custom policies.
7. **Document it** so customers know the three settings they can adjust and the one Go limitation (see appendix).

**The one big decision to make first:** option **(A) vs (B)** above — it changes how much work the rest is. Everything else can start in parallel.

**What is explicitly *not* part of this:** the signing keys/certificates themselves (that's a separate identity concern), node-level (Kubelet) settings, and customer-owned external databases.

---

## 1. Executive summary

OpenShift 4.22 mandates that **all layered products stop hard-coding TLS handshake parameters** (protocol version, cipher suites, curves/groups) and instead **inherit them from the cluster's central `tlsSecurityProfile`**, exposed through at most three customer-adjustable "knobs":

1. **API Server** `tlsSecurityProfile` — authoritative default for in-cluster services.
2. **Ingress Controller** `tlsSecurityProfile` — for endpoints serving ingress/edge traffic.
3. **Kubelet** `tlsSecurityProfile` — for node agents (**N/A for Sigstore**, see §4).

The goal is **PQC-readiness in a single pass**: a customer who selects (or customizes) a profile gets the whole platform — including Trusted Artifact Signer — aligned, with PQC-resilient hybrid key exchange available once the profile permits **TLS 1.3+**.

**The hard truth for Sigstore:** this operator mostly deploys **upstream pre-built images** (Fulcio, Rekor, TSA, Trillian, CTFE) and only injects flags / config files / env. The OpenShift `tlsSecurityProfile` model assumes a **library-go Go server** that exposes `MinTLSVersion` + `CipherSuites`. **Most Sigstore operands do not expose those knobs today.** Therefore this epic is **not** a single operator change — it is a coordinated **upstream + downstream** effort, and its central architectural decision is **native flags vs. TLS-terminating sidecar** (§7).

---

## 2. Two distinct layers — do not conflate them

The word "TLS" hides two independent concerns. This epic is about **Layer 2 only**.

| | Layer 1 — **Provisioning** | Layer 2 — **Handshake policy** (THIS EPIC) |
| --- | --- | --- |
| Question | Is TLS on? Where does the **certificate** come from? | Given TLS is on, **which protocol version + ciphers + curves** are negotiated? |
| Sources | manual `CertRef`/`PrivateKeyRef`, OpenShift `service-ca`, or off | API-Server / Ingress `tlsSecurityProfile` |
| Code today | `TLS` struct in `api/v1alpha1/common.go`; five `tlsAction` handlers; `internal/utils/tls/{tls.go,ensure}` | **none — every operand uses Go/Redis/MySQL defaults** |
| Status | exists (and a separate enable/disable refactor was prototyped) | greenfield |

> A repo-wide search for `MinVersion`, `tls-ciphers`, `tls_version`, `ssl_cipher`, `tls-min`, etc. returns **zero matches**. Confirmed: **nothing in RHTAS currently constrains TLS version or cipher suites.** Everything inherits implementation defaults.

---

## 3. The OpenShift model we must adopt

### 3.1 `tlsSecurityProfile`
A cluster object (`APIServer`, `IngressController`, `KubeletConfig`) carries `spec.tlsSecurityProfile`, one of:

- **Old** — broad compatibility, TLS 1.0+.
- **Intermediate** — current default, TLS 1.2+.
- **Modern** — TLS 1.3 only.
- **Custom** — explicit `minTLSVersion` + `ciphers[]`; **customers frequently start from a preset and disable individual algorithms** their security team distrusts. We **must** honor Custom, not just the three presets.

`github.com/openshift/api/config/v1` (already vendored — see `cmd/main.go`) provides `TLSSecurityProfile`, the preset → `TLSProfileSpec` map (`configv1.TLSProfiles`), `MinTLSVersion`, and `Ciphers`. `library-go/pkg/crypto` provides helpers to convert these into Go `tls.Config` values and IANA names (not yet a dependency).

### 3.2 `TLSAdherence` toggle (legacy | strict)
Per the parent epic, a cluster-level `TLSAdherence` mode governs enforcement:

- **legacy** — best-effort; non-compliance tolerated (back-compat).
- **strict** — non-compliance is a **security bug**; verified via eBPF handshake snooping, Go crypto instrumentation, and continuous CI port scanning to catch "silent failures."

RHTAS must expose/propagate an equivalent adherence setting (operator flag/env vs. CRD field — see Decision **D5**) and, in strict mode, **fail closed** rather than fall back to defaults.

### 3.3 The "three knobs," mapped to RHTAS
| Knob | Applies to RHTAS? | Which components |
| --- | --- | --- |
| **API Server** profile | ✅ default/authoritative | all **internal** pod-to-pod services |
| **Ingress** profile | ✅ | **edge** endpoints (Fulcio/Rekor/TSA/TUF/CLI) — mostly already inherited via Route/Ingress |
| **Kubelet** profile | ❌ N/A | none — Sigstore ships **workloads, not node agents** |

---

## 4. PQC & Go TLS 1.3 nuances (so QE doesn't file false bugs)

- **PQC hybrid key exchange (`X25519MLKEM768`) exists only in TLS 1.3.** A profile must permit TLS 1.3 for PQC to engage. ⇒ effective floor is **1.3-capable**.
- **Go's TLS 1.3 cipher suites are NOT configurable.** `tls.Config.CipherSuites` only affects ≤1.2. For 1.3 you control **version + curve/group preference**, not ciphers. The epic's "silent failures caused by Go's restrictive TLS 1.3 implementation" refers to exactly this — a Custom profile that disables a 1.3 suite cannot be honored by a Go server, so the handshake may silently differ from the profile.
- **Hybrid KEM is default-on only in Go ≥ 1.24.** The **operand images must be built with Go ≥ 1.24** to get PQC groups. The operator itself is **Go 1.26** (`go.mod`) and is fine; the gap is in the **upstream image build toolchains**.
- **Kubelet knob is irrelevant** here; do not spend effort on it.

---

## 5. Architecture — where TLS actually terminates (the decisive split)

```
                         ┌────────────────────────── EDGE (Ingress/Route) ──────────────────────────┐
   external client  ───▶ │  OpenShift Router  ── honors IngressController.tlsSecurityProfile          │ ✅ mostly inherited
                         └───────────────────────────────────────────────────────────────────────────┘
                                         │ (edge-terminated HTTP)
                                         ▼
   ┌──────────────────────────────── INTERNAL (pod-to-pod gRPC/TCP) ─────────────────────────────────┐
   │  Fulcio ─▶ CTFE(CTlog)         Rekor ─▶ Trillian LogServer         Trillian ─▶ MySQL/MariaDB      │
   │  CTlog  ─▶ Trillian LogServer  Rekor ─▶ Redis (search index)       LogSigner ─▶ MySQL/MariaDB     │  ⚠️ terminated INSIDE the operand
   └──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

- **Edge endpoints** (Fulcio API, Rekor API, TSA, TUF, CLI download) are exposed via **OpenShift Route / k8s Ingress with edge termination** (note in `api/v1alpha1/common.go`; Ingress `Spec.TLS` set in `internal/utils/kubernetes/ingress.go`). The **router already honors the Ingress profile** ⇒ these are **compliant-by-construction → verification-only** (barring re-encrypt cases).
- **Internal gRPC/TCP** terminates TLS **inside the operand process**, where the router profile gives nothing. **This is where ~all real work concentrates.**

---

## 6. Component-by-component impact

Legend — **Native?** = can the workload express version/cipher/curve in its own config today.
**Strategy:** `Native` (operand flags/config) · `Sidecar` (TLS-terminating proxy) · `Verify` (edge-inherited) · `Customer` (BYO, out of our control).

### 6.1 Quick matrix

| Component | Upstream project | TLS surface | Native? | Edge/Internal | Likely strategy | Upstream change | Downstream change |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Redis** (Rekor search index) | redis / valkey | server (+optional mTLS) | ✅ `tls-protocols`,`tls-ciphers`,`tls-ciphersuites`,`tls-curves` | Internal | **Native** | none | inject directives |
| **Trillian DB** (managed) | MySQL/MariaDB | server | ✅ `tls_version`,`ssl_cipher`,`ssl_cipher_suites` | Internal | **Native (managed only)** | none | inject my.cnf |
| **Trillian DB** (external) | customer | server | n/a | Internal | **Customer** | none | document + validate |
| **Trillian LogServer** | google/trillian | gRPC server + DB client | ⚠️ no version/cipher flags | Internal | **Sidecar / Upstream** | add flags | wire flags or sidecar |
| **Trillian LogSigner** | google/trillian | gRPC server + DB client | ⚠️ | Internal | **Sidecar / Upstream** | add flags | wire flags or sidecar |
| **CTlog (CTFE)** | google/certificate-transparency-go | HTTPS server + Trillian client | ⚠️ only client CA flag today | Internal | **Sidecar / Upstream** | add flags | wire flags or sidecar |
| **Fulcio** | sigstore/fulcio | gRPC+HTTP gateway; CTFE client | ⚠️ config is OIDC, not handshake | Edge + Internal | **Verify (edge) / Sidecar (gRPC)** | add flags | sidecar for internal gRPC |
| **Rekor** | sigstore/rekor | HTTP/gRPC; Trillian+Redis clients | ⚠️ | Edge + Internal | **Verify (edge) / Sidecar (internal)** | add flags | sidecar/client config |
| **TSA** | sigstore/timestamp-authority | HTTP | ⚠️ | Edge | **Verify** | maybe | likely none |
| **TUF** | served as static files | HTTP file server | image-dependent | Edge | **Verify** | none | likely none |
| **CLI download** | console plugin | HTTPS | n/a | Edge | **Verify** | none | none |
| **Operator (manager)** | this repo | metrics/healthz; webhook (none) | ✅ Go 1.26 | Internal | **Native** | n/a | set MinVersion/curves from profile |

### 6.2 Deep dive per component

For each: **Role → TLS surfaces → current operator wiring → native capability → upstream task → downstream task → strategy.**

#### Redis (Rekor search index) — *fastest win, prove the pattern here*
- **Role:** secondary index store for Rekor.
- **Surfaces:** TLS server listener (and optional client auth).
- **Current wiring:** redis directives assembled in `internal/controller/rekor/actions/searchIndex/redis/actions/deployment.go` (`ensureTLS`): today only `tls-port`, `tls-cert-file`, `tls-key-file`, `tls-ca-cert-file`, `tls-auth-clients no`.
- **Native capability:** ✅ `tls-protocols "TLSv1.2 TLSv1.3"`, `tls-ciphers`, `tls-ciphersuites`, `tls-curves`.
- **Upstream task:** none (config-driven).
- **Downstream task:** append profile-derived directives in `ensureTLS`; map Custom ciphers → OpenSSL names.
- **Strategy:** **Native.** Also gates **BYO Redis** as customer-owned (§6.2 external DB analog).

#### Trillian database (MySQL / MariaDB)
- **Role:** Merkle-tree storage for Rekor & CTlog.
- **Surfaces:** DB server TLS; clients are LogServer/LogSigner.
- **Current wiring:** managed DB deployment; external DB path uses `trustedCA` (see `docs/external-database.md`).
- **Native capability:** ✅ (managed) `tls_version`, `ssl_cipher` (1.2), `ssl_cipher_suites`/`tls_ciphersuites` (1.3, engine-dependent).
- **Upstream task:** none.
- **Downstream task:** render my.cnf from profile **for the managed DB only**; **external DB = customer responsibility** — document + optionally validate.
- **Strategy:** **Native (managed) / Customer (external).**

#### Trillian LogServer & LogSigner
- **Role:** core Merkle log gRPC services.
- **Surfaces:** gRPC **server** (`--tls_cert_file`/`--tls_key_file`, set in `internal/controller/trillian/utils/server-deployment.go`; probes flipped to HTTPS); **DB client**.
- **Native capability:** ⚠️ upstream Trillian exposes **no** min-version/cipher/curve flags today.
- **Upstream task (U1):** add `--tls_min_version` / `--tls_cipher_suites` (+ groups) to `google/trillian` server bootstrap.
- **Downstream task:** if U1 lands, wire flags from profile; otherwise **front the gRPC listener with a TLS-terminating sidecar** the operator configures.
- **Strategy:** **Sidecar (4.22) → Native (when U1 ships).**

#### CTlog (CTFE — `certificate-transparency-go`)
- **Role:** CT log front-end for Fulcio certs.
- **Surfaces:** HTTPS server; **Trillian client** (`--trillian_tls_ca_cert_file`, set in `internal/controller/ctlog/actions/deployment.go`).
- **Native capability:** ⚠️ no handshake-policy flags for the server today.
- **Upstream task (U2):** add server min-version/cipher/curve flags to CTFE.
- **Downstream task:** wire flags, or sidecar; client side must dial **≥ TLS 1.3** when profile demands.
- **Strategy:** **Sidecar / Upstream.**

#### Fulcio
- **Role:** short-lived signing CA.
- **Surfaces:** **edge** HTTP/gRPC API (via Route) **and** internal **CTFE client**; internal gRPC if peers dial it.
- **Native capability:** ⚠️ Fulcio config is OIDC/CA-centric, not handshake.
- **Upstream task (U3):** expose handshake-policy flags for its served listeners.
- **Downstream task:** **edge = Verify** (router profile); **internal gRPC = sidecar**; ensure CTFE dial honors min version.
- **Strategy:** **Verify (edge) / Sidecar (internal).**

#### Rekor
- **Role:** transparency log API.
- **Surfaces:** **edge** API (Route) + **clients** to Trillian and Redis.
- **Upstream task (U4):** server handshake flags; **client** dial options to enforce min version.
- **Downstream task:** edge = Verify; internal client trust already via `tls.CAPath`/`UseTlsClient` (`internal/utils/tls/tls.go`) — add version flooring.
- **Strategy:** **Verify (edge) / Sidecar+client (internal).**

#### TSA, TUF, CLI download
- **TSA** (`sigstore/timestamp-authority`): HTTP, edge-terminated ⇒ **Verify**; only act if it serves TLS directly.
- **TUF:** static file server behind Route/Ingress ⇒ **Verify**.
- **CLI download:** console plugin over Ingress ⇒ **Verify**.

#### Operator manager (this repo)
- **Role:** controller process; metrics/healthz; **no admission webhook** today.
- **Native capability:** ✅ Go 1.26.
- **Downstream task:** if/when it serves TLS (metrics over HTTPS, future webhook), set `tls.Config` `MinVersion`/`CurvePreferences` from the profile — **never** rely on Go defaults (epic AC).
- **Strategy:** **Native.**

---

## 7. The pivotal decision — native flags (A) vs TLS-terminating sidecar (B)

This single choice reshapes Stories 7–12.

| | **A — Upstream flags** | **B — TLS-terminating sidecar** |
| --- | --- | --- |
| What | Add min-version/cipher/curve flags to Trillian/CTFE/Fulcio/Rekor | Front each internal listener with nginx/envoy/haproxy configured by the operator |
| Pros | Clean, no extra process, "right" long-term | Ships in-repo, no multi-repo coordination, uniform profile application, decouples from Go-1.3 limits |
| Cons | Multi-repo, slow, release-risky for 4.22; still bound by Go 1.3 cipher rule | +1 container/pod (resources, image, supply-chain), extra hop, mTLS plumbing |
| 4.22 fit | ❌ unlikely in time | ✅ realistic blocker path |

**Recommendation:** **B for the 4.22 release-blocker**, **A as upstream follow-up** that later retires the sidecars. Lock this in Decision **D1** before estimating 7–12.

---

## 8. Cross-cutting workstreams

1. **TLS profile source reader (foundation):** read `APIServer` (default) + `IngressController` `tlsSecurityProfile`; resolve presets **and Custom**; emit canonical `{minVersion, ciphers[], curves[]}`. **Watch** those config resources so profile edits trigger re-reconcile. Add RBAC (`config.openshift.io` `apiservers`/`ingresscontrollers` get/list/watch). Reuse `library-go/pkg/crypto` or a minimal vendored mapping.
2. **`TLSAdherence` propagation + knob precedence:** legacy vs strict; API-Server-vs-Ingress authority; strict = **fail closed**, no silent default fallback.
3. **Name-mapping layer:** Go ⇄ IANA ⇄ OpenSSL cipher/curve names per operand format (Redis vs MySQL vs proxy vs Go flags). Single source of truth + tests.
4. **Client-side adherence:** every inter-component dial (CTlog→Trillian, Rekor→Trillian/Redis, Fulcio→CTFE, Trillian→DB) enforces the profile's min version. Partly upstream.
5. **De-default hardening + Semgrep:** assert no code path silently relies on Go/Redis/MySQL defaults; add a Semgrep ruleset to catch regressions (expect false positives — review).
6. **Verification & CI:** `tls-scanner` endpoint scans; continuous **port-scan / eBPF handshake** check; e2e matrix over **Old / Intermediate / Modern / Custom**; assert strict-mode rejects disallowed handshakes.
7. **Docs:** the "three knobs" customer guide + the **Go-TLS-1.3-cipher limitation** caveat + external-DB/BYO-Redis responsibility boundary.

---

## 9. Out of scope (state explicitly to avoid scope creep)

- **Signing material** — Fulcio CA, TSA cert chain (`internal/controller/tsa/utils/tsa_cert_chain.go`), Rekor/CTlog signing keys. These are *identities*, not transport TLS; separate rotation lifecycle.
- **Kubelet `tlsSecurityProfile`** — no node agents.
- **External DB / BYO Redis internals** — customer-owned; we document + validate, not enforce.
- **Cert provisioning source** (manual/service-ca/off) — that's the **Layer-1** enable/disable refactor, tracked separately; this epic assumes TLS is already provisioned.

---

## 10. Open decisions (resolve before sizing)

- **D1 (pivotal):** native flags (A) vs sidecar (B) vs hybrid? → shapes Stories 7–12.
- **D2:** API-Server profile authoritative for all internal services? Any per-component override allowed?
- **D3:** Do we *own* edge endpoints or accept router/Ingress profile as sufficient (verify-only)?
- **D4:** External DB / BYO Redis boundary wording — validate-and-warn vs document-only.
- **D5:** Where does `TLSAdherence` (legacy|strict) live — operator flag/env vs. CRD field? Precedence vs. cluster setting?
- **D6:** Re-encrypt vs edge termination for any endpoint that must be E2E-encrypted (changes "verify-only" to "real work").

---

## 11. Phased delivery / proposed JIRA tree

**Epic (this repo):** *Adopt centralized OpenShift `tlsSecurityProfile` for Trusted Artifact Signer (PQC-readiness)* — child of PLMPGM-6492.

**Foundation (blockers):**
1. TLS profile source reader (+watch +RBAC).
2. `TLSAdherence` toggle + knob precedence.
3. Cipher/curve name-mapping layer.

**Apply — fully in-repo (do first, prove pattern):**
4. Redis directives.
5. Trillian managed DB my.cnf (+ external-DB boundary docs).

**Decision gate:**
6. Architecture spike — sidecar vs upstream (D1) + reference impl.

**Apply — gated by D1:**
7. Trillian LogServer/LogSigner. 8. CTlog/CTFE. 9. Fulcio internal gRPC (edge = verify). 10. Rekor server + clients. 11. TSA/TUF confirm edge-only.

**Cross-cutting:**
12. Client-side min-version enforcement. 13. De-default + Semgrep. 14. Verification & CI matrix (Old/Intermediate/Modern/Custom). 15. Docs.

**Upstream tracking (separate repos, referenced from epic):**
- U1 google/trillian · U2 certificate-transparency-go · U3 sigstore/fulcio · U4 sigstore/rekor · U5 sigstore/timestamp-authority — add min-version/cipher/curve flags.
- U6 — bump operand build toolchains to **Go ≥ 1.24** for default hybrid PQC groups.

**Dependency order:** `1,2,3 → 4,5 (quick win) → 6 (spike) → 7–12 → 13–15`. `U1–U6` run in parallel and may retire sidecars later.

---

## 12. Acceptance criteria → workstream mapping

| Epic DoD | Covered by |
| --- | --- |
| Remove all local/hardcoded TLS config | 4,5,7–12 (+ Semgrep 13) |
| Fetch & apply policy from central source (API-Server default / Ingress) | 1,2 + per-component apply |
| `tls-scanner` confirms endpoint compliance | 14 |
| Service remains stable/accessible to legit clients | 12,14 (matrix incl. Old/Intermediate) |
| Explicitly respect profile; no Go defaults | 5 (de-default), 6 (strict fail-closed) |
| Semgrep review for residual hardcoded TLS | 13 |
| Functional tests incl. **Custom** profile | 14 |
| PQC-ready in one pass | 1–12 end-to-end + U6 (Go ≥1.24 images) |

---

## 13. Risk register

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Upstream flags miss 4.22 | High | Sidecar (B) as blocker path; upstream as follow-up |
| Go TLS 1.3 ciphers non-configurable → silent profile drift | High | Document; in strict mode assert version+groups, accept 1.3 suite set; sidecar (non-Go proxy) where exact cipher control required |
| Operand images built with Go <1.24 → no PQC groups | High | U6 build-toolchain bump; CI assert negotiated group |
| Custom profiles disabling algorithms | Med | First-class Custom support + name-mapping tests (3) |
| External DB / BYO Redis non-compliant | Med | Document boundary (D4); validate-and-warn |
| Sidecar supply-chain / resource cost | Med | Minimal hardened proxy image; resource limits; revisit once upstream lands |
| Re-encrypt needs at edge | Med | D6; treat as real work, not verify-only |

---

## Appendix A. Decoding the parent-epic statement

The PLMPGM-6492 summary is dense with OpenShift-specific jargon. Here it is, clause by clause, in plain terms — useful for reviewers who haven't lived in `#forum-ocp-tls-strict-obedience`.

> *"...centralizes security configurations via the existing OpenShift API server `tlsSecurityProfile`..."*

There is **already** a cluster-wide setting — `APIServer.spec.tlsSecurityProfile` — where the admin declares the allowed TLS version + ciphers (Old / Intermediate / Modern / Custom). The plan is to make **every component read from this one existing setting** instead of hardcoding its own. "Centralize" = one source of truth, many consumers.
**For us:** our services must *pull* version/ciphers from here, not inherit library defaults.

> *"...introducing a mandatory `TLSAdherence` toggle (legacy or strict) to enforce compliance..."*

A **new** cluster switch with two positions: **legacy** (tolerate not-yet-migrated components — a grace period) and **strict** (components *must* obey; deviation is a defect). It's "mandatory" in that the switch always exists and every component is expected to honor it.
**For us:** read this switch; in **strict** mode **fail closed** (error out) rather than silently fall back to defaults.

> *"...while letting the Ingress Controller API support legacy client overrides."*

A deliberate escape hatch: the API-server profile governs internal TLS strictly, but the **Ingress profile is allowed to be more permissive**, so an admin can keep older *external* clients working at the edge without weakening the whole cluster.
**For us:** this is exactly our **edge-vs-internal split** (§5). Edge endpoints follow the (possibly looser) Ingress profile; internal pod-to-pod traffic follows the stricter API-server profile. Two different knobs, on purpose.

> *"...non-compliance in 'strict' mode will be treated as a security bug..."*

Not tech-debt, not a feature request — a **release-blocking security defect** filed against *your* component. If your service negotiates a forbidden handshake while the cluster is in strict mode, that's a shippable blocker.
**For us:** this is why the epic is a **4.22 release blocker**, and why our verification matrix exists — to prove we never generate such a bug.

> *"...verified through ... eBPF-based handshake snooping, ... Golang instrumentation of crypto libraries, and continuous CI port scanning..."*

Three independent ways the platform team will **measure** us:
- **eBPF handshake snooping** — kernel-level capture of the *actual* handshake on the wire (what really got negotiated, regardless of what config claims).
- **Go crypto instrumentation** — hooking Go's `crypto/tls` to observe the version/suite each Go process picks internally.
- **CI port scanning** — automated scanners hitting our endpoints continuously, asserting only permitted profiles are accepted.

**For us:** "configure and hope" is not enough. Compliance is **measured on the wire**, so our tests must check the *negotiated* handshake, not just the rendered config.

> *"...to identify and resolve 'silent failures' caused by Golang's restrictive TLS 1.3 implementation."*

**The most important nuance.** Go **does not let you choose TLS 1.3 cipher suites** — `tls.Config.CipherSuites` only affects TLS ≤1.2; for 1.3 Go uses a fixed internal set you cannot restrict. So if an admin writes a **Custom** profile that disables a specific 1.3 suite, a Go server **cannot honor it** and keeps offering Go's built-in 1.3 suites. The handshake **silently diverges** from policy: no error, no log, but the scanners see a forbidden suite.
**For us:** this is the single biggest trap (Risk #2). It's *why* a **non-Go TLS-terminating proxy** (nginx/haproxy — which *can* restrict 1.3 suites) is on the table for operands we can't fully control in Go, and why QE must be warned that a "failure" here may be Go's limitation, not our bug.

**One-line takeaway:** the cluster gets **one place** to declare TLS policy, **one switch** to enforce it, with the **edge allowed to be looser** for old clients — and the platform team will **measure your actual handshakes** to catch cases where a Go service *says* it complies but, because Go can't constrain TLS 1.3 ciphers, **silently doesn't**.

---

*Generated as an analysis/design artifact. No production code changed by this document. File references point at current `main` of `secure-sign-operator`.*
