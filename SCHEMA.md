# subio output schema

`subio discover -ledger run.jsonl` writes the evidence trail, and
`-m run.json` writes the run manifest. This is their contract. It exists
because a tool whose whole claim is "every hostname joins to the observations
that produced it" has to make those records readable by something other than
itself — until now the only statement of these fields was the Go structs.

Current versions: ledger **`subio.ledger.v2`**, manifest
**`subio.run-manifest.v2`**.

## How to read the ledger

One JSON document per line, five record kinds distinguished by `kind`. Records
of different kinds are interleaved by design: a finding is followed by its
evidence and its DNS observations, then the per-source run records, then
resolver disagreements last.

**Read `kind` first and ignore kinds you do not know.** A new kind may be added
within the same version; a field may be added to an existing kind. What will not
happen without a version change is a field being removed, renamed, or given a
new meaning. `schema_version` is on every record, so a consumer can refuse a
version it was not written for.

**A missing value and an empty value are different.** Times are `null` when the
provider stated none — never backfilled with the collection time. `sources` is
never empty on a finding.

**`complete` is a statement about reading, not about the world.** It means subio
consumed the provider's whole answer. Whether that answer was the whole truth is
the provider's property, not subio's, and `source_run.caps_silently` marks the
runs where it is known not to be. A consumer deciding that a name has gone away
must read both fields, and the counts in `source_run` besides: a source is also
not whole when `unusable` is non-zero.

**Some keys are absent rather than empty**, so a parser must treat absence as
"nothing to say" and not as a schema error. They are marked *(absent when
empty)* below, and the list was built from real output rather than assumed:

- `evidence`: `record_id`, `evidence_ref`, `attributes`
- `dns_observation`: `rcode`, `records`, `cname_chain`, `truncated`, `wildcard_samples`, `error_class`, `extended_error`, `denial_inferred`, `inferred_from`
- `source_run`: `error_class`, `note`, `reset_at`, `caps_silently`, `wildcard_explained`, `failed_validation`, `dns_errors`
- `resolver_disagreement`: `claimed_records`, `checked_records`

`records` on a DNS observation being absent means the answer carried none — a
negative answer, which is an answer, and `outcome` is where that is stated.

## `kind: "finding"` — one canonical hostname

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | `subio.ledger.v2`. |
| `kind` | string | `finding`. |
| `finding_id` | hex string | Stable id for this hostname in this root; the join key for evidence and DNS records. |
| `fqdn` | string | The canonical hostname. See `normalization_profile`. |
| `root_domain` | string | The authorization root it was admitted under. A finding is always inside one root. |
| `sources` | array of string | Every source id that reported it, sorted. Never empty. |
| `families` | array of string | The evidence families those sources belong to, sorted. Two sources in one family are not independent confirmation. |
| `first_seen_at` / `last_seen_at` | RFC3339 or `null` | The **provider's** stated times. `null` means the provider stated none. |
| `evidence_count` | integer | How many evidence records point at this finding. |
| `verification_status` | enum | `not_checked`, `resolved`, `nxdomain`, `nodata`, `resolution_error`. `not_checked` means no DNS stage ran, not that the name is absent. |
| `wildcard_suspected` | bool | The name resolves the way a wildcard would, so its existence is not established. |
| `original_values` | array of string | The spellings providers actually returned, before canonicalization. Canonicalization is lossy and the original is evidence. |
| `normalization_profile` | string | `idna2008-uts46`. A different profile would mean `fqdn` is not comparable with an older run's. |

## `kind: "evidence"` — one provider assertion

| Field | Type | Meaning |
|---|---|---|
| `schema_version`, `kind` | string | `evidence`. |
| `evidence_id` | hex string | Stable id for this assertion. |
| `finding_id` | hex string | The finding this is evidence for. |
| `source_id` | string | Which adapter reported it. |
| `family` | string | `certificate-transparency`, `passive-dns`, `code-search`, `scan-engine`, `web-archive`, `threat-intel`, `curated-dataset`, `local-import`, `active-dns`, `active-http`. |
| `method` | string | How the name appeared: `certificate-san`, `archived-url`, `code-match`, and so on. |
| `observed_at` | RFC3339 or `null` | The provider's stated observation time. `null` when it stated none. |
| `collected_at` | RFC3339 | When subio asked. Always present, and never a substitute for `observed_at`. |
| `record_id` | string *(absent when empty)* | The provider's own id for the underlying record — a certificate id, an archive digest, a commit sha. |
| `evidence_ref` | string *(absent when empty)* | A pointer at that record. Never contains a credential. |
| `original_value` | string | The hostname as this provider spelled it. |
| `attributes` | object or absent | Small allowlisted extras, e.g. `wildcard_certificate: "true"`. Not a copy of the raw payload. |

## `kind: "dns_observation"` — one resolver answer

| Field | Type | Meaning |
|---|---|---|
| `schema_version`, `kind` | string | `dns_observation`. |
| `finding_id`, `fqdn` | string | What was asked about. |
| `checked_at` | RFC3339 | When. |
| `resolver` | string | Which resolver answered. Two resolvers can disagree; see the disagreement record. |
| `query_type` | string | `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`, `CAA`, `PTR`. |
| `rcode` | string *(absent when empty)* | The DNS response code as text. |
| `outcome` | enum | `resolved`, `nxdomain`, `nodata`, `resolution_error`. An error is not a negative. |
| `records` | array of `{type, value, ttl}` *(absent when empty)* | Absent on a negative answer, which is an answer. |
| `cname_chain` | array of string *(absent when empty)* | The chain followed, when there was one. |
| `truncated` | bool *(absent when false)* | The answer was truncated and TCP was or was not retried. |
| `wildcard_suspected` | bool | This answer matches the zone's wildcard profile. |
| `wildcard_samples` | array of string *(absent when empty)* | The random names the wildcard profile was built from, so the verdict can be checked. |
| `extended_error` | string *(absent when empty)* | The reason the resolver attached, RFC 8914, as text — for example `filtered: blocked by policy`. Three codes describe this answer rather than a failure: `forged answer`, `synthesized` and `stale answer` each say these records may not be what the zone publishes. |
| `denial_inferred` | bool *(absent when false)* | This negative answer came from the resolver's own cache or synthesis, not from the zone on this occasion — EDE `stale answer`, `stale nxdomain answer` or `synthesized`. `outcome: nxdomain` alone cannot say that, and the difference is whether anything asked the zone. |
| `inferred_from` | string *(absent when asked)* | subio did not send this query. A resolver had just answered NXDOMAIN, with the zone's SOA, for the name given here - this name or one above it - and RFC 8020 says nothing exists beneath a name that does not exist. Only zones whose earlier checks kept that rule are inferred from; `resolver` is the one that gave the denial. Not `denial_inferred`: that is a resolver's memory, this is subio's. |
| `error_class` | string or absent | Set when `outcome` is `resolution_error`. |

## `kind: "source_run"` — what one adapter did

The record that makes "what did I fail to see?" answerable. 25 fields; the ones
a consumer most often needs:

| Field | Type | Meaning |
|---|---|---|
| `run_id` | string | Ties every source_run record to the same run, so a ledger holding several runs can be split by it. |
| `source_id`, `family` | string | Which adapter. |
| `status` | enum | `complete`, `empty`, `partial`, `truncated`, `failed`, `throttled`, `timed_out`, `cancelled`, `missing_credentials`, `terms_blocked`. **Only `complete` and `empty` mean subio read the provider's whole answer** — and read `caps_silently` before concluding the answer was whole. |
| `caps_silently` | bool *(absent when false)* | This provider can return a short result set with nothing in the response to say so, and this run returned names. `status: "complete"` beside this field means subio read everything it was given, not that it was given everything: **a name's absence in this source's output is not evidence.** Set from the provider's own documented cap or a measurement here, never guessed. On `crtsh` it comes from measuring 21 names against crt.sh's own database holding 2334 for the same domain, with both runs reporting `complete`; `-s crtshdb` queries that database. It does not affect the exit code, because the status is true about what was read. |
| `error_class` | string or absent | `unauthorized`, `forbidden_entitlement`, `rate_limited`, `provider_unavailable`, `schema_drift`, `partial_pagination`, `pagination_loop`, `deadline`, `cancelled`, `oversize_response`, `scope_rejected`, `transport`, `redirect_refused`. |
| `note` | string or absent | One sanitized operator-visible line. |
| `terms_state` | string | `unknown`, `review_required`, `blocked_commercial`, `permitted`. |
| `requests`, `pages`, `retries`, `rate_limit_hits` | integer | What it cost the provider. |
| `raw_observations`, `in_scope_observations`, `out_of_scope_rejected`, `malformed_rejected` | integer | What it returned and what was dropped, kept apart: a source that emits mostly noise should look noisy. |
| `unique_names`, `marginal_names` | integer | Distinct names, and those only this source reported. |
| `duration_ms` | integer | Wall time for this source. |
| `quota_remaining`, `reset_at` | integer / RFC3339 *(`reset_at` absent when empty)* | What the provider said about its own quota, when it said anything. |
| `wildcard_explained`, `failed_validation`, `dns_errors` | integer *(absent when zero)* | Per-source counts from the later stages. |

## `kind: "resolver_disagreement"` — two resolvers, two answers

Kept even when the name it concerns is not reported, because which resolver was
contradicted is the operator's evidence for removing it from their list.

| Field | Type | Meaning |
|---|---|---|
| `fqdn`, `query_type`, `checked_at` | | What was asked, and when. |
| `claimed_by`, `claimed_outcome`, `claimed_records` | string / enum / array *(records absent when empty)* | The resolver that answered first, and what it said. |
| `checked_by`, `checked_outcome`, `checked_records` | string / enum / array *(records absent when empty)* | The resolver that was asked to confirm, and what it said. |
| `kept` | bool | Whether the name was kept. |

## The manifest

`-m run.json` is one object describing the run without recording what it looked
at: the roots are reduced to a hash, so a manifest can be attached to a ticket.
`manifest_schema_version` is `subio.run-manifest.v2` and `ledger_schema_version`
names the ledger contract the run wrote.

## Versioning rule

The version changes when an existing field's meaning changes, when a field is
removed or renamed, or when canonicalization changes such that `fqdn` values
from two runs are no longer comparable — that last one is why
`normalization_profile` is on every finding.

Adding a field, or adding a value to an enum, does **not** change the version:
no existing record is reinterpreted. `error_class: "cancelled"` was added on
2026-11-10 for exactly that reason, so that a source still working when the
operator pressed Ctrl-C stopped being reported as one that ran out of time.

`test/docs` fails the build if a field in these records is not named here, so
this file cannot drift behind the code without someone noticing. It caught one
field missing from the first draft of this file (`source_run.run_id`), and a run
against the hermetic fixture confirmed every name above appears in real output —
which is where the absent-when-empty list came from.
