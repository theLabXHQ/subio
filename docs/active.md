# Active discovery

[← back to the README](../README.md)

## Finding names no index holds

Passive tools converge, because they all read the same upstream data. To find what
no index has, you have to ask DNS, and that is where a fast resolver pays off.

**All of this guesses at names on the target's nameservers or connects to its
servers.** It needs `-active` and a written record naming the roots, and it refuses
to run without both, before sending anything:

```
subio discover example.com -active -auth auth.json -active-all
subio discover example.com -active -auth auth.json -brute -permute -mine
subio discover example.com -active -auth auth.json -cands from-subwiz.txt -rqps 100
subio discover example.com -active -auth auth.json -web -tls -rs @resolvers.txt
subio discover example.com -active -auth auth.json -w mylist.txt -depth 2 -rs @resolvers.txt -qps 5000
subio discover example.com -active -auth auth.json -permute -trusted 8.8.8.8 -store ./state
```

| flag | what it does |
|---|---|
| `-active-all` | turns on every method below that needs only `active-dns` (brute, permute, mine, nsec, ptr, axfr), for a full sweep in one flag. `-tls` and `-web` stay opt-in because they need their own method |
| `-brute`, `-w` | asks a wordlist under each root: yours, or a small built-in one. Labels your known names already use go first |
| `-permute` | asks variations of known names. Rules learned from the root's own naming scheme go first, then numbers, swapped parts, siblings and joins |
| `-cands` | resolves full candidate names from a file, from any external generator (subwiz, an LLM, gotator, dnsgen). They pass the same scope gate, NSEC3 filter, wildcard handling and ledger as every other guess, so a third-party generator gains subio's correctness without subio bundling its code |
| `-depth N` | also asks under found names, N levels down. A name answering NXDOMAIN is skipped, since RFC 8020 says nothing exists beneath it |
| `-mine` | reads each root's NS, MX, SOA, TXT, DMARC and common SRV records for names |
| `-axfr` | tries a zone transfer from each nameserver |
| `-nsec` | walks the zone's NSEC chain, where it exposes one. On an NSEC3 zone it maps the hashed chain instead and reverses it against a wordlist offline: a guess is hashed locally and compared, so a name is confirmed or ruled out without a query. A guess the chain proves absent is never sent, so a brute or permutation run over an NSEC3 zone costs local hashing, not a query per guess |
| `-ptr` | reads reverse DNS of the addresses found |
| `-tls` | reads certificate names from found hosts on port 443. Needs `active-tls` in the record |
| `-web` | reads the hostnames a found host's own page and headers reference — its content-security-policy, its links, its absolute URLs, and the hostnames in its own JavaScript. This reaches names with no DNS record of their own, such as a host named only in a sibling's CSP, which no passive source or DNS method can find. A referenced name is still resolved before it counts. Needs `active-http` in the record |
| `-vhost` | probes each found address for virtual hosts: names the server serves a *distinct* site for even though no DNS record points to them. It takes a baseline from two random hosts, skips a server whose answers vary, and flags a candidate only when its response differs from both baselines — conservative, because a flagged vhost is a claim to act on. A hit is HTTP evidence under the `active-http` family, never presented as a resolved name. Needs `active-http` in the record |
| `-trusted` | keeps a guess only if these resolvers confirm it. A rejection is kept as evidence, not just counted: the ledger gets a `resolver_disagreement` record naming both sides and what each answered, the report names the contradicted resolver and suggests removing it, and the manifest counts it per resolver. `.invalid` vetting only catches a resolver that lies about everything; this catches one that lies selectively |
| `-max-candidates` | ceiling on guesses per run, 5 million by default |

Three rules hold throughout:

- A guess never widens the scope. Every candidate is checked against your roots
  before a packet is sent, and a name in a DNS record or certificate outside them is
  never queried.
- A guess is a finding only if a resolver answers and a wildcard does not explain
  the answer. Under a wildcard, the exact records are what remain, and the report
  says how many guesses were explained away. No guess is backed by a provider, so the
  ledger records these under their own `active-dns` family.
- A run that hit its ceiling reports `truncated`, and one with lookups no resolver
  answered reports `partial`, since a real name may be among them.

The authorization record is the one under [Comparing against other
tools](benchmarks.md#comparing-against-other-tools), with `active-dns` in `allowed_methods`, and
optionally `max_qps` and `max_candidates`, which subio enforces. The manifest records
who authorized the run and the SHA-256 of each wordlist. Only the target's owner can
grant this, so write the record only for a target you hold that authority over.

None of this has been measured against a real zone yet. It is tested against
synthetic DNS. The approach to learned rules follows published
descriptions of the technique; no code from such tools was used.


## The built-in wordlist is English

`-brute` without `-w` uses a built-in list of 432 labels, written from common
hosting, mail and development vocabulary. A run says so at the moment it starts
guessing, because the fact that matters most about that list is invisible
otherwise:

```
[INF] brute: the built-in list is 432 English labels. On a target that does not
work in English, -w with a list of your own is the difference between finding
those names and not
```

That is not a general caution. A comparison against a commercial dataset on
`kun.uz` found four hostnames whose labels are Uzbek or Russian words — `sklad`,
`reklama`, `muxbir`, `bizninguylar` — and no English list of any size reaches
them (the measurement).

Padding the built-in list with one language's vocabulary is still the wrong
fix, for the reason it always was: `-brute` costs one query per label per name,
so every English target would pay for labels that cannot appear in it. But
leaving the operator to source a list from nothing was not much better, so
since 2026-11-17 there is a second built-in list, kept separate and off by
default:

```
subio discover kun.uz -active -auth auth.json -brute -uz
```

`-uz` adds an Uzbek and Russian label list to the run. Two things to know about
it. The four names above are in it and they are the only entries with any
evidence behind them — the rest are plausible, not measured, which is the same
standard as the English list. And it is Latin script only: a Cyrillic label
reaches DNS as punycode, so a word written in Cyrillic would never match the
wire form of the name it is meant to find. A zone that publishes Cyrillic
hostnames needs those punycode forms in a `-w` list built for it.

`-w` remains the right answer for a list specific to one zone, and `subio`
keeps the list you give it out of its own records, so bring its source and
licence with you.


## `subio all`

One command that turns on every discovery method, and no more than the
authorization allows:

```
subio all example.com                      # fullest run that needs nobody's permission
subio all example.com -auth auth.json      # the record selects the rest
subio all example.com -auth auth.json -a -ledger run.jsonl
```

The rule is the one the rest of the tool enforces: **the record decides, not the
flag.** Without `-auth` it runs every enabled passive adapter and then observes
DNS for what they reported. With `-auth`, `allowed_methods` is read and the
methods come on to match it - `active-dns` enables brute, permute, mine, nsec,
ptr and axfr; `active-tls` enables `-tls`; `active-http` enables `-web` and
`-vhost`. A method the record does not grant is never requested, so `all` cannot
be the reason a run reached further than its paperwork. A record that grants
nothing active is reported and the run stays passive rather than being refused.

It is a preset over `discover`, not a second implementation, so every `discover`
flag works and anything you pass explicitly wins.

Two things it deliberately leaves alone. It does not change how results print or
write any file: add `-a`, `-ledger`, `-m` yourself. And it does not turn on
`-authoritative`, which asks each root's own nameservers instead of a recursive
resolver - sound with a record in hand, but it fails a whole run when a root
publishes no NS record subio can read rather than falling back quietly, which is
right for a flag you typed and wrong for one a preset chose.
