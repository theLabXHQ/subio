# Related roots

[← back to the README](../README.md)

## Suggesting related roots

Subdomain tools enumerate under a root you already know. They miss the horizontal
surface: sibling brands, regional domains, acquisitions — whole *other* roots. A
certificate often covers several at once, and most tools discard those names for
falling outside the queried root.

```
subio relate -d example.com
subio relate -d example.com -s crtsh,scanmalware -min 2 -j
subio relate -d example.com -whois -records
subio relate -d example.com -asn -rs 9.9.9.9
```

Four signals, and they do not establish the same thing. `relate` ranks on what
each one proves, not on how much of it there is:

| `CONFIDENCE` | Signal | What it establishes |
|---|---|---|
| `owner` | `-whois` | the registries say the same registrant registered both |
| `strong` | certificates (default) | one certificate covers the target and this apex |
| `medium` | `-whois` | the registry's domain search ties it to your own nameserver |
| `weak` | `-asn`, `-records` | shared infrastructure, which is not ownership |

The default signal reads the target's certificate transparency and reports the
other registrable domains those certificates cover. On google.com it surfaces the
regional Google domains (google.com.au, google.com.br, …) that share hundreds of
certificates.

`-whois` is reverse-WHOIS done honestly. The product sold under that name is a
vendor's bulk index; what the registries' own protocol gives for free is
**confirmation** — for each apex another signal suggested, ask its registry who
registered it and compare that with the target's registrant. On `laposte.fr` it
confirms five of seven suggested apexes as La Poste's own, and one of those five
shares a single certificate yet outranks an apex with fourteen. It also runs
RDAP's one standardized reverse query, the `nsLdhName` domain search, on
nameservers inside your own apex only — a provider's nameserver would answer with
its other customers. Expect it to be empty on `.com`: post-GDPR registries
withhold the registrant, which `relate` reports as a missing signal rather than
as an absence of relatives.

`-asn` reads the reverse DNS of the autonomous system your roots are routed in,
via Team Cymru's DNS interface and RIPEstat's prefix list. It is the weakest
signal and mostly refuses to run: above `-asn-max-addresses` (default 65536) the
system is a hosting provider's, where the neighbours are other customers, so
`relate` says so and sweeps nothing. On AS3333 (RIPE NCC, 4608 addresses) a full
sweep found `root-servers.org`, which RIPE NCC does operate, alongside two
neighbours that are infrastructure rather than property.

`-records` adds the apexes the target's own MX, NS, SOA and TXT (SPF, DMARC)
records point at. A mail or DNS provider shows up here as well as a sibling the
target runs, so each apex carries its record type in `VIA`. On google.com it adds
nothing, correctly: Google's MX, NS and SPF all point back at google.com itself.

`-min` is a threshold on *certificate* count, so it never hides a registrant
match or an ASN neighbour, which have no certificates by nature.

These are **suggestions, not findings**. subio's core rule is that discovery never
widens the authorization scope, so `relate` enumerates nothing under a suggested
root and writes nothing into any run. You verify ownership and add a root with
`-d` yourself. `-whois` discloses each suggested apex to its own registry, and
`-asn` reads public reverse DNS for third-party address space; neither sends
anything to a suggested root or to a name under it.
