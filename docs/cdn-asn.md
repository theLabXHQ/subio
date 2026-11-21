# Edges, origins and address space

[← back to the README](../README.md)

## Telling an edge from an origin

A name whose address is a CDN edge says nothing about the machine behind it:
scanning that address scans the CDN, and a hundred names sharing it are one
vendor, not a hundred hosts. `subio cdn` is the cdncheck step of a pipeline.

```
subio cdn -i 104.16.0.1,www.example.com
subio discover example.com -silent | subio cdn -l - -e | subio resolve -l -
```

It reads two signals and no range file: the CNAME chain the resolver already
returns (`*.cloudfront.net`, `*.akamaiedge.net`, matched on a label boundary),
and Team Cymru's origin record for each address, checked against the
autonomous systems CDN, WAF and cloud providers announce from. A CNAME outranks
an AS. A host matching neither is `not_identified`, never "origin", because a
provider announcing from an unlisted AS goes unseen. `-e` passes on only the
hosts not behind a CDN or WAF; cloud hosts pass, since the machine may be the
target's own, and a lookup that got no answer does not pass, since it could be
an edge. That case exits 4.


## From an organisation to its address space

`subio asn` is the asnmap step, with mapcidr's operations on its output. Each
input is read as what it looks like: an AS number lists the prefixes it
announces (RIPEstat), an address or a domain leads to the AS that routes it
(Team Cymru), a range passes straight through, and anything else is searched
against the registries' AS holder names.

```
subio asn -i AS13335
subio asn -i example.com -agg
subio asn -i "Example Corp" -4 -j
subio asn -i 192.0.2.0/24 -e -shuffle
```

`-agg` merges contained and adjacent ranges, `-4`/`-6` pick a family, `-e`
prints every address (bounded by `-max`, which exits 4 when it cuts), `-shuffle`
randomises that list, and `-c` prints only the count. A name search matches
the text a registry was given, not ownership, so each matched AS is printed
for a person to check. When RIPEstat cannot be reached, an address's AS falls
back to the one prefix Cymru named, and the run says so and exits 4. It lists
address space and connects to none of it.

A domain or address hosted in a CDN's or a cloud provider's AS gets the range
that holds its own address, not the provider's whole network, and the run says
whose AS it is. Asked for kernel.org on 2026-11-21, the earlier behaviour
printed all 453 prefixes of Akamai's Linode AS as kernel.org's address space,
which is a list someone would go on to scan. `-whole-as` asks for the
provider's whole AS anyway; an AS named outright is always mapped whole.
