# `nu_plugin_dns`

[Nushell](http://www.nushell.sh/) plugin that does DNS queries  and parses
results into meaningful types. Intended to be a native replacement for
[`dig`](https://en.m.wikipedia.org/wiki/Dig_(command)). Uses the excellent
[`hickory`](https://github.com/hickory-dns/hickory-dns) crates.

## Usage

* All queries by default attempt to validate records with DNSSEC. If records
  do not have DNSSEC or the nameserver does not support it, then by default, it
  falls back to plain queries. This behavior can be tuned with the `--dnssec`
  flag.
* Supported protocols are UDP, TCP, TLS, HTTPS, and QUIC
* If no nameserver address is specified, the system's DNS config is used, or if
  none is available, falls back to Google.

### Examples

```
simple query for A / AAAA records
> dns query amazon.com

╭─#─┬───────────────header───────────────┬────────question─────────┬────────────────────────────answer─────────────────────────────┬──────────────────────────────────────────authority───────────────────────────────────────────┬───additional───┬────────────────edns─────────────────┬─size──╮
│ 0 │ ╭─────────────────────┬──────────╮ │ ╭───────┬─────────────╮ │ ╭─#─┬────name─────┬type┬class┬────ttl─────┬──────rdata──────╮ │ [list 0 items]                                                                               │ [list 0 items] │ ╭─────────────┬───────────────────╮ │  87 B │
│   │ │ id                  │ 26694    │ │ │ name  │ amazon.com. │ │ │ 0 │ amazon.com. │ A  │ IN  │ 3min 35sec │ 54.239.28.85    │ │                                                                                              │                │ │ rcode_high  │ 0                 │ │       │
│   │ │ message_type        │ RESPONSE │ │ │ type  │ A           │ │ │ 1 │ amazon.com. │ A  │ IN  │ 3min 35sec │ 52.94.236.248   │ │                                                                                              │                │ │ version     │ 0                 │ │       │
│   │ │ op_code             │ QUERY    │ │ │ class │ IN          │ │ │ 2 │ amazon.com. │ A  │ IN  │ 3min 35sec │ 205.251.242.103 │ │                                                                                              │                │ │ dnssec_ok   │ false             │ │       │
│   │ │ authoritative       │ false    │ │ ╰───────┴─────────────╯ │ ╰───┴─────────────┴────┴─────┴────────────┴─────────────────╯ │                                                                                              │                │ │ max_payload │ 512 B             │ │       │
│   │ │ truncated           │ false    │ │                         │                                                               │                                                                                              │                │ │ opts        │ {record 0 fields} │ │       │
│   │ │ recursion_desired   │ true     │ │                         │                                                               │                                                                                              │                │ ╰─────────────┴───────────────────╯ │       │
│   │ │ recursion_available │ true     │ │                         │                                                               │                                                                                              │                │                                     │       │
│   │ │ authentic_data      │ false    │ │                         │                                                               │                                                                                              │                │                                     │       │
│   │ │ response_code       │ No Error │ │                         │                                                               │                                                                                              │                │                                     │       │
│   │ │ query_count         │ 1        │ │                         │                                                               │                                                                                              │                │                                     │       │
│   │ │ answer_count        │ 3        │ │                         │                                                               │                                                                                              │                │                                     │       │
│   │ │ name_server_count   │ 0        │ │                         │                                                               │                                                                                              │                │                                     │       │
│   │ │ additional_count    │ 1        │ │                         │                                                               │                                                                                              │                │                                     │       │
│   │ ╰─────────────────────┴──────────╯ │                         │                                                               │                                                                                              │                │                                     │       │
│ 1 │ ╭─────────────────────┬──────────╮ │ ╭───────┬─────────────╮ │ [list 0 items]                                                │ ╭─#─┬────name─────┬type─┬class┬────ttl─────┬─────────────────────rdata─────────────────────╮ │ [list 0 items] │ ╭─────────────┬───────────────────╮ │ 106 B │
│   │ │ id                  │ 43590    │ │ │ name  │ amazon.com. │ │                                                               │ │ 0 │ amazon.com. │ SOA │ IN  │ 1min 34sec │ ╭─────────┬─────────────────────────────────╮ │ │                │ │ rcode_high  │ 0                 │ │       │
│   │ │ message_type        │ RESPONSE │ │ │ type  │ AAAA        │ │                                                               │ │   │             │     │     │            │ │ mname   │ dns-external-master.amazon.com. │ │ │                │ │ version     │ 0                 │ │       │
│   │ │ op_code             │ QUERY    │ │ │ class │ IN          │ │                                                               │ │   │             │     │     │            │ │ rname   │ hostmaster.amazon.com.          │ │ │                │ │ dnssec_ok   │ false             │ │       │
│   │ │ authoritative       │ false    │ │ ╰───────┴─────────────╯ │                                                               │ │   │             │     │     │            │ │ serial  │ 2010185872                      │ │ │                │ │ max_payload │ 512 B             │ │       │
│   │ │ truncated           │ false    │ │                         │                                                               │ │   │             │     │     │            │ │ refresh │ 3min                            │ │ │                │ │ opts        │ {record 0 fields} │ │       │
│   │ │ recursion_desired   │ true     │ │                         │                                                               │ │   │             │     │     │            │ │ retry   │ 1min                            │ │ │                │ ╰─────────────┴───────────────────╯ │       │
│   │ │ recursion_available │ true     │ │                         │                                                               │ │   │             │     │     │            │ │ expire  │ 1wk                             │ │ │                │                                     │       │
│   │ │ authentic_data      │ false    │ │                         │                                                               │ │   │             │     │     │            │ │ minimum │ 15min                           │ │ │                │                                     │       │
│   │ │ response_code       │ No Error │ │                         │                                                               │ │   │             │     │     │            │ ╰─────────┴─────────────────────────────────╯ │ │                │                                     │       │
│   │ │ query_count         │ 1        │ │                         │                                                               │ ╰───┴─────────────┴─────┴─────┴────────────┴───────────────────────────────────────────────╯ │                │                                     │       │
│   │ │ answer_count        │ 0        │ │                         │                                                               │                                                                                              │                │                                     │       │
│   │ │ name_server_count   │ 1        │ │                         │                                                               │                                                                                              │                │                                     │       │
│   │ │ additional_count    │ 1        │ │                         │                                                               │                                                                                              │                │                                     │       │
│   │ ╰─────────────────────┴──────────╯ │                         │                                                               │                                                                                              │                │                                     │       │
╰───┴────────────────────────────────────┴─────────────────────────┴───────────────────────────────────────────────────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────┴────────────────┴─────────────────────────────────────┴───────╯
```

```
specify query type
> dns query --type CNAME en.wikipedia.org

╭─#─┬───────────────header───────────────┬───────────question────────────┬─────────────────────────────────────answer──────────────────────────────────────┬───authority────┬───additional───┬────────────────edns─────────────────┬─size─╮
│ 0 │ ╭─────────────────────┬──────────╮ │ ╭───────┬───────────────────╮ │ ╭─#─┬───────name────────┬─type──┬class┬───────ttl───────┬────────rdata────────╮ │ [list 0 items] │ [list 0 items] │ ╭─────────────┬───────────────────╮ │ 74 B │
│   │ │ id                  │ 40068    │ │ │ name  │ en.wikipedia.org. │ │ │ 0 │ en.wikipedia.org. │ CNAME │ IN  │ 4hr 26min 40sec │ dyna.wikimedia.org. │ │                │                │ │ rcode_high  │ 0                 │ │      │
│   │ │ message_type        │ RESPONSE │ │ │ type  │ CNAME             │ │ ╰───┴───────────────────┴───────┴─────┴─────────────────┴─────────────────────╯ │                │                │ │ version     │ 0                 │ │      │
│   │ │ op_code             │ QUERY    │ │ │ class │ IN                │ │                                                                                 │                │                │ │ dnssec_ok   │ false             │ │      │
│   │ │ authoritative       │ false    │ │ ╰───────┴───────────────────╯ │                                                                                 │                │                │ │ max_payload │ 512 B             │ │      │
│   │ │ truncated           │ false    │ │                               │                                                                                 │                │                │ │ opts        │ {record 0 fields} │ │      │
│   │ │ recursion_desired   │ true     │ │                               │                                                                                 │                │                │ ╰─────────────┴───────────────────╯ │      │
│   │ │ recursion_available │ true     │ │                               │                                                                                 │                │                │                                     │      │
│   │ │ authentic_data      │ false    │ │                               │                                                                                 │                │                │                                     │      │
│   │ │ response_code       │ No Error │ │                               │                                                                                 │                │                │                                     │      │
│   │ │ query_count         │ 1        │ │                               │                                                                                 │                │                │                                     │      │
│   │ │ answer_count        │ 1        │ │                               │                                                                                 │                │                │                                     │      │
│   │ │ name_server_count   │ 0        │ │                               │                                                                                 │                │                │                                     │      │
│   │ │ additional_count    │ 1        │ │                               │                                                                                 │                │                │                                     │      │
│   │ ╰─────────────────────┴──────────╯ │                               │                                                                                 │                │                │                                     │      │
╰───┴────────────────────────────────────┴───────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────┴────────────────┴────────────────┴─────────────────────────────────────┴──────╯
```

```
specify query types by numeric ID, and get numeric IDs in output
> dns query --type [5, 15] -c google.com

╭─#─┬────────────────────header─────────────────────┬───────────question───────────┬─────────────────────────────────────────────answer──────────────────────────────────────────────┬─────────────────────────────────────────────authority─────────────────────────────────────────────┬───additional───┬────────────────edns─────────────────┬─size─╮
│ 0 │ ╭─────────────────────┬─────────────────────╮ │ ╭───────┬───────────────╮    │ ╭─#─┬────name─────┬─────type──────┬─────class─────┬──ttl──┬───────────────rdata───────────────╮ │ [list 0 items]                                                                                    │ [list 0 items] │ ╭─────────────┬───────────────────╮ │ 60 B │
│   │ │ id                  │ 25259               │ │ │ name  │ google.com.   │    │ │ 0 │ google.com. │ ╭──────┬────╮ │ ╭──────┬────╮ │ 53sec │ ╭────────────┬──────────────────╮ │ │                                                                                                   │                │ │ rcode_high  │ 0                 │ │      │
│   │ │                     │ ╭──────┬──────────╮ │ │ │       │ ╭──────┬────╮ │    │ │   │             │ │ name │ MX │ │ │ name │ IN │ │       │ │ preference │ 10               │ │ │                                                                                                   │                │ │ version     │ 0                 │ │      │
│   │ │ message_type        │ │ name │ RESPONSE │ │ │ │ type  │ │ name │ MX │ │    │ │   │             │ │ code │ 15 │ │ │ code │ 1  │ │       │ │ exchange   │ smtp.google.com. │ │ │                                                                                                   │                │ │ dnssec_ok   │ false             │ │      │
│   │ │                     │ │ code │ 1        │ │ │ │       │ │ code │ 15 │ │    │ │   │             │ ╰──────┴────╯ │ ╰──────┴────╯ │       │ ╰────────────┴──────────────────╯ │ │                                                                                                   │                │ │ max_payload │ 512 B             │ │      │
│   │ │                     │ ╰──────┴──────────╯ │ │ │       │ ╰──────┴────╯ │    │ ╰───┴─────────────┴───────────────┴───────────────┴───────┴───────────────────────────────────╯ │                                                                                                   │                │ │ opts        │ {record 0 fields} │ │      │
│   │ │                     │ ╭──────┬───────╮    │ │ │       │ ╭──────┬────╮ │    │                                                                                                 │                                                                                                   │                │ ╰─────────────┴───────────────────╯ │      │
│   │ │ op_code             │ │ name │ QUERY │    │ │ │ class │ │ name │ IN │ │    │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │                     │ │ code │ 0     │    │ │ │       │ │ code │ 1  │ │    │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │                     │ ╰──────┴───────╯    │ │ │       │ ╰──────┴────╯ │    │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ authoritative       │ false               │ │ ╰───────┴───────────────╯    │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ truncated           │ false               │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ recursion_desired   │ true                │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ recursion_available │ true                │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ authentic_data      │ false               │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │                     │ ╭──────┬──────────╮ │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ response_code       │ │ name │ No Error │ │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │                     │ │ code │ 0        │ │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │                     │ ╰──────┴──────────╯ │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ query_count         │ 1                   │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ answer_count        │ 1                   │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ name_server_count   │ 0                   │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ additional_count    │ 1                   │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ ╰─────────────────────┴─────────────────────╯ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│ 1 │ ╭─────────────────────┬─────────────────────╮ │ ╭───────┬──────────────────╮ │ [list 0 items]                                                                                  │ ╭─#─┬────name─────┬──────type──────┬─────class─────┬─ttl──┬────────────────rdata────────────────╮ │ [list 0 items] │ ╭─────────────┬───────────────────╮ │ 89 B │
│   │ │ id                  │ 55673               │ │ │ name  │ google.com.      │ │                                                                                                 │ │ 0 │ google.com. │ ╭──────┬─────╮ │ ╭──────┬────╮ │ 1min │ ╭─────────┬───────────────────────╮ │ │                │ │ rcode_high  │ 0                 │ │      │
│   │ │                     │ ╭──────┬──────────╮ │ │ │       │ ╭──────┬───────╮ │ │                                                                                                 │ │   │             │ │ name │ SOA │ │ │ name │ IN │ │      │ │ mname   │ ns1.google.com.       │ │ │                │ │ version     │ 0                 │ │      │
│   │ │ message_type        │ │ name │ RESPONSE │ │ │ │ type  │ │ name │ CNAME │ │ │                                                                                                 │ │   │             │ │ code │ 6   │ │ │ code │ 1  │ │      │ │ rname   │ dns-admin.google.com. │ │ │                │ │ dnssec_ok   │ false             │ │      │
│   │ │                     │ │ code │ 1        │ │ │ │       │ │ code │ 5     │ │ │                                                                                                 │ │   │             │ ╰──────┴─────╯ │ ╰──────┴────╯ │      │ │ serial  │ 629673961             │ │ │                │ │ max_payload │ 512 B             │ │      │
│   │ │                     │ ╰──────┴──────────╯ │ │ │       │ ╰──────┴───────╯ │ │                                                                                                 │ │   │             │                │               │      │ │ refresh │ 15min                 │ │ │                │ │ opts        │ {record 0 fields} │ │      │
│   │ │                     │ ╭──────┬───────╮    │ │ │       │ ╭──────┬────╮    │ │                                                                                                 │ │   │             │                │               │      │ │ retry   │ 15min                 │ │ │                │ ╰─────────────┴───────────────────╯ │      │
│   │ │ op_code             │ │ name │ QUERY │    │ │ │ class │ │ name │ IN │    │ │                                                                                                 │ │   │             │                │               │      │ │ expire  │ 30min                 │ │ │                │                                     │      │
│   │ │                     │ │ code │ 0     │    │ │ │       │ │ code │ 1  │    │ │                                                                                                 │ │   │             │                │               │      │ │ minimum │ 1min                  │ │ │                │                                     │      │
│   │ │                     │ ╰──────┴───────╯    │ │ │       │ ╰──────┴────╯    │ │                                                                                                 │ │   │             │                │               │      │ ╰─────────┴───────────────────────╯ │ │                │                                     │      │
│   │ │ authoritative       │ false               │ │ ╰───────┴──────────────────╯ │                                                                                                 │ ╰───┴─────────────┴────────────────┴───────────────┴──────┴─────────────────────────────────────╯ │                │                                     │      │
│   │ │ truncated           │ false               │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ recursion_desired   │ true                │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ recursion_available │ true                │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ authentic_data      │ false               │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │                     │ ╭──────┬──────────╮ │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ response_code       │ │ name │ No Error │ │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │                     │ │ code │ 0        │ │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │                     │ ╰──────┴──────────╯ │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ query_count         │ 1                   │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ answer_count        │ 0                   │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ name_server_count   │ 1                   │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ │ additional_count    │ 1                   │ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
│   │ ╰─────────────────────┴─────────────────────╯ │                              │                                                                                                 │                                                                                                   │                │                                     │      │
╰───┴───────────────────────────────────────────────┴──────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────┴────────────────┴─────────────────────────────────────┴──────╯
```

```
pipe name into command
> 'google.com' | dns query
```

```
pipe lists of names into command
> ['google.com', 'amazon.com'] | dns query
```

```
query record name that has labels with non-renderable bytes
> [ $"ding(char -u '07')-ds", "metric", "gstatic", "com" ] | each { into binary } | collect { $in } | dns query
```

```
pipe table of queries into command (ignores --type flag)
> [{name: 'google.com', type: 'A'}, {name: 'amazon.com', type: 'A'}] | dns query
```

```
choose a different protocol and/or port
> dns query -p tls -n dns.google -s 8.8.8.8 en.wikipedia.org
> dns query -p https -n cloudflare-dns.com -s 1.1.1.1 en.wikipedia.org
> dns query -p quic -n dns.adguard-dns.com -s 94.140.15.15:853 en.wikipedia.org
```

## Configuration

You can specify any of the command line flags in your `config.nu` to make them
permanent. If an option is specified in both the `config.nu` and the CLI, the
CLI takes precedence.

```nu
$env.config.plugins.dns = {
  server: "94.140.15.15"
  protocol: https
  dns-name: dns.adguard-dns.com
  dnssec-mode: strict
  tasks: 16
  timeout: 30sec
}
```

## Install

```nu
cargo install nu_plugin_dns
plugin add $"($env.CARGO_HOME)/bin/nu_plugin_dns"
plugin use dns
```
