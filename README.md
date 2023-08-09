# `nu_plugin_dns`

[Nushell](http://www.nushell.sh/) plugin that does DNS queries. Intended to be
a native replacement for [`dig`](https://en.m.wikipedia.org/wiki/Dig_(command)).
Uses the excellent [`trust-dns`](https://github.com/bluejekyll/trust-dns)
crates.

## Usage

```
simple query for A / AAAA records
> dns query google.com

╭────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│            │ ╭──────────┬────────────╮                                                                                                                                                   │
│ nameserver │ │ address  │ 8.8.8.8:53 │                                                                                                                                                   │
│            │ │ protocol │ udp        │                                                                                                                                                   │
│            │ ╰──────────┴────────────╯                                                                                                                                                   │
│            │ ╭───┬───────────────────────────────────┬─────────────────────────┬─────────────────────────────────────────────────────────────────────┬────────────────┬────────────────╮ │
│ messages   │ │ # │              header               │        question         │                               answer                                │   authority    │   additional   │ │
│            │ ├───┼───────────────────────────────────┼─────────────────────────┼─────────────────────────────────────────────────────────────────────┼────────────────┼────────────────┤ │
│            │ │ 0 │ ╭────────────────────┬──────────╮ │ ╭───────┬─────────────╮ │ ╭───┬─────────────┬──────┬───────┬─────┬──────────────────────────╮ │ [list 0 items] │ [list 0 items] │ │
│            │ │   │ │ id                 │ 64411    │ │ │ name  │ google.com. │ │ │ # │    name     │ type │ class │ ttl │          rdata           │ │                │                │ │
│            │ │   │ │ message_type       │ RESPONSE │ │ │ type  │ AAAA        │ │ ├───┼─────────────┼──────┼───────┼─────┼──────────────────────────┤ │                │                │ │
│            │ │   │ │ op_code            │ QUERY    │ │ │ class │ IN          │ │ │ 0 │ google.com. │ AAAA │ IN    │ 182 │ 2607:f8b0:4006:821::200e │ │                │                │ │
│            │ │   │ │ authoritative      │ false    │ │ ╰───────┴─────────────╯ │ ╰───┴─────────────┴──────┴───────┴─────┴──────────────────────────╯ │                │                │ │
│            │ │   │ │ truncated          │ false    │ │                         │                                                                     │                │                │ │
│            │ │   │ │ recusion_desired   │ true     │ │                         │                                                                     │                │                │ │
│            │ │   │ │ recusion_available │ true     │ │                         │                                                                     │                │                │ │
│            │ │   │ │ authentic_data     │ false    │ │                         │                                                                     │                │                │ │
│            │ │   │ │ response_code      │ No Error │ │                         │                                                                     │                │                │ │
│            │ │   │ │ query_count        │ 1        │ │                         │                                                                     │                │                │ │
│            │ │   │ │ answer_count       │ 1        │ │                         │                                                                     │                │                │ │
│            │ │   │ │ name_server_count  │ 0        │ │                         │                                                                     │                │                │ │
│            │ │   │ │ additional_count   │ 1        │ │                         │                                                                     │                │                │ │
│            │ │   │ ╰────────────────────┴──────────╯ │                         │                                                                     │                │                │ │
│            │ │ 1 │ ╭────────────────────┬──────────╮ │ ╭───────┬─────────────╮ │ ╭───┬─────────────┬──────┬───────┬─────┬────────────────╮           │ [list 0 items] │ [list 0 items] │ │
│            │ │   │ │ id                 │ 4666     │ │ │ name  │ google.com. │ │ │ # │    name     │ type │ class │ ttl │     rdata      │           │                │                │ │
│            │ │   │ │ message_type       │ RESPONSE │ │ │ type  │ A           │ │ ├───┼─────────────┼──────┼───────┼─────┼────────────────┤           │                │                │ │
│            │ │   │ │ op_code            │ QUERY    │ │ │ class │ IN          │ │ │ 0 │ google.com. │ A    │ IN    │ 300 │ 142.251.40.174 │           │                │                │ │
│            │ │   │ │ authoritative      │ false    │ │ ╰───────┴─────────────╯ │ ╰───┴─────────────┴──────┴───────┴─────┴────────────────╯           │                │                │ │
│            │ │   │ │ truncated          │ false    │ │                         │                                                                     │                │                │ │
│            │ │   │ │ recusion_desired   │ true     │ │                         │                                                                     │                │                │ │
│            │ │   │ │ recusion_available │ true     │ │                         │                                                                     │                │                │ │
│            │ │   │ │ authentic_data     │ false    │ │                         │                                                                     │                │                │ │
│            │ │   │ │ response_code      │ No Error │ │                         │                                                                     │                │                │ │
│            │ │   │ │ query_count        │ 1        │ │                         │                                                                     │                │                │ │
│            │ │   │ │ answer_count       │ 1        │ │                         │                                                                     │                │                │ │
│            │ │   │ │ name_server_count  │ 0        │ │                         │                                                                     │                │                │ │
│            │ │   │ │ additional_count   │ 1        │ │                         │                                                                     │                │                │ │
│            │ │   │ ╰────────────────────┴──────────╯ │                         │                                                                     │                │                │ │
│            │ ╰───┴───────────────────────────────────┴─────────────────────────┴─────────────────────────────────────────────────────────────────────┴────────────────┴────────────────╯ │
╰────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

specify query type
> dns query --type CNAME google.com

╭────────────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│            │ ╭──────────┬────────────╮                                                                                                                                                                                          │
│ nameserver │ │ address  │ 8.8.8.8:53 │                                                                                                                                                                                          │
│            │ │ protocol │ udp        │                                                                                                                                                                                          │
│            │ ╰──────────┴────────────╯                                                                                                                                                                                          │
│            │ ╭───┬───────────────────────────────────┬─────────────────────────┬────────────────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────────╮ │
│ messages   │ │ # │              header               │        question         │     answer     │                                                 authority                                                  │   additional   │ │
│            │ ├───┼───────────────────────────────────┼─────────────────────────┼────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────┤ │
│            │ │ 0 │ ╭────────────────────┬──────────╮ │ ╭───────┬─────────────╮ │ [list 0 items] │ ╭───┬─────────────┬──────┬───────┬─────┬─────────────────────────────────────────────────────────────────╮ │ [list 0 items] │ │
│            │ │   │ │ id                 │ 8309     │ │ │ name  │ google.com. │ │                │ │ # │    name     │ type │ class │ ttl │                              rdata                              │ │                │ │
│            │ │   │ │ message_type       │ RESPONSE │ │ │ type  │ CNAME       │ │                │ ├───┼─────────────┼──────┼───────┼─────┼─────────────────────────────────────────────────────────────────┤ │                │ │
│            │ │   │ │ op_code            │ QUERY    │ │ │ class │ IN          │ │                │ │ 0 │ google.com. │ SOA  │ IN    │  60 │ ns1.google.com. dns-admin.google.com. 554462945 900 900 1800 60 │ │                │ │
│            │ │   │ │ authoritative      │ false    │ │ ╰───────┴─────────────╯ │                │ ╰───┴─────────────┴──────┴───────┴─────┴─────────────────────────────────────────────────────────────────╯ │                │ │
│            │ │   │ │ truncated          │ false    │ │                         │                │                                                                                                            │                │ │
│            │ │   │ │ recusion_desired   │ true     │ │                         │                │                                                                                                            │                │ │
│            │ │   │ │ recusion_available │ true     │ │                         │                │                                                                                                            │                │ │
│            │ │   │ │ authentic_data     │ false    │ │                         │                │                                                                                                            │                │ │
│            │ │   │ │ response_code      │ No Error │ │                         │                │                                                                                                            │                │ │
│            │ │   │ │ query_count        │ 1        │ │                         │                │                                                                                                            │                │ │
│            │ │   │ │ answer_count       │ 0        │ │                         │                │                                                                                                            │                │ │
│            │ │   │ │ name_server_count  │ 1        │ │                         │                │                                                                                                            │                │ │
│            │ │   │ │ additional_count   │ 1        │ │                         │                │                                                                                                            │                │ │
│            │ │   │ ╰────────────────────┴──────────╯ │                         │                │                                                                                                            │                │ │
│            │ ╰───┴───────────────────────────────────┴─────────────────────────┴────────────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────────╯ │
╰────────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

specify query types by numeric ID, and get numeric IDs in output
> dns query --type [5, 15] -c google.com

╭────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│            │ ╭──────────┬────────────╮                                                                                                                                                                                                                                                                                             │
│ nameserver │ │ address  │ 8.8.8.8:53 │                                                                                                                                                                                                                                                                                             │
│            │ │ protocol │ udp        │                                                                                                                                                                                                                                                                                             │
│            │ ╰──────────┴────────────╯                                                                                                                                                                                                                                                                                             │
│            │ ╭───┬──────────────────────────────────────────────┬──────────────────────────────┬─────────────────────────────────────────────────────────────────────────────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────────╮ │
│ messages   │ │ # │                    header                    │           question           │                                     answer                                      │                                                          authority                                                           │   additional   │ │
│            │ ├───┼──────────────────────────────────────────────┼──────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────┤ │
│            │ │ 0 │ ╭────────────────────┬─────────────────────╮ │ ╭───────┬──────────────────╮ │ [list 0 items]                                                                  │ ╭───┬─────────────┬────────────────┬───────────────┬─────┬─────────────────────────────────────────────────────────────────╮ │ [list 0 items] │ │
│            │ │   │ │ id                 │ 23997               │ │ │ name  │ google.com.      │ │                                                                                 │ │ # │    name     │      type      │     class     │ ttl │                              rdata                              │ │                │ │
│            │ │   │ │                    │ ╭──────┬──────────╮ │ │ │       │ ╭──────┬───────╮ │ │                                                                                 │ ├───┼─────────────┼────────────────┼───────────────┼─────┼─────────────────────────────────────────────────────────────────┤ │                │ │
│            │ │   │ │ message_type       │ │ name │ RESPONSE │ │ │ │ type  │ │ name │ CNAME │ │ │                                                                                 │ │ 0 │ google.com. │ ╭──────┬─────╮ │ ╭──────┬────╮ │  60 │ ns1.google.com. dns-admin.google.com. 554462945 900 900 1800 60 │ │                │ │
│            │ │   │ │                    │ │ code │ 1        │ │ │ │       │ │ code │ 5     │ │ │                                                                                 │ │   │             │ │ name │ SOA │ │ │ name │ IN │ │     │                                                                 │ │                │ │
│            │ │   │ │                    │ ╰──────┴──────────╯ │ │ │       │ ╰──────┴───────╯ │ │                                                                                 │ │   │             │ │ code │ 6   │ │ │ code │ 1  │ │     │                                                                 │ │                │ │
│            │ │   │ │                    │ ╭──────┬───────╮    │ │ │       │ ╭──────┬────╮    │ │                                                                                 │ │   │             │ ╰──────┴─────╯ │ ╰──────┴────╯ │     │                                                                 │ │                │ │
│            │ │   │ │ op_code            │ │ name │ QUERY │    │ │ │ class │ │ name │ IN │    │ │                                                                                 │ ╰───┴─────────────┴────────────────┴───────────────┴─────┴─────────────────────────────────────────────────────────────────╯ │                │ │
│            │ │   │ │                    │ │ code │ 0     │    │ │ │       │ │ code │ 1  │    │ │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │                    │ ╰──────┴───────╯    │ │ │       │ ╰──────┴────╯    │ │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ authoritative      │ false               │ │ ╰───────┴──────────────────╯ │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ truncated          │ false               │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ recusion_desired   │ true                │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ recusion_available │ true                │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ authentic_data     │ false               │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │                    │ ╭──────┬──────────╮ │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ response_code      │ │ name │ No Error │ │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │                    │ │ code │ 0        │ │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │                    │ ╰──────┴──────────╯ │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ query_count        │ 1                   │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ answer_count       │ 0                   │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ name_server_count  │ 1                   │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ additional_count   │ 1                   │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ ╰────────────────────┴─────────────────────╯ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │ 1 │ ╭────────────────────┬─────────────────────╮ │ ╭───────┬───────────────╮    │ ╭───┬─────────────┬───────────────┬───────────────┬─────┬─────────────────────╮ │ [list 0 items]                                                                                                               │ [list 0 items] │ │
│            │ │   │ │ id                 │ 13733               │ │ │ name  │ google.com.   │    │ │ # │    name     │     type      │     class     │ ttl │        rdata        │ │                                                                                                                              │                │ │
│            │ │   │ │                    │ ╭──────┬──────────╮ │ │ │       │ ╭──────┬────╮ │    │ ├───┼─────────────┼───────────────┼───────────────┼─────┼─────────────────────┤ │                                                                                                                              │                │ │
│            │ │   │ │ message_type       │ │ name │ RESPONSE │ │ │ │ type  │ │ name │ MX │ │    │ │ 0 │ google.com. │ ╭──────┬────╮ │ ╭──────┬────╮ │ 213 │ 10 smtp.google.com. │ │                                                                                                                              │                │ │
│            │ │   │ │                    │ │ code │ 1        │ │ │ │       │ │ code │ 15 │ │    │ │   │             │ │ name │ MX │ │ │ name │ IN │ │     │                     │ │                                                                                                                              │                │ │
│            │ │   │ │                    │ ╰──────┴──────────╯ │ │ │       │ ╰──────┴────╯ │    │ │   │             │ │ code │ 15 │ │ │ code │ 1  │ │     │                     │ │                                                                                                                              │                │ │
│            │ │   │ │                    │ ╭──────┬───────╮    │ │ │       │ ╭──────┬────╮ │    │ │   │             │ ╰──────┴────╯ │ ╰──────┴────╯ │     │                     │ │                                                                                                                              │                │ │
│            │ │   │ │ op_code            │ │ name │ QUERY │    │ │ │ class │ │ name │ IN │ │    │ ╰───┴─────────────┴───────────────┴───────────────┴─────┴─────────────────────╯ │                                                                                                                              │                │ │
│            │ │   │ │                    │ │ code │ 0     │    │ │ │       │ │ code │ 1  │ │    │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │                    │ ╰──────┴───────╯    │ │ │       │ ╰──────┴────╯ │    │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ authoritative      │ false               │ │ ╰───────┴───────────────╯    │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ truncated          │ false               │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ recusion_desired   │ true                │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ recusion_available │ true                │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ authentic_data     │ false               │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │                    │ ╭──────┬──────────╮ │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ response_code      │ │ name │ No Error │ │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │                    │ │ code │ 0        │ │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │                    │ ╰──────┴──────────╯ │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ query_count        │ 1                   │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ answer_count       │ 1                   │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ name_server_count  │ 0                   │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ │ additional_count   │ 1                   │ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ │   │ ╰────────────────────┴─────────────────────╯ │                              │                                                                                 │                                                                                                                              │                │ │
│            │ ╰───┴──────────────────────────────────────────────┴──────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────────╯ │
╰────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

pipe name into command
> 'google.com' | dns query

pipe lists of names into command
> ['google.com', 'amazon.com'] | dns query

pipe table of queries into command (ignores --type flag)
> [{name: 'google.com', type: 'A'}, {name: 'amazon.com', type: 'A'}] | dns query
```

## Install

`cargo install nu_plugin_dns`
