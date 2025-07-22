# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.0.3] - 2025-07-22

* Upgrade dependencies

## [4.0.2] - 2025-06-11

* Upgrade nushell to 0.105.1 + other deps

## [4.0.1] - 2025-04-24

* Upgrade nushell to 0.104.0 + other deps

## [4.0.0] - 2025-04-24

### Changed

#### **BREAKING** Upgrade hickory to 0.25.1
[hickory 0.25](https://github.com/hickory-dns/hickory-dns/releases/tag/v0.25.0)
introduced massive breaking changes. The output of this plugin was updated to
reflect those changes.

* Many breaking changes were made to the data structures of the crate, so
  without listing all the details, the record types which have changes
  in their structure are:

  * `CDNSKEY`
  * `CDS`
  * `DNSKEY`
  * `DS`
  * `KEY`
  * `TLSA`

  The `edns` record had its `dnssec_ok` column moved into a nested `flags`
  record.
* The DNSSEC mode of `strict` has been removed, since hickory now does negative
  validation. Now in the default mode of `--dnssec opportunistic`, if a record
  has no DNSSEC signatures, this is cryptographically validated from upstream
  resolvers, and an error is returned if this validation fails.
* A new column `proof` has been added to the `answer` table which represents the
  record's DNSSEC proof status. See
  [here](https://docs.rs/hickory-proto/0.25.1/hickory_proto/dnssec/proof/enum.Proof.html)
  for details.

### Other
* Upgrade nushell crates to 0.103.0

## [3.0.7] - 2025-02-14

* Upgrade nushell crates to 0.102.0

## [3.0.6] - 2024-12-08

* Upgrade nushell crates to 0.100.0

## [3.0.5] - 2024-10-17

* Upgrade nushell crates to 0.99

## [3.0.4] - 2024-09-19

* Upgrade nushell crates to 0.98

## [3.0.3] - 2024-08-28

* Upgrade nushell crates to 0.97.1

## [3.0.2] - 2024-07-28

* Upgrade nushell crates to 0.96

## [3.0.0] - 2024-05-05

This release fixes compatibility with Nushell 0.93, which introduced major
breaking changes to the plugin API, including the ability to stream output
results. Accordingly, some breaking changes to this plugin's output format
accompanies these fixes.


### Fixes

* Compatibility with Nushell 0.93

### Added

* Output is now streamed, so `dns query` can now be used in the middle of a
  pipeline and is able to remain resource efficient.
* To accompany the above, queries are done concurrently, though output is
  returned in the same order queries are given. The level of concurrency can be
  tuned with the new `--tasks` flag. (Please exercise caution. Don't DOS your
  nameserver!)
* A new CLI flag `--timeout` is added that allows controlling how long to wait
  before timing out a request
* CLI flags can now be given through the plug-in configuration in the main
  `config.nu`. See the README for an example.

### Changed

* The output format was a record that included at the top level a field for
  the nameserver which was queried and one for the messages in the response.
  This top level record is now omitted. The output is a table of the response
  messages. The output is now equivalent to if one had done `dns query | get
  messages` before. If you wish to confirm which nameserver you are querying,
  you can set the `RUST_LOG` environment variable to `info`.

## [2.0.0] - 2024-03-12

* Fix typo: `recusion_desired` was fixed to `recursion_desired`. This is
  technically a **breaking change** if you use this in any scripts.
* Upgrade nu to 0.91.0

## [1.0.5] - 2024-02-08

* Upgrade dependencies. Fixes breakage in nu 0.90.1

## [1.0.4] - 2024-01-29

* Upgrade dependencies

## [1.0.3] - 2023-10-21

* `trust-dns` has been rebranded as `hickory`. Change all the crates and upgrade
  to 0.24

## [1.0.2] - 2023-10-20

* Upgrade dependencies

## [1.0.1] - 2023-10-19

* Upgrade to nu 0.86.0
* Upgrade all other dependencies
* Added logging. You can see logs by setting the `RUST_LOG` environment variable
