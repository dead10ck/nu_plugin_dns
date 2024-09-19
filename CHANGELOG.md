# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
