# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
