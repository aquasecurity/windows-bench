# windows-bench
[![GitHub Release][release-img]][release]
[![License][license-img]][license]
[![GitHub Build Actions][build-action-img]][actions]
[![GitHub Release Actions][release-action-img]][actions]

windows-bench is a Go application that checks whether the windows operating system is configured securely by running the checks documented in the CIS Distribution Independent windows Benchmark.

Tests are configured with YAML files, making this tool easy to update as test specifications evolve.

CIS windows Benchmark support
windows-bench currently supports tests for benchmark version 1.1.0 only.

windows-bench will determine the test set to run on the host machine based on the following:

Operating system platform - windows server 2022

Install Go, then clone this repository and run as follows (assuming your $GOPATH is set):

go get github.com/aquasecurity/windows-bench
cd $GOPATH/src/github.com/aquasecurity/windows-bench
GOOS=windows GOARCH=386 go build -o bin/windows-bench.exe main.go

# See all supported options

./windows-bench --help

# Run checks

./windows-bench

# Run checks for specified windows cis version

./windows-bench --version <version>
Tests
Tests are specified in definition files cfg/<version>/definitions.yaml.

Where <version> is the version of windows cis for which the test applies.


[actions]: https://github.com/aquasecurity/windows-bench/actions
[build-action-img]: https://github.com/aquasecurity/windows-bench/workflows/build/badge.svg
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[license]: https://opensource.org/licenses/Apache-2.0
[release-img]: https://img.shields.io/github/release/aquasecurity/windows-bench.svg
[release]: https://github.com/aquasecurity/windows-bench/releases
[release-action-img]: https://github.com/aquasecurity/windows-bench/workflows/release/badge.svg
