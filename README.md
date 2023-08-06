# windows-bench

[![GitHub Release][release-img]][release]
[![License][license-img]][license]
[![GitHub Build Actions][build-action-img]][actions]
[![GitHub Release Actions][release-action-img]][actions]

# This Repo is Still Work in Progress

windows-bench is a Go application that checks whether the windows operating system is configured securely by running the checks documented in the CIS Distribution Independent windows Benchmark.

Tests are configured with YAML files, making this tool easy to update as test specifications evolve.

CIS windows Benchmark support
windows-bench currently supports tests for Windows server 2022 benchmark version 2.0.0 only.

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

```sh
[INFO] 1 Account Policies
[INFO] 1.1 Password Policy
[PASS] 1.1.1 Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)
[PASS] 1.1.2 Ensure 'Maximum password age' is set to '365 or fewer days, but not 0' (Automated)
[PASS] 1.1.3 Ensure 'Minimum password age' is set to '1 or more day(s)' (Automated)
[FAIL] 1.1.4 Ensure 'Minimum password length' is set to '14 or more character(s)' (Automated)
[FAIL] 1.1.5 Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Automated)

== Remediations ==
1.1.4 To establish the recommended configuration via GP, set the following UI path to 14 or more character(s):
    Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Minimum password length

1.1.5 To establish the recommended configuration via GP, set the following UI path to 14 or more character(s):
     Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Password must meet complexity requirements


== Summary ==
3 checks PASS
2 checks FAIL
0 checks WARN
0 checks INFO

```

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


# Run checks with json format

./windows-bench --json

```json

{
  "id": "1",
  "text": "Account Policies",
  "tests": [
    {
      "section": "1.1",
      "desc": "Password Policy",
      "Constraints": null,
      "type": "",
      "results": [
        {
          "test_number": "1.1.1",
          "test_desc": "Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)",
          "SubChecks": null,
          "audit_type": "powershell",
          "audit": {
            "cmd": {
              "DomainController": "Get-ADDefaultDomainPasswordPolicy -Current LocalComputer | Select -ExpandProperty PasswordHistoryCount",
              "Server": "Get-ADDefaultDomainPasswordPolicy -Current LocalComputer | Select -ExpandProperty PasswordHistoryCount"
            }
          },
          "type": "",
          "test_info": [
            "To establish the recommended configuration via GP, set the following UI path to 24 or more password(s):\n  Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account\n  Policies\\Password Policy\\Enforce password history\n"
          ],
          "status": "PASS",
          "actual_value": "24",
          "expected_result": "'' is greater or equal to 24",
          "scored": true,
          "IsMultiple": false
        },
        {
          "test_number": "1.1.2",
          "test_desc": "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0' (Automated)",
          "SubChecks": null,
          "audit_type": "powershell",
          "audit": {
            "cmd": {
              "DomainController": "Get-ADDefaultDomainPasswordPolicy -Current LocalComputer | Select -ExpandProperty MaxPasswordAge | Select -ExpandProperty TotalDays",
              "Server": "Get-ADDefaultDomainPasswordPolicy -Current LocalComputer | Select -ExpandProperty MaxPasswordAge | Select -ExpandProperty TotalDays"
            }
          },
          "type": "",
          "test_info": [
            "To establish the recommended configuration via GP, set the following UI path to 365 or fewer days, but not 0:\n Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Maximum password age\n"
          ],
          "status": "PASS",
          "actual_value": "42",
          "expected_result": "'' is lower or equal to 365 AND '' is not equal to '0'",
          "scored": true,
          "IsMultiple": false
        },
        {
          "test_number": "1.1.3",
          "test_desc": "Ensure 'Minimum password age' is set to '1 or more day(s)' (Automated)",
          "SubChecks": null,
          "audit_type": "powershell",
          "audit": {
            "cmd": {
              "DomainController": "Get-ADDefaultDomainPasswordPolicy -Current LocalComputer | Select -ExpandProperty MinPasswordAge | Select -ExpandProperty TotalDays",
              "Server": "Get-ADDefaultDomainPasswordPolicy -Current LocalComputer | Select -ExpandProperty MinPasswordAge | Select -ExpandProperty TotalDays"
            }
          },
          "type": "",
          "test_info": [
            "To establish the recommended configuration via GP, set the following UI path to 1 or more day(s):\n   Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Minimum password age\n"
          ],
          "status": "PASS",
          "actual_value": "1",
          "expected_result": "'' is greater or equal to 1",
          "scored": true,
          "IsMultiple": false
        },
        {
          "test_number": "1.1.4",
          "test_desc": "Ensure 'Minimum password length' is set to '14 or more character(s)' (Automated)",
          "SubChecks": null,
          "audit_type": "powershell",
          "audit": {
            "cmd": {
              "DomainController": "Get-ADDefaultDomainPasswordPolicy -Current LocalComputer | Select -ExpandProperty MinPasswordLength",
              "Server": "Get-ADDefaultDomainPasswordPolicy -Current LocalComputer | Select -ExpandProperty MinPasswordLength"
            }
          },
          "type": "",
          "test_info": [
            "To establish the recommended configuration via GP, set the following UI path to 14 or more character(s):\n    Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Minimum password length\n"
          ],
          "status": "FAIL",
          "actual_value": "7",
          "expected_result": "'' is greater or equal to 14",
          "scored": true,
          "IsMultiple": false
        },
        {
          "test_number": "1.1.5",
          "test_desc": "Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Automated)",
          "SubChecks": null,
          "audit_type": "powershell",
          "audit": {
            "cmd": {
              "DomainController": "Get-ADDefaultDomainPasswordPolicy -Current LocalComputer | Select -ExpandProperty ComplexityEnabled",
              "Server": "Get-ADDefaultDomainPasswordPolicy -Current LocalComputer | Select -ExpandProperty ComplexityEnabled"
            }
          },
          "type": "",
          "test_info": [
            "To establish the recommended configuration via GP, set the following UI path to 14 or more character(s):\n     Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Password must meet complexity requirements\n"
          ],
          "status": "PASS",
          "actual_value": "True",
          "expected_result": "'' has 'True'",
          "scored": true,
          "IsMultiple": false
        }
      ],
      "pass": 4,
      "fail": 1,
      "warn": 0,
      "info": 0
    }
  ],
  "total_pass": 4,
  "total_fail": 1,
  "total_warn": 0,
  "total_info": 0
}
```