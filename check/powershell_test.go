// Copyright © 2019 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package check

import (
	"fmt"
	"log"
	"testing"

	"github.com/aquasecurity/bench-common/check"
	ps "github.com/aquasecurity/go-powershell"
)

type mockShellStarter struct {
	fail        bool
	expectedErr error
}

var errorStartShell = fmt.Errorf("Failed to start shell")
var errorGetOSTypeCommand = fmt.Errorf("Failed to execute get OS Type command")
var errorExecuteCommand = fmt.Errorf("Failed to execute command")

const osTypeCmd = "domain-controller"
const testPShellCommand = "domain-controller CMD"
const testSpace = " "
const testNewLine = "\n"
const testWinNewLine = "\r\n"

type mockShell struct {
	getOSTypeFail   bool
	execCommandFail bool
}

func (ms *mockShell) Execute(cmd string) (string, string, error) {
	log.Printf("Execute.cmd %s\n", cmd)

	switch cmd {
	case osTypeCmd:
		if ms.getOSTypeFail {
			return "", "", errorGetOSTypeCommand
		}
		return cmd, "", nil
	case testPShellCommand:
		if ms.execCommandFail {
			return "", "", errorExecuteCommand
		}
		return cmd, "", nil
	}

	return cmd, "", nil
}
func (ms *mockShell) Exit() {}

func (m *mockShellStarter) startShell() (ps.Shell, error) {
	if m.fail {
		return nil, m.expectedErr
	}
	return &mockShell{}, nil
}

func TestConstructShell(t *testing.T) {
	type TestCase struct {
		mss *mockShellStarter
	}

	testCases := []TestCase{
		{mss: &mockShellStarter{
			fail: false,
		}},
		{mss: &mockShellStarter{
			fail:        true,
			expectedErr: errorStartShell,
		}},
	}

	for _, testCase := range testCases {
		ps, err := constructShell(testCase.mss)
		if testCase.mss.fail {
			if err == nil {
				t.Errorf("Expected Error")
			}
		} else if ps == nil {
			t.Errorf("PowerShell must be initialized")
		} else if ps.sh == nil {
			t.Errorf("Internal Shell must be initialized")
		}
	}
}

func TestExecute(t *testing.T) {
	type TestCase struct {
		ps             *PowerShell
		expectedResult string
		fail           bool
		expectedErr    string
	}

	testCases := []TestCase{
		{
			ps: &PowerShell{
				Cmd: map[string]string{
					osTypeCmd: testPShellCommand,
				},
				sh: &mockShell{
					getOSTypeFail: true,
				},
				osTypePowershellCommand: osTypeCmd,
			},
			fail:        true,
			expectedErr: `stderr: "" err: Failed to get operating system type: Failed to execute get OS Type command`,
		},
		{
			ps: &PowerShell{
				Cmd: map[string]string{
					osTypeCmd: testPShellCommand,
				},
				sh: &mockShell{
					execCommandFail: true,
				},
				osTypePowershellCommand: osTypeCmd,
			},
			fail:        true,
			expectedErr: `stderr: "Failed to execute command" err: Failed to execute command`,
		},
		{
			ps: &PowerShell{
				Cmd: map[string]string{
					osTypeCmd: testPShellCommand,
				},
				sh:                      &mockShell{},
				osTypePowershellCommand: "missing os command",
			},
			fail:        true,
			expectedErr: `stderr: "" err: Unable to find matching command for OS Type: "missing os command"`,
		},
		{
			ps: &PowerShell{
				Cmd: map[string]string{
					osTypeCmd: testSpace + testPShellCommand + testSpace, // surrounded by spaces
				},
				sh:                      &mockShell{},
				osTypePowershellCommand: osTypeCmd,
			},
			expectedResult: testPShellCommand,
			fail:           false,
		},
		{
			ps: &PowerShell{
				Cmd: map[string]string{
					osTypeCmd: testSpace + testPShellCommand + testNewLine, // starts with space end with new lines
				},
				sh:                      &mockShell{},
				osTypePowershellCommand: osTypeCmd,
			},
			expectedResult: testPShellCommand,
			fail:           false,
		},
	}

	for _, testCase := range testCases {
		result, em, st := testCase.ps.Execute()
		fmt.Printf("result: %q em:%s st:%q lr:%d\n", result, em, st, len(result))
		if testCase.fail {
			if st != check.FAIL {
				t.Errorf("Expected FAIL state but instead got %q", st)
			} else if testCase.expectedErr != em {
				t.Errorf("unexpected error: %q but instead got: %s", testCase.expectedErr, em)
			}
		} else if len(result) == 0 {
			t.Errorf("Expected result but instead got empty value")
		} else if testCase.expectedResult != result {
			t.Errorf("Expected result: %q but instead got: %q", testCase.expectedResult, result)
		}
	}
}
