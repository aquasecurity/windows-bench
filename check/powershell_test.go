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
	"io"
	"testing"

	"github.com/aquasecurity/go-powershell/backend"
)

type mockShell struct {
	fail         bool
	expectedGood string
	expectedErr  string
}

func (s mockShell) Execute(cmd string) (string, string, error) {
	if s.fail {
		return "", "errorMessage", fmt.Errorf("actualError")
	}
	return "good", "", nil
}

func (s mockShell) Exit() {}

func TestExecute(t *testing.T) {
	type TestCase struct {
		ps          PowerShell
		expectedErr string
		fail        bool
	}

	testCases := []TestCase{
		{
			ps: PowerShell{
				Cmd: "",
				sh: mockShell{
					fail: true,
				},
			},
			expectedErr: `stderr: "errorMessage" err: actualError`,
			fail:        true,
		},
		{
			ps: PowerShell{
				Cmd: "",
				sh: mockShell{
					fail: false,
				},
			},
			fail: false,
		},
	}

	for _, testCase := range testCases {
		_, em, _ := testCase.ps.Execute()
		if testCase.fail && len(em) == 0 {
			t.Errorf("expected err")
		}

		if testCase.fail && em != testCase.expectedErr {
			t.Errorf("error message should be populated correctly")
		}
	}
}

type mockStarter struct {
	fail        bool
	expectedErr error
}

var errFailedToStartPowerShell = fmt.Errorf("failed to start powershell")

func (m *mockStarter) StartProcess(cmd string, args ...string) (backend.Waiter, io.Writer, io.Reader, io.Reader, error) {
	if m.fail {
		return nil, nil, nil, nil, errFailedToStartPowerShell
	}
	return nil, nil, nil, nil, nil
}
func TestAcquireShell(t *testing.T) {
	type TestCase struct {
		ms *mockStarter
	}

	testCases := []TestCase{
		{ms: &mockStarter{
			fail: false,
		}},
		{ms: &mockStarter{
			fail:        true,
			expectedErr: errFailedToStartPowerShell,
		}},
	}

	for _, testCase := range testCases {
		_, err := acquireShell(testCase.ms)
		if testCase.ms.expectedErr != nil && (err != testCase.ms.expectedErr || err != errFailedToStartPowerShell) {
			t.Errorf("expected: %q and got: %q", testCase.ms.expectedErr, err)
		}
	}

}
