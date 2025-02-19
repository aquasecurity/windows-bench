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

package cmd

import (
	"fmt"
	"os"
	"testing"

	commonCheck "github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/windows-bench/shell"
	"github.com/stretchr/testify/assert"
)

var (
	testDefinitionFile = "CIS_Microsoft_Windows_Server_2019_Stand-alone_v2.0.0.yaml"
)

type mockPowerShell struct{}

func (p mockPowerShell) Execute(customConfig ...interface{}) (result string, errMessage string, state commonCheck.State) {
	return "pass", "pass", commonCheck.PASS
}

func init() {
	here, _ := os.Getwd()
	// cfgDir is defined in root.go
	cfgDir = fmt.Sprintf("%s/../cfg", here)
}

func TestGetControls(t *testing.T) {
	var err error
	path := fmt.Sprintf("%s/%s", cfgDir, testDefinitionFile)
	b := getMockBench()
	_, err = getControls(b, path, nil)
	if err != nil {
		t.Errorf("unexpected error: %s\n", err)
	}
}

func TestRunControls(t *testing.T) {
	b := getMockBench()
	path := fmt.Sprintf("%s/%s", cfgDir, testDefinitionFile)
	control, err := getControls(b, path, nil)
	if err != nil {
		t.Errorf("unexpected error: %s\n", err)
	}

	// Run all checks
	sm := runControls(control, "")
	assert.True(t, sm.Pass > 0)
	// Run only specified checks
	checkList := "1.1.1"
	smt := runControls(control, checkList)
	assert.True(t, smt.Pass == 1)
}

func getMockBench() commonCheck.Bench {
	b := commonCheck.NewBench()
	ps := &mockPowerShell{}
	_ = b.RegisterAuditType(shell.TypePowershell, func() interface{} {
		return ps
	})
	return b
}
