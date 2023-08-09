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
	ver                = "2.0.0"
	testDefinitionFile = "definitions.yaml"
	path               string
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

// Tests all standard windows-bench definition files
func TestGetDefinitionFilePath(t *testing.T) {
	d, err := os.Open(cfgDir)
	if err != nil {
		t.Errorf("unexpected error: %s\n", err)
	}

	vers, err := d.Readdirnames(-1)
	if err != nil {
		t.Errorf("unexpected error: %s\n", err)
	}

	for _, ver := range vers {

		verDir := fmt.Sprintf("%s/%s", cfgDir, ver)
		cfvd, err := os.Open(verDir)
		if err != nil {
			t.Errorf("unexpected error: %s\n", err)
		}
		files, err := cfvd.Readdirnames(-1)
		if err != nil {
			t.Errorf("unexpected error: %s\n", err)
		}

		for _, file := range files {
			_, err := getDefinitionFilePath(ver, file)
			if err != nil {
				t.Errorf("unexpected error: %s\n", err)
			}
		}

	}
}

func TestGetControls(t *testing.T) {
	var err error
	path, err = getDefinitionFilePath(ver, testDefinitionFile)
	if err != nil {
		t.Errorf("unexpected error: %s\n", err)
	}

	b := getMockBench()
	_, err = getControls(b, path, nil)
	if err != nil {
		t.Errorf("unexpected error: %s\n", err)
	}
}

func TestRunControls(t *testing.T) {
	b := getMockBench()
	path, err := loadConfig("2.0.0")
	assert.NoError(t, err)
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
