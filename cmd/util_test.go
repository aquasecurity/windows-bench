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
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	type TestCase struct {
		cisVersion    string
		serverType    string
		serverVersion string
		want          string
	}

	testCases := []TestCase{
		{
			cisVersion:    "2.0.0",
			serverType:    "Server",
			serverVersion: "2019",
			want:          "CIS_Microsoft_Windows_Server_2019_Stand-alone_v2.0.0.yaml",
		},
		{
			cisVersion:    "2.0.0",
			serverType:    "MemberServer",
			serverVersion: "2019",
			want:          "CIS_Microsoft_Windows_Server_2022_Benchmark_v2.0.0.yaml",
		},
		{
			cisVersion:    "2.0.0",
			serverType:    "DomainController",
			serverVersion: "2019",
			want:          "CIS_Microsoft_Windows_Server_2022_Benchmark_v2.0.0.yaml",
		},
		{
			cisVersion:    "2.0.0",
			serverType:    "DomainController",
			serverVersion: "2022",
			want:          "CIS_Microsoft_Windows_Server_2022_Benchmark_v2.0.0.yaml",
		},
		{
			cisVersion:    "2.0.0",
			serverType:    "Server",
			serverVersion: "2022",
			want:          "",
		},
		{
			cisVersion:    "x.y.z",
			serverType:    "whois",
			serverVersion: "bad",
			want:          "",
		},
	}
	for _, tc := range testCases {
		out, _ := loadConfig(tc.cisVersion, tc.serverVersion, tc.serverType)
		assert.Contains(t, out, tc.want)
	}
}

func TestRunChecks(t *testing.T) {
	b := getMockBench()
	err := runChecks(b, "Server", "Microsoft Windows Server 2019")
	var write bytes.Buffer
	outputWriter = &write
	if err != nil {
		t.Errorf("unexpected error: %s\n", err)
	}
	assert.NoError(t, err)
}

func TestUpdateControl(t *testing.T) {
	audit := `{
"cmd":{"DomainController":"Get-ItemPropertyValue 'HKLM:SOFTWAREMicrosoftWindowsCurrentVersionPoliciesExplorer' AllowOnlineTips",
"Server":"Get-ItemPropertyValue'HKLM:SOFTWAREMicrosoftWindowsCurrentVersionPoliciesExplorer' AllowOnlineTips"
}}`
	var aud interface{}
	err := json.Unmarshal([]byte(audit), &aud)
	assert.NoError(t, err)
	got := getOsTypeAuditCommand(aud, "DomainController")
	assert.Equal(t, "Get-ItemPropertyValue 'HKLM:SOFTWAREMicrosoftWindowsCurrentVersionPoliciesExplorer' AllowOnlineTips", got)

}
