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

	"github.com/aquasecurity/bench-common/check"
	ps "github.com/aquasecurity/go-powershell"
	"github.com/aquasecurity/go-powershell/backend"
)

const TypePowershell = "powershell"

type PowerShell string

// Execute - Implements the 'check.Auditer' interface
// It uses the aquasecurity/go-powershell package to interface with
// the windows powershell to execute the command.
func (p *PowerShell) Execute(customConfig ...interface{}) (result string, errMessage string, state check.State) {

	// choose a backend
	back := &backend.Local{}

	// start a local powershell process
	shell, err := ps.New(back)
	if err != nil {
		return "", err.Error(), check.FAIL
	}
	defer shell.Exit()

	stdout, stderr, err := shell.Execute(string(*p))
	errMessage = stderr
	if err != nil {
		errMessage = fmt.Sprintf("stderr: %q err: %v", stderr, err)
		return stdout, errMessage, check.FAIL
	}

	return stdout, stderr, check.PASS
}
