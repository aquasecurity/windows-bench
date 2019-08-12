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
	"github.com/golang/glog"
)

const TypePowershell = "powershell"

type PowerShell struct {
	Cmd string
	sh  ps.Shell
}

func NewPowerShell() (*PowerShell, error) {
	sh, err := composeShell()
	if err != nil {
		return nil, err
	}
	return &PowerShell{
		Cmd: "",
		sh:  sh,
	}, nil
}

// Execute - Implements the 'check.Auditer' interface
// It uses the aquasecurity/go-powershell package to interface with
// the windows powershell to execute the command.
func (p PowerShell) Execute(customConfig ...interface{}) (result string, errMessage string, state check.State) {

	if p.sh == nil {
		errMessage = fmt.Sprintf("PowerShell is not initialized!\n")
		return "", errMessage, check.FAIL
	}

	stdout, stderr, err := p.sh.Execute(p.Cmd)
	errMessage = stderr
	if err != nil {
		errMessage = fmt.Sprintf("stderr: %q err: %v", stderr, err)
		return stdout, errMessage, check.FAIL
	}

	glog.V(2).Info(fmt.Sprintf("Powershell.Execute - stdout: %s \nstderr:%q \n", stdout, stderr))
	return stdout, stderr, ""
}

func composeShell() (ps.Shell, error) {
	be := acquireBackend()
	sh, err := acquireShell(be)
	if err != nil {
		return nil, err
	}
	return sh, nil
}

func acquireShell(be backend.Starter) (ps.Shell, error) {
	shell, err := ps.New(be)
	if err != nil {
		return nil, err
	}

	return shell, nil
}

func acquireBackend() backend.Starter {
	return &backend.Local{}
}
