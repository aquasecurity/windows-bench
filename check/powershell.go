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
	"strings"

	"github.com/aquasecurity/bench-common/check"
	ps "github.com/aquasecurity/go-powershell"
	"github.com/aquasecurity/go-powershell/backend"
	"github.com/golang/glog"
)

const TypePowershell = "powershell"
const osTypePowershellCommand = `Get-ComputerInfo -Property "os*" | Select -ExpandProperty OsProductType`

type PowerShell struct {
	Cmd map[string]string
	sh  ps.Shell
}

func NewPowerShell() (*PowerShell, error) {
	sh, err := composeShell()
	if err != nil {
		return nil, err
	}
	return &PowerShell{
		Cmd: make(map[string]string),
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

	osType, err := determineOSType(p.sh)
	if err != nil {
		errMessage = fmt.Sprintf("Failed to get operating system type\n")
		return "", errMessage, check.FAIL
	}

	cmd, found := p.Cmd[osType]
	if !found {
		errMessage = fmt.Sprintf("Unable to find matching command for OS Type: %q\n", osType)
		return "", errMessage, check.FAIL
	}

	stdout, err := performExec(p.sh, cmd)
	if err != nil {
		errMessage = fmt.Sprintf("err: %v", err)
		return stdout, errMessage, check.FAIL
	}

	glog.V(2).Info(fmt.Sprintf("Powershell.Execute - stdout: %s\n", stdout))
	return stdout, "", ""
}

func determineOSType(sh ps.Shell) (string, error) {
	stdout, err := performExec(sh, osTypePowershellCommand)
	if err != nil {
		return "", err
	}

	return stdout, nil
}

func performExec(sh ps.Shell, cmd string) (string, error) {
	glog.V(2).Info(fmt.Sprintf("Powershell.Execute - executing command: %q\n", cmd))
	stdout, stderr, err := sh.Execute(cmd)

	if stderr != "" {
		glog.V(2).Info(fmt.Sprintf("Powershell.Execute - stderr: %v\n", stderr))
	}

	if err != nil {
		glog.V(2).Info(fmt.Sprintf("Powershell.Execute - error: %v\n", err))
		return "", err
	}
	retValue := strings.TrimSpace(stdout)
	glog.V(2).Info(fmt.Sprintf("Powershell.Execute - returning: %q\n", retValue))
	return retValue, nil
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
