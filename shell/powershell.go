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

package shell

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aquasecurity/bench-common/check"
	ps "github.com/aquasecurity/go-powershell"
	"github.com/aquasecurity/go-powershell/backend"
	"github.com/golang/glog"
)

const TypePowershell = "powershell"
const osTypePowershellCommand = `Get-ComputerInfo -Property "os*" | Select -ExpandProperty OsProductType`

var errWrongOSType = errors.New("wrongOSType")

type PowerShell struct {
	Cmd    map[string]string
	sh     ps.Shell
	osType string
}

type shellStarter interface {
	startShell() (ps.Shell, error)
}

type localShellStarter struct{}

func NewPowerShell() (*PowerShell, error) {
	p, err := constructShell(&localShellStarter{})
	if err != nil {
		return nil, err
	}

	osType, err := p.performExec(osTypePowershellCommand)
	if err != nil {
		return nil, fmt.Errorf("Failed to get operating system type: %w", err)
	}
	p.osType = osType
	return p, nil
}

func constructShell(c shellStarter) (*PowerShell, error) {
	sh, err := c.startShell()
	if err != nil {
		return nil, err
	}

	return &PowerShell{
		Cmd: make(map[string]string),
		sh:  sh,
	}, nil
}

func (p *localShellStarter) startShell() (ps.Shell, error) {
	// start a local powershell process
	return ps.New(&backend.Local{})
}

// Execute - Implements the 'check.Auditer' interface
// It uses the aquasecurity/go-powershell package to interface with
// the windows powershell to execute the command.
func (p *PowerShell) Execute(customConfig ...interface{}) (result string, errMessage string, state check.State) {
	if len(customConfig) > 0 {
		p.updateCommand(customConfig[0])
	}
	stdout, err := p.executeCommand()
	if err != nil {
		errMessage = fmt.Sprintf("err: %v", err)
		if errors.Is(err, errWrongOSType) {
			return "", errMessage, check.SKIP
		}
		return "", errMessage, check.FAIL
	}

	glog.V(2).Info(fmt.Sprintf("Powershell.Execute - stdout: %s\n", stdout))
	return stdout, "", ""
}

func (p *PowerShell) updateCommand(commands interface{}) {
	if audit, ok := commands.(map[string]interface{}); ok {
		if data, ok := audit["cmd"].(map[string]interface{}); ok {
			p.Cmd = make(map[string]string, 0)
			for key, val := range data {
				if v, ok := val.(string); ok {
					p.Cmd[key] = v
				}
			}
		}

	}
}

func (p *PowerShell) executeCommand() (string, error) {
	cmd, err := p.commandForRuntimeOS()
	if err != nil {
		return "", err
	}

	stdout, err := p.performExec(cmd)
	if err != nil {
		return "", err
	}

	return stdout, nil
}

func (p *PowerShell) commandForRuntimeOS() (string, error) {
	cmd, found := p.Cmd[p.osType]
	if !found {
		return "", errors.Join(errWrongOSType, fmt.Errorf("Unable to find matching command for OS Type: %q", p.osType))
	}
	return cmd, nil
}

func (p *PowerShell) performExec(cmd string) (string, error) {
	glog.V(2).Info(fmt.Sprintf("powershell.performExec - executing command: %q\n", cmd))
	stdout, stderr, err := p.sh.Execute(cmd)
	if stderr != "" {
		glog.V(2).Info(fmt.Sprintf("powershell.performExec - stderr: %v\n", stderr))
	}

	if err != nil {
		glog.V(2).Info(fmt.Sprintf("powershell.performExec - error: %v\n", err))
		return "", err
	}
	retValue := strings.TrimSpace(stdout)
	glog.V(2).Info(fmt.Sprintf("powershell.performExec - returning: %q\n", retValue))
	return retValue, nil
}

func (p *PowerShell) Exit() {
	glog.V(2).Info(fmt.Sprintf("Powershell.Exit - p.sh valid? %t\n", (p.sh != nil)))
	if p.sh != nil {
		glog.V(2).Info("Powershell.Exit - request...")
		p.sh.Exit()
		glog.V(2).Info("done!\n")
	}
}
