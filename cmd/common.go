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
	"path/filepath"

	commonCheck "github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/bench-common/util"
	"github.com/aquasecurity/windows-bench/check"
	"github.com/golang/glog"
)

func runChecks(nodetype check.NodeType) {
	var version string
	var err error

	if windowsCisVersion != "" {
		version = windowsCisVersion
	} else {
		version = "1.1.0"
	}

	path := loadConfig(version, nodetype)

	glog.V(1).Info(fmt.Sprintf("Using benchmark file: %s\n", path))

	b := commonCheck.NewBench()
	ps, err := check.NewPowerShell()
	if err != nil {
		util.ExitWithError(err)
	}
	err = b.RegisterAuditType(check.TypePowershell, func() interface{} {
		glog.V(2).Info("Returning a PowerShell (Auditer) \n")
		return ps
	})
	if err != nil {
		util.ExitWithError(err)
	}

	// No Constraints for now
	constraints := make([]string, 0)

	controls, err := getControls(b, path, constraints)
	if err != nil {
		util.ExitWithError(err)
	}

	summary := runControls(controls, checkList)
	err = outputResults(controls, summary)
	if err != nil {
		util.ExitWithError(err)
	}

}

// loadConfig finds the correct config dir based on the kubernetes version,
// merges any specific config.yaml file found with the main config
// and returns the benchmark file to use.
func loadConfig(version string, nodetype check.NodeType) string {
	var file string
	var err error

	switch nodetype {
	case check.DomainController:
		file = domainControllerFile
	case check.MemberServer:
		file = memberServerFile
	}

	path, err := getConfigFilePath(version, file)
	if err != nil {
		util.ExitWithError(fmt.Errorf("can't find %s controls file in %s: %v", nodetype, cfgDir, err))
	}

	return filepath.Join(path, file)
}

func outputResults(controls *commonCheck.Controls, summary commonCheck.Summary) error {
	// if we successfully ran some tests and it's json format, ignore the warnings
	if (summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0) && jsonFmt {
		out, err := controls.JSON()
		if err != nil {
			return err
		}
		util.PrintOutput(string(out), outputFile)
	} else {
		util.PrettyPrint(controls, summary, noRemediations, includeTestOutput)
	}

	return nil
}
