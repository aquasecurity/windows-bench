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

	"github.com/aquasecurity/bench-common/check"
	commonCheck "github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/bench-common/util"
	"github.com/golang/glog"
)

func runChecks(b commonCheck.Bench, serverType string) error {
	var version string
	var err error

	if windowsCisVersion != "" {
		version = windowsCisVersion
	} else {
		version = "2.0.0"
	}

	if cfgFile == "" {
		cfgFile, err = loadConfig(version)
		if err != nil {
			return err
		}
	}

	glog.V(1).Info(fmt.Sprintf("Using benchmark file: %s\n", cfgFile))

	// No Constraints for now
	constraints := make([]string, 0)
	controls, err := getControls(b, cfgFile, constraints)
	if err != nil {
		return err
	}

	summary := runControls(controls, checkList)

	// `runControls` can detect some items without correct `cmd`, and the state will be set `SKIP`
	// We should remove skipped controls, because there is no way to print them.
	for _, group := range controls.Groups {
		for i := len(group.Checks) - 1; i >= 0; i-- {
			if group.Checks[i].State == commonCheck.SKIP {
				group.Checks = append(group.Checks[:i], group.Checks[i+1:]...)
			}
		}
	}
	controls = updateControlCheck(controls, serverType)

	return outputResults(controls, summary)
}

func updateControlCheck(controls *check.Controls, osType string) *check.Controls {
	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			check.Audit = getOsTypeAuditCommand(check.Audit, osType)
		}
	}
	return controls
}

func getOsTypeAuditCommand(audit interface{}, serverType string) string {
	if a, ok := audit.(map[interface{}]interface{}); ok {
		if cmd, ok := a["cmd"].(map[interface{}]interface{}); ok {
			if val, ok := cmd[serverType].(string); ok {
				return val
			}
		}
	}
	return fmt.Sprintf("%v", audit)
}

// loadConfig finds the correct config dir based on the kubernetes version,
// merges any specific config.yaml file found with the main config
// and returns the benchmark file to use.
func loadConfig(version string) (string, error) {
	var err error
	path, err := getConfigFilePath(version, definitionsFile)
	if err != nil {
		return "", err
	}

	return filepath.Join(path, definitionsFile), nil
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
