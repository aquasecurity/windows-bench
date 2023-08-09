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
	"github.com/golang/glog"
)

func runChecks(b commonCheck.Bench) error {
	var version string
	var err error

	if windowsCisVersion != "" {
		version = windowsCisVersion
	} else {
		version = "2.0.0"
	}
	path, err := loadConfig(version)
	if err != nil {
		return err
	}
	glog.V(1).Info(fmt.Sprintf("Using benchmark file: %s\n", path))

	// No Constraints for now
	constraints := make([]string, 0)
	controls, err := getControls(b, path, constraints)
	if err != nil {
		return err
	}

	summary := runControls(controls, checkList)
	err = outputResults(controls, summary)
	if err != nil {
		return err
	}
	return nil

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
