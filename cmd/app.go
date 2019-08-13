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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/bench-common/util"
	"github.com/golang/glog"
)

func runControls(controls *check.Controls, checkList string) check.Summary {
	var summary check.Summary

	if checkList != "" {
		ids := util.CleanIDs(checkList)
		summary = controls.RunChecks(ids...)
	} else {
		summary = controls.RunGroup()
	}

	return summary
}

func getControls(bench check.Bench, path string, constraints []string) (*check.Controls, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	controls, err := bench.NewControls([]byte(data), constraints)
	if err != nil {
		return nil, err
	}

	return controls, err
}

func getDefinitionFilePath(version, filename string) (string, error) {

	glog.V(2).Info(fmt.Sprintf("Looking for config for version %s filename: %s\n", version, filename))
	path := filepath.Join(cfgDir, version)
	file := filepath.Join(path, filename)

	glog.V(2).Info(fmt.Sprintf("Looking for config file: %s\n", file))

	_, err := os.Stat(file)
	if err != nil {
		return "", err
	}

	return file, nil
}

// getConfigFilePath locates the config files we should be using based on either the specified
// version, or the running version of kubernetes if not specified
func getConfigFilePath(fileVersion string, filename string) (path string, err error) {

	glog.V(2).Info(fmt.Sprintf("Looking for config for version %s", fileVersion))

	for {
		path = filepath.Join(cfgDir, fileVersion)
		file := filepath.Join(path, string(filename))
		glog.V(2).Info(fmt.Sprintf("Looking for config file: %s\n", file))

		if _, err = os.Stat(file); !os.IsNotExist(err) {
			return path, err
		}

	}
}
