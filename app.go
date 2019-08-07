package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/bench-common/util"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
)

func app(cmd *cobra.Command, args []string) {
	var version string
	var err error

	if windowsCisVersion != "" {
		version = windowsCisVersion
	} else {
		version = "1.1.0"
	}

	path, err := getDefinitionFilePath(version)
	if err != nil {
		util.ExitWithError(err)
	}

	// No Contraints for now
	constraints := make([]string, 0)

	controls, err := getControls(path, constraints)
	if err != nil {
		util.ExitWithError(err)
	}

	summary := runControls(controls, checkList)
	err = outputResults(controls, summary)
	if err != nil {
		util.ExitWithError(err)
	}
}

func outputResults(controls *check.Controls, summary check.Summary) error {
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

func getControls(path string, constraints []string) (*check.Controls, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	controls, err := check.NewControls([]byte(data), constraints)
	if err != nil {
		return nil, err
	}

	return controls, err
}

func getDefinitionFilePath(version string) (string, error) {
	filename := "definitions.yaml"

	glog.V(2).Info(fmt.Sprintf("Looking for config for version %s", version))

	path := filepath.Join(cfgDir, version)
	file := filepath.Join(path, filename)

	glog.V(2).Info(fmt.Sprintf("Looking for config file: %s\n", file))

	_, err := os.Stat(file)
	if err != nil {
		return "", err
	}

	return file, nil
}
