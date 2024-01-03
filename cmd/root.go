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
	"io"
	"os"

	goflag "flag"

	commonCheck "github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/windows-bench/shell"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	noResults      bool
	noSummary      bool
	noRemediations bool

	windowsCisVersion string
	cfgDir            string
	cfgFile           string
	checkList         string
	jsonFmt           bool
	includeTestOutput bool
	outputFile        string
	definitionsFile             = "definitions.yaml"
	outputWriter      io.Writer = os.Stdout
	errWriter         io.Writer = os.Stderr
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "windows-bench",
	Short: "windows-bench is a Go application that checks whether the windows operating system is deployed securely",
	Long:  `This tool runs the CIS Windows Benchmark (https://www.cisecurity.org/cis-benchmarks)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		b := commonCheck.NewBench()
		ps, err := shell.NewPowerShell()
		if err != nil {
			return err
		}
		err = b.RegisterAuditType(shell.TypePowershell, func() interface{} {
			if err != nil {
				return nil
			}
			glog.V(2).Info("Returning a PowerShell (Auditer) \n")
			return ps
		})
		return runChecks(b, ps.OsType)
	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	err := goflag.Set("logtostderr", "true")
	if err != nil {
		return err
	}
	err = goflag.CommandLine.Parse([]string{})
	if err != nil {
		return err
	}
	RootCmd.SetOut(outputWriter)
	RootCmd.SetErr(errWriter)
	if err := RootCmd.Execute(); err != nil {
		return err
	}
	return nil
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags, which, if defined here,
	// will be global for your application.

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	RootCmd.PersistentFlags().BoolVar(&noResults, "noresults", false, "Disable printing of results section")
	RootCmd.PersistentFlags().BoolVar(&noSummary, "nosummary", false, "Disable printing of summary section")
	RootCmd.PersistentFlags().BoolVar(&noRemediations, "noremediations", false, "Disable printing of remediations section")
	RootCmd.Flags().StringVarP(&windowsCisVersion, "version", "", "2.0.0", "Specify windows cis version, automatically detected if unset")
	RootCmd.Flags().StringVarP(&cfgDir, "config-dir", "D", "cfg", "directory to get benchmark definitions")
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is empty, will be used 'cfg/<version>/definitions.yaml')")
	RootCmd.PersistentFlags().BoolVar(&jsonFmt, "json", false, "Prints the results as JSON")
	RootCmd.PersistentFlags().BoolVar(&includeTestOutput, "include-test-output", false, "Prints the test's output")
	RootCmd.PersistentFlags().StringVar(&outputFile, "outputfile", "", "Writes the JSON results to output file")
	RootCmd.PersistentFlags().StringVarP(
		&checkList,
		"check",
		"c",
		"",
		`A comma-delimited list of checks to run as specified in CIS document. Example --check="1.1.1,1.1.2"`,
	)

	goflag.CommandLine.VisitAll(func(goflag *goflag.Flag) {
		RootCmd.PersistentFlags().AddGoFlag(goflag)
	})

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetConfigName(".windows-bench") // name of config file (without extension)
	viper.AddConfigPath("$HOME")          // adding home directory as first search path
	viper.AutomaticEnv()                  // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
