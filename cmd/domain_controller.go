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
	"github.com/aquasecurity/windows-bench/check"
	"github.com/spf13/cobra"
)

// domainControllerCmd represents the master command
var domainControllerCmd = &cobra.Command{
	Use:   "domain-controller",
	Short: "Run benchmark checks for a Domain Controller node.",
	Long:  `Run benchmark checks for a Domain Controller node.`,
	Run: func(cmd *cobra.Command, args []string) {
		runChecks(check.DomainController)
	},
}

func init() {
	domainControllerCmd.PersistentFlags().StringVarP(&domainControllerFile,
		"file",
		"f",
		"/domain-controller.yaml",
		"Alternative YAML file for Domain Controller checks",
	)

	RootCmd.AddCommand(domainControllerCmd)
}
