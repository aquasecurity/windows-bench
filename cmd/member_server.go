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

// memberServerCmd represents the master command
var memberServerCmd = &cobra.Command{
	Use:   "member-server",
	Short: "Run benchmark checks for a Member Server node.",
	Long:  `Run benchmark checks for a Member Server node.`,
	Run: func(cmd *cobra.Command, args []string) {
		runChecks(check.MemberServer)
	},
}

func init() {
	memberServerCmd.PersistentFlags().StringVarP(&memberServerFile,
		"file",
		"f",
		"/member-server.yaml",
		"Alternative YAML file for Member Server checks",
	)

	RootCmd.AddCommand(memberServerCmd)
}
