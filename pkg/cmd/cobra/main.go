/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/
package cobra

import (
	"eolh/pkg/cmd"
	"eolh/pkg/cmd/flags"
	"eolh/pkg/cmd/printer"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func GetEolhRunner(c *cobra.Command) (cmd.Runner, error) {
	var runner cmd.Runner
	output, err := flags.PrepareOutput(viper.GetStringSlice("output"))
	if err != nil {
		return runner, err
	}
	p, err := printer.NewBroadcast(output.PrinterConfigs, printer.ContainerModeEnriched)
	if err != nil {
		return runner, err
	}
	runner.Printer = p
	detect := viper.GetBool("detect")
	runner.EolhConfig.Detect = detect
	providers := flags.PrepareETW(viper.GetStringSlice("add"), viper.GetStringSlice("remove"))
	runner.EolhConfig.Providers = providers
	return runner, nil
}
