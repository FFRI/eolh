/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/
package cmd

import (
	"context"
	cmdcobra "eolh/pkg/cmd/cobra"
	"eolh/pkg/logger"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var helpFlag bool
var rootCmd = &cobra.Command{
	Use:                "eolh",
	Short:              "Trace events using ETW",
	Long:               "Eolh uses ETW technology to tap into your system and give you access to hundreds of events that help you understand how your system behaves.",
	DisableFlagParsing: true,
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
				if err := cmd.Help(); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s\n", err)
					os.Exit(1)
				}
				os.Exit(0)
			}
			if err := cmd.Flags().Parse(args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %s\n", err)
				fmt.Fprintf(os.Stderr, "Run 'eolh --help' for usage.\n")
				os.Exit(1)
			}
		}
		if helpFlag {
			if err := cmd.Help(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %s\n", err)
				fmt.Fprintf(os.Stderr, "Run 'eolh --help' for usage.\n")
				os.Exit(1)
			}
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		logger.Init(logger.NewDefaultLoggingConfig())
		runner, err := cmdcobra.GetEolhRunner(cmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		runner.Run(ctx)
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func initCmd() error {
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	rootCmd.SetHelpCommand(&cobra.Command{})

	rootCmd.Flags().StringArrayP(
		"output",
		"o",
		[]string{"json"},
		"[json|webhook...]\t\tControl how and where output is printed",
	)

	err := viper.BindPFlag("output", rootCmd.Flags().Lookup("output"))
	if err != nil {
		return err
	}
	rootCmd.Flags().StringArrayP(
		"log",
		"l",
		[]string{"info"},
		"[debug|info|warn...]\t\tLogger options",
	)
	err = viper.BindPFlag("log", rootCmd.Flags().Lookup("log"))
	if err != nil {
		return err
	}
	rootCmd.Flags().BoolP(
		"detect",
		"d",
		true,
		"\t\t\t\t\tEnable detection",
	)
	err = viper.BindPFlag("detect", rootCmd.Flags().Lookup("detect"))
	if err != nil {
		return err
	}
	rootCmd.Flags().StringArrayP(
		"add",
		"a",
		nil,
		"\t\t\t\tEnable Additional ETW Providers",
	)
	err = viper.BindPFlag("add", rootCmd.Flags().Lookup("add"))
	if err != nil {
		return err
	}
	rootCmd.Flags().StringArrayP(
		"remove",
		"r",
		nil,
		"[process|file|network]\t\tDisable Default ETW Provides",
	)

	err = viper.BindPFlag("remove", rootCmd.Flags().Lookup("output"))
	if err != nil {
		return err
	}
	rootCmd.Flags().SortFlags = false
	return nil
}

func Execute() error {
	if err := initCmd(); err != nil {
		return err
	}

	return rootCmd.Execute()
}
