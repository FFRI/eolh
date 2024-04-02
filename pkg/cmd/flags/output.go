/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/
package flags

import (
	"eolh/pkg/cmd/printer"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type PrepareOutputResult struct {
	PrinterConfigs []printer.PrinterConfig
}

func parseFormat(outputParts []string, printerMap map[string]string) error {
	// if not file was passed, we use stdout
	if len(outputParts) == 1 {
		outputParts = append(outputParts, "stdout")
	}

	for _, outPath := range strings.Split(outputParts[1], ",") {
		if outPath == "" {
			return fmt.Errorf("format flag can't be empty, use '--output help' for more info")
		}

		if _, ok := printerMap[outPath]; ok {
			return fmt.Errorf("cannot use the same path for multiple outputs: %s, use '--output help' for more info", outPath)
		}
		printerMap[outPath] = outputParts[0]
	}

	return nil
}

func PrepareOutput(outputSlice []string) (PrepareOutputResult, error) {
	outConfig := PrepareOutputResult{}
	printerMap := make(map[string]string)
	for _, o := range outputSlice {
		outputParts := strings.SplitN(o, ":", 2)
		switch outputParts[0] {
		case "json":
			err := parseFormat(outputParts, printerMap)
			if err != nil {
				return outConfig, err
			}
		case "forward":
			_, err := url.ParseRequestURI(outputParts[1])
			if err != nil {
				return outConfig, err
			}

			printerMap[outputParts[1]] = "forward"
		case "webhook":
			_, err := url.ParseRequestURI(outputParts[1])
			if err != nil {
				return outConfig, err
			}
			printerMap[outputParts[1]] = "webhook"
		default:
			return outConfig, fmt.Errorf("invalid output flag: %s, use '--output help' for more info", outputParts[0])
		}
	}

	if len(printerMap) == 0 {
		printerMap["stdout"] = "json"
	}

	printerConfigs, err := getPrinterConfigs(printerMap)
	if err != nil {
		return outConfig, err
	}

	outConfig.PrinterConfigs = printerConfigs

	return outConfig, nil

}

func getPrinterConfigs(printerMap map[string]string) ([]printer.PrinterConfig, error) {
	printerConfigs := make([]printer.PrinterConfig, 0, len(printerMap))

	for outPath, printerKind := range printerMap {

		outFile := os.Stdout

		printerConfigs = append(printerConfigs, printer.PrinterConfig{
			Kind:    printerKind,
			OutPath: outPath,
			OutFile: outFile,
		})
	}

	return printerConfigs, nil
}
