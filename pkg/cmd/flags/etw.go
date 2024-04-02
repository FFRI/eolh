/*
Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/
package flags

import "slices"

func PrepareETW(addSlice []string, removeSlice []string) []string {
	etwProviders := []string{}
	if !slices.Contains(removeSlice, "file") {
		etwProviders = append(etwProviders, "Microsoft-Windows-Kernel-File")
	}
	if !slices.Contains(removeSlice, "network") {
		etwProviders = append(etwProviders, "Microsoft-Windows-Kernel-Network")
	}
	if !slices.Contains(removeSlice, "process") {
		etwProviders = append(etwProviders, "Microsoft-Windows-Kernel-Process")
	}
	etwProviders = append(etwProviders, addSlice...)
	return etwProviders
}
