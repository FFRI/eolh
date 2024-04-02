/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package events

import "eolh/pkg/trace"

type ID int32

// Event is a struct describing an event configuration
type Event struct {
	ID32Bit  ID
	Name     string
	DocPath  string // Relative to the 'doc/events' directory
	Internal bool
	Syscall  bool
	Sets     []string
	Params   []trace.ArgMeta
}
