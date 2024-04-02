/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package etw

import (
	"eolh/pkg/containers/runtime"
	"eolh/pkg/engine"
	"eolh/pkg/trace"
)

type Config struct {
	EngineConfig engine.Config
	Sockets      runtime.Sockets
	ChanEvents   chan trace.Event
	Providers    []string
}
