/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package printer

import (
	"encoding/json"
	"eolh/pkg/logger"
	"eolh/pkg/trace"
	"fmt"
	"io"
)

type EventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	// Epilogue(stats metrics.Stats)
	// Print prints a single event
	Print(event trace.Event)
	// dispose of resources
	Close()
}

type jsonEventPrinter struct {
	out    io.WriteCloser
	logger logger.Logger
}

func (p jsonEventPrinter) Init() error { return nil }

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(event trace.Event) {
	eBytes, err := json.Marshal(event)
	if err != nil {
		p.logger.Errorw("Error marshaling event to json", "error", err)
	}
	fmt.Fprintln(p.out, string(eBytes))
}

func (p jsonEventPrinter) Close() {
}
