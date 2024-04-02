/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/
package cmd

import (
	"context"
	"eolh/pkg/cmd/printer"
	"eolh/pkg/containers/runtime"
	"eolh/pkg/detect"
	"eolh/pkg/engine"
	"eolh/pkg/etw"
	"eolh/pkg/logger"
	"eolh/pkg/signatures"
	"eolh/pkg/trace"
	"os"
)

type Event = etw.Event

func IsPe(bytesArray []byte) bool {
	if len(bytesArray) >= 2 {
		if bytesArray[0] == 0x4d && bytesArray[1] == 0x5a {
			return true
		}
	}

	return false
}

type Config struct {
	ChanEvents chan trace.Event
	Detect     bool
	Providers  []string
}

type Runner struct {
	EolhConfig Config
	Printer    printer.EventPrinter
}

func (r Runner) Run(ctx context.Context) {
	sockets := runtime.Autodiscover(func(err error, runtime runtime.RuntimeId, socket string) {
		if err != nil {
			logger.Debugw("RuntimeSockets: failed to register default", "socket", runtime.String(), "error", err)
		} else {
			logger.Debugw("RuntimeSockets: registered default", "socket", runtime.String(), "from", socket)
		}
	})
	sigs, _ := signatures.Find()
	enabled := true
	if !r.EolhConfig.Detect {
		enabled = false
	}
	engineConfig := engine.Config{
		Enabled:             enabled,
		Signatures:          sigs,
		SignatureBufferSize: 1000,
		DataSources:         []detect.DataSource{},
	}
	config := etw.Config{
		Sockets:      sockets,
		EngineConfig: engineConfig,
		ChanEvents:   make(chan trace.Event, 1000),
		Providers:    r.EolhConfig.Providers,
	}
	eolh := etw.New(config)
	err := eolh.Init()
	if err != nil {
		logger.Errorw("Failed to initialize Eolh ", err.Error())
		return
	}
	printerConfig := printer.PrinterConfig{
		Kind:    "json",
		OutFile: os.Stdout,
	}
	pConfigs := [1]printer.PrinterConfig{printerConfig}
	p, err := printer.NewBroadcast(pConfigs[:], printer.ContainerModeEnabled)
	if err != nil {
		logger.Errorw(err.Error())
		return
	}
	go func() {
		for {
			select {
			case event := <-config.ChanEvents:
				p.Print(event)
			case <-ctx.Done():
				return
			}
		}
	}()
	eolh.Run(ctx)
	for {
		select {
		case event := <-config.ChanEvents:
			p.Print(event)
		default:
			p.Close()
			return
		}
	}
}
