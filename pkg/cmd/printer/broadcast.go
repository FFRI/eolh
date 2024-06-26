/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/
package printer

import (
	"eolh/pkg/trace"
	"io"
	"sync"
)

type ContainerMode int

const (
	ContainerModeDisabled ContainerMode = iota
	ContainerModeEnabled
	ContainerModeEnriched
)

type PrinterConfig struct {
	Kind          string
	OutPath       string
	OutFile       io.WriteCloser
	ContainerMode ContainerMode
	RelativeTS    bool
}

type Broadcast struct {
	PrinterConfigs []PrinterConfig
	printers       []EventPrinter
	wg             *sync.WaitGroup
	eventsChan     []chan trace.Event
	done           chan struct{}
	containerMode  ContainerMode
}

func NewBroadcast(printerConfigs []PrinterConfig, containerMode ContainerMode) (*Broadcast, error) {
	b := &Broadcast{PrinterConfigs: printerConfigs, containerMode: containerMode}
	return b, b.Init()
}

func (b *Broadcast) Init() error {
	printers := make([]EventPrinter, 0, len(b.PrinterConfigs))
	wg := &sync.WaitGroup{}

	for _, pConfig := range b.PrinterConfigs {
		pConfig.ContainerMode = b.containerMode

		p, err := New(pConfig)
		if err != nil {
			return err
		}

		printers = append(printers, p)
	}

	eventsChan := make([]chan trace.Event, 0, len(printers))
	done := make(chan struct{})

	for _, printer := range printers {
		// we use a buffered channel to avoid blocking the event channel,
		// we match the size of ChanEvents buffer
		eventChan := make(chan trace.Event, 1000)
		eventsChan = append(eventsChan, eventChan)

		wg.Add(1)
		go startPrinter(wg, done, eventChan, printer)
	}

	b.printers = printers
	b.eventsChan = eventsChan
	b.wg = wg
	b.done = done

	return nil
}

func (b *Broadcast) Preamble() {
	for _, p := range b.printers {
		p.Preamble()
	}
}

// Print broadcasts the event to all printers
func (b *Broadcast) Print(event trace.Event) {
	for _, c := range b.eventsChan {
		// we are blocking here if the printer is not consuming events fast enough
		c <- event
	}
}

/**
func (b *Broadcast) Epilogue(stats metrics.Stats) {
	// if you execute epilogue no other events should be sent to the printers,
	// so we finish the events goroutines
	close(b.done)

	b.wg.Wait()

	for _, p := range b.printers {
		p.Epilogue(stats)
	}
}*/

// Close closes Broadcast printer
func (b *Broadcast) Close() {
	for _, p := range b.printers {
		p.Close()
	}
}

func startPrinter(wg *sync.WaitGroup, done chan struct{}, c chan trace.Event, p EventPrinter) {
	for {
		select {
		case <-done:
			wg.Done()
			return
		case event := <-c:
			p.Print(event)
		}
	}
}
