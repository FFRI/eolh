/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package etw

import (
	"context"
	"eolh/pkg/containers"
	"eolh/pkg/detect"
	"eolh/pkg/engine"
	"eolh/pkg/logger"
	"eolh/pkg/protocol"
	"eolh/pkg/trace"
)

func (e *Eolh) engineEvents(ctx context.Context, in <-chan *trace.Event) (<-chan *trace.Event, <-chan error) {
	out := make(chan *trace.Event)
	errc := make(chan error, 1)

	engineOutput := make(chan detect.Finding, 100)
	engineInput := make(chan protocol.Event)
	source := engine.EventSources{Eolh: engineInput}

	e.config.EngineConfig.DataSources = append(e.config.EngineConfig.DataSources, containers.NewDataSource(e.containers))

	sigEngine, err := engine.NewEngine(e.config.EngineConfig, source, engineOutput)
	if err != nil {
		logger.Fatalw("failed to start signature engine in \"everything is an event\" mode", "error", err)
	}
	e.sigEngine = sigEngine

	go e.sigEngine.Start(ctx)

	// TODO: in the upcoming releases, the rule engine should be changed to receive trace.Event,
	// and return a trace.Event, which should remove the necessity of converting trace.Event to protocol.Event,
	// and converting detect.Finding into trace.Event

	go func() {
		defer close(out)
		defer close(errc)
		defer close(engineInput)
		defer close(engineOutput)

		for {
			select {
			case event := <-in:
				if event == nil {
					continue // might happen during initialization (ctrl+c seg faults)
				}
				if event.Message != "" {
					continue // Detection Event
				}

				///id := events.ID(event.EventID)
				// if the event is marked as submit, we pass it to the engine
				//if e.events[id].submit > 0 {
				//err := e.parseArguments(event)
				//if err != nil {
				//e.handleError(err)
				//	continue
				//}

				// Get a copy of our event before sending it down the pipeline.
				// This is needed because a later modification of the event (in
				// particular of the matched policies) can affect engine stage.
				eventCopy := *event
				// pass the event to the sink stage, if the event is also marked as emit
				// it will be sent to print by the sink stage
				out <- event

				// send the event to the rule event
				engineInput <- eventCopy.ToProtocol()
				//}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case finding := <-engineOutput:
				if finding.Event.Payload == nil {
					continue // might happen during initialization (ctrl+c seg faults)
				}
				event, err := FindingToEvent(finding)
				if err != nil {
					// e.handleError(err)
					continue
				}
				out <- event
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, errc
}
