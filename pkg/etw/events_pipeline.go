/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package etw

import (
	"context"
	"eolh/pkg/events"
	"eolh/pkg/logger"
	"eolh/pkg/trace"
	"fmt"
	"strconv"

	"github.com/shirou/gopsutil/v3/process"
	"local.packages/golang-etw/etw"
)

func (e *Eolh) decodeEvents(outerCtx context.Context, sourceChan chan etw.Event) (<-chan *trace.Event, <-chan error) {
	out := make(chan *trace.Event, 10000)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for dataRaw := range sourceChan {
			pid := dataRaw.EventData["ProcessID"]
			var num uint64
			// Fixme
			if pid == nil {
				continue
			}
			num, _ = strconv.ParseUint(pid.(string), 10, 64)
			if num == uint64(e.pid) || num == uint64(e.runtimePid) || num == 0 || num == 4 || num == uint64(e.kubeletPid) || num == uint64(e.defenderPid) {
				continue
			}
			num = uint64(dataRaw.System.Execution.ProcessID)
			metadata, err := e.containers.Enrich(int(num))

			containerData := trace.Container{
				ID:          metadata.ContainerId,
				ImageName:   metadata.Image,
				ImageDigest: metadata.ImageDigest,
				Name:        metadata.Name,
			}
			kubernetesData := trace.Kubernetes{
				PodName:      metadata.Pod.Name,
				PodNamespace: metadata.Pod.Namespace,
				PodUID:       metadata.Pod.UID,
			}
			evt := e.eventsPool.Get().(*trace.Event)
			// matchPolicies
			evt.Timestamp = dataRaw.System.TimeCreated.SystemTime
			evt.Message = ""
			evt.RawEvent = dataRaw
			evt.Container = containerData
			evt.Kubernetes = kubernetesData
			evt.ContainerID = containerData.ID
			evt.IsHost = evt.ContainerID == e.runtimeContainerID
			evt.Cmdline = ""
			evt.HostName = dataRaw.System.Computer
			p, err := process.NewProcess(int32(num))
			if err == nil {
				name, err := p.Name()
				if err == nil {
					evt.ProcessName = name
				}
				parent, err := p.Parent()
				if err == nil {
					evt.ParentProcessID = int(parent.Pid)
				}
				cmdline, err := p.Cmdline()
				if err == nil {
					evt.Cmdline = cmdline
				}
			}
			evt.ProcessID = int(num)
			tid := dataRaw.EventData["ThreadID"]
			if tid == nil {
				num = 0 // Fixme
			} else {
				num, _ = strconv.ParseUint(tid.(string), 10, 64)
			}
			evt.ThreadID = int(num)
			select {
			case out <- evt:
			case <-outerCtx.Done():
				return
			}
		}
	}()
	return out, errc
}

func (e *Eolh) handleEvents(ctx context.Context) {
	var errcList []<-chan error

	eventsChan, errc := e.decodeEvents(ctx, e.eventsChannel)

	errcList = append(errcList, errc)

	eventsChan, errc = e.processEvents(ctx, eventsChan)
	if e.config.EngineConfig.Enabled {
		eventsChan, errc = e.engineEvents(ctx, eventsChan)
		errcList = append(errcList, errc)
	}
	errc = e.sinkEvents(ctx, eventsChan)
	errcList = append(errcList, errc)
	// TODO:error handling!
}

func (e *Eolh) processEvents(ctx context.Context, in <-chan *trace.Event) (<-chan *trace.Event, <-chan error) {
	out := make(chan *trace.Event, 10000)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)

		for event := range in {
			if event == nil {
				logger.Debugw("event nil")
				continue
			}

			errs := e.processEvent(event)
			if len(errs) > 0 {
				logger.Debugw("process Event err")
				// todo: error handling
				continue
			}
			select {
			case out <- event:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errc
}

func (e *Eolh) processEvent(event *trace.Event) []error {
	eventId := events.ID(event.EventID)
	processors := e.eventProcessor[eventId]
	errs := []error{}
	for _, procFunc := range processors {
		err := procFunc(event)
		if err != nil {
			logger.Errorw("Error processing event", "event", event.EventName, "error", err)
			errs = append(errs, err)
		}
	}
	return errs
}

func (e *Eolh) RegisterEventProcessor(id events.ID, proc func(evt *trace.Event) error) error {
	if e.eventProcessor == nil {
		return fmt.Errorf("eolh not initialized yet")
	}
	if e.eventProcessor[id] == nil {
		e.eventProcessor[id] = make([]func(evt *trace.Event) error, 0)
	}
	e.eventProcessor[id] = append(e.eventProcessor[id], proc)
	return nil
}

func (e *Eolh) registerEventProcessors() {
	if e.eventProcessor == nil {
		e.eventProcessor = make(map[events.ID][]func(evt *trace.Event) error)
	}

}

func (e *Eolh) sinkEvents(ctx context.Context, in <-chan *trace.Event) <-chan error {
	errc := make(chan error, 1)

	go func() {
		defer close(errc)

		for event := range in {
			if event == nil {
				continue // might happen during initialization (ctrl+c seg faults)
			}
			// Send the event to the printers.
			if e.config.EngineConfig.Enabled && event.Message == "" {
				continue
			}
			select {
			case e.config.ChanEvents <- *event:
				e.eventsPool.Put(event)
			case <-ctx.Done():
				return
			}
		}
	}()

	return errc
}
