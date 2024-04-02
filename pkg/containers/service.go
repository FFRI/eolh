/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package containers

import (
	"context"
	"fmt"

	"eolh/pkg/containers/runtime"
	"eolh/pkg/logger"
)

type runtimeInfoService struct {
	sockets   runtime.Sockets
	enrichers map[runtime.RuntimeId]runtime.ContainerEnricher
}

// RuntimeInfoService initializes a service which can register enrichers for container runtimes
func RuntimeInfoService(sockets runtime.Sockets) runtimeInfoService {
	return runtimeInfoService{
		enrichers: make(map[runtime.RuntimeId]runtime.ContainerEnricher),
		sockets:   sockets,
	}
}

// Register associates some ContainerEnricher with a runtime, the service can then use it for relevant queries
func (e *runtimeInfoService) Register(rtime runtime.RuntimeId, enricherBuilder func(socket string) (runtime.ContainerEnricher, error)) error {
	if !e.sockets.Supports(rtime) {
		return fmt.Errorf("error registering enricher: unsupported runtime %s", rtime.String())
	}
	socket := e.sockets.Socket(rtime)
	enricher, err := enricherBuilder(socket)
	if err != nil {
		logger.Errorw("Register Error enricherBuilder")
		return err
	}
	e.enrichers[rtime] = enricher
	return nil
}

func (e *runtimeInfoService) Populate(containerRuntime runtime.RuntimeId) (map[uint32]runtime.CRInfo, error) {
	enricher := e.enrichers[containerRuntime]
	if enricher != nil {
		return enricher.Populate()
	}
	return nil, fmt.Errorf("unsupported runtime")
}

// Get calls the inner enricher's Get, based on the containerRuntime parameter if a relevant enricher was registered
// If an unknown runtime is received, enrichment will be attempted through all registered enrichers
func (e *runtimeInfoService) Get(ctx context.Context, containerId string, containerRuntime runtime.RuntimeId) (runtime.ContainerMetadata, error) {
	if containerRuntime == runtime.Unknown {
		return e.getFromUnknownRuntime(ctx, containerId)
	}

	return e.getFromKnownRuntime(ctx, containerId, containerRuntime)
}

// standard case when we can query the known runtime from the get go
func (e *runtimeInfoService) getFromKnownRuntime(ctx context.Context, containerId string, containerRuntime runtime.RuntimeId) (runtime.ContainerMetadata, error) {
	enricher := e.enrichers[containerRuntime]
	if enricher != nil {
		return enricher.Get(ctx, containerId)
	}
	return runtime.ContainerMetadata{}, fmt.Errorf("unsupported runtime")
}

// in case where we don't know the container's runtime, we query through all the registered enrichers
func (e *runtimeInfoService) getFromUnknownRuntime(ctx context.Context, containerId string) (runtime.ContainerMetadata, error) {
	for _, enricher := range e.enrichers {
		metadata, err := enricher.Get(ctx, containerId)

		if err == nil {
			return metadata, nil
		}
	}

	return runtime.ContainerMetadata{}, fmt.Errorf("no runtime found for container")
}
