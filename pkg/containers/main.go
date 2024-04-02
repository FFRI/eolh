/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package containers

import (
	"encoding/json"
	cruntime "eolh/pkg/containers/runtime"
	"eolh/pkg/detect"
	"eolh/pkg/logger"
	"fmt"
	"sync"
)

type SignaturesDataSource struct {
	containers *Containers
}

func NewDataSource(c *Containers) *SignaturesDataSource {
	return &SignaturesDataSource{
		containers: c,
	}
}

// Containers contains information about running containers in the host.
type Containers struct {
	crMap    map[uint32]cruntime.CRInfo
	deleted  []uint64
	mtx      sync.RWMutex // protecting both cgroups and deleted fields
	enricher runtimeInfoService
}

func (ctx SignaturesDataSource) Get(key interface{}) (map[string]interface{}, error) {
	containerId, ok := key.(string)
	if !ok {
		return nil, detect.ErrKeyNotSupported
	}
	ctx.containers.mtx.RLock()
	defer ctx.containers.mtx.RUnlock()
	for _, crinfo := range ctx.containers.crMap {
		if crinfo.Container.ContainerId == containerId {
			containerData := crinfo.Container
			podData := containerData.Pod
			result := make(map[string]interface{}, 7)
			result["container_id"] = containerData.ContainerId
			result["container_name"] = containerData.Name
			result["container_image"] = containerData.Image
			result["k8s_pod_id"] = podData.UID
			result["k8s_pod_name"] = podData.Name
			result["k8s_pod_namespace"] = podData.Namespace
			result["k8s_pod_sandbox"] = podData.Sandbox
			return result, nil
		}
	}
	return nil, detect.ErrDataNotFound
}

func (ctx SignaturesDataSource) Schema() string {
	schemaMap := map[string]string{
		"container_id":      "string",
		"container_name":    "string",
		"container_image":   "string",
		"k8s_pod_id":        "string",
		"k8s_pod_name":      "string",
		"k8s_pod_namespace": "string",
		"k8s_pod_sandbox":   "bool",
	}
	schema, _ := json.Marshal(schemaMap)
	return string(schema)
}

func (ctx SignaturesDataSource) Keys() []string {
	return []string{"string"}
}

func (ctx SignaturesDataSource) Version() uint {
	return 1
}

func (ctx SignaturesDataSource) Namespace() string {
	return "eolh"
}

func (ctx SignaturesDataSource) ID() string {
	return "containers"
}

func New(sockets cruntime.Sockets) (*Containers, error) {
	containers := &Containers{
		crMap: make(map[uint32]cruntime.CRInfo),
	}
	runtimeService := RuntimeInfoService(sockets)
	err := runtimeService.Register(cruntime.Containerd, cruntime.ContainerdEnricher)
	if err != nil {
		logger.Debugw("Enricher", "error", err)
	}
	containers.enricher = runtimeService
	return containers, nil
}

func (c *Containers) Enrich(pid int) (cruntime.ContainerMetadata, error) {
	si, err := cruntime.GetSIOfProcess(int32(pid))
	if err != nil {
		return cruntime.ContainerMetadata{}, err
	}
	err = c.Populate()
	if err != nil {
		return cruntime.ContainerMetadata{}, err
	}
	crinfo, ok := c.crMap[si]
	if !ok {
		return cruntime.ContainerMetadata{}, fmt.Errorf("No container found with the session identifier")
	}
	return crinfo.Container, nil
}

func (c *Containers) Populate() error {
	var err error
	c.crMap, err = c.enricher.Populate(cruntime.FromString("containerd"))
	return err
}
