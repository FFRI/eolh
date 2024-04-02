/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package runtime

import (
	"context"
)

type ContainerMetadata struct {
	ContainerId string
	Name        string
	Image       string
	ImageDigest string
	Pod         PodMetadata
}

type PodMetadata struct {
	Name      string
	Namespace string
	UID       string
	Sandbox   bool
}

// These labels are injected by kubelet on container creation, we can use them to gather additional data in a k8s context
const (
	PodNameLabel                 = "io.kubernetes.pod.name"
	PodNamespaceLabel            = "io.kubernetes.pod.namespace"
	PodUIDLabel                  = "io.kubernetes.pod.uid"
	ContainerNameLabel           = "io.kubernetes.container.name"
	ContainerTypeDockerLabel     = "io.kubernetes.docker.type"
	ContainerTypeContainerdLabel = "io.cri-containerd.kind"
	ContainerTypeCrioAnnotation  = "io.kubernetes.cri-o.ContainerType"
)

type ContainerEnricher interface {
	Get(ctx context.Context, containerId string) (ContainerMetadata, error)
	FindContainer(procid int32) string
	//GetContainerList() ([]types.Container, error)
	Populate() (map[uint32]CRInfo, error)
}

// Represents the internal ID of a container runtime
type RuntimeId int

const (
	Unknown RuntimeId = iota
	Docker
	Containerd
	Crio
	Podman
)

var runtimeStringMap = map[RuntimeId]string{
	Unknown:    "unknown",
	Docker:     "docker",
	Containerd: "containerd",
	//Crio:       "crio",
	//Podman:     "podman",
}

func (runtime RuntimeId) String() string {
	return runtimeStringMap[runtime]
}

func FromString(str string) RuntimeId {
	switch str {
	case "docker":
		return Docker
	case "containerd":
		return Containerd
	default:
		return Unknown
	}
}
