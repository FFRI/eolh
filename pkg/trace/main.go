/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package trace

import (
	"eolh/pkg/protocol"
	"time"

	"local.packages/golang-etw/etw"
)

type Container struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	ImageName   string `json:"image,omitempty"`
	ImageDigest string `json:"imageDigest,omitempty"`
}

type Metadata struct {
	Version     string
	Description string
	Tags        []string
	Properties  map[string]interface{}
}

type Kubernetes struct {
	PodName      string `json:"podName,omitempty"`
	PodNamespace string `json:"podNamespace,omitempty"`
	PodUID       string `json:"podUID,omitempty"`
	PodSandbox   bool   `json:"podSandbox,omitempty"`
}

type ContextFlags struct {
	ContainerStarted bool `json:"containerStarted"`
	IsCompat         bool `json:"isCompat"`
}

type Argument struct {
	ArgMeta
	Value interface{} `json:"value"`
}

// ArgMeta describes an argument
type ArgMeta struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Event struct {
	Timestamp       time.Time    `json:"timestamp"`
	ProcessID       int          `json:"processId"`
	ThreadID        int          `json:"threadId"`
	ParentProcessID int          `json:"parentProcessId"`
	IsHost          bool         `json:"isHost"`
	ProcessName     string       `json:"processName"`
	Cmdline         string       `json:"cmdLine"`
	HostName        string       `json:"computerName"`
	ContainerID     string       `json:"containerId"`
	Container       Container    `json:"container,omitempty"`
	Kubernetes      Kubernetes   `json:"kubernetes,omitempty"`
	EventID         int          `json:"eventId,string"`
	EventName       string       `json:"eventName"`
	ContextFlags    ContextFlags `json:"contextFlags"`
	Args            []Argument   `json:"args"` // Arguments are ordered according their appearance in the original event
	Metadata        *Metadata    `json:"metadata,omitempty"`
	RawEvent        etw.Event    `json:"raw,omitempty"`
	Message         string       `json:"message"`
}

// Converts a trace.Event into a protocol.Event that the rules engine can consume
func (e Event) ToProtocol() protocol.Event {
	return protocol.Event{
		Headers: protocol.EventHeaders{
			Selector: protocol.Selector{
				Name:   e.EventName,
				Origin: string(e.Origin()),
				Source: "eolh",
			},
		},
		Payload: e,
	}
}

// EventOrigin is where a trace.Event occured, it can either be from the host machine or from a container
type EventOrigin string

const (
	ContainerOrigin     EventOrigin = "container"      // Events originated from within a container, starting with the entry-point execution
	HostOrigin          EventOrigin = "host"           // Events originated from the host
	ContainerInitOrigin EventOrigin = "container-init" // Events originated from within container, before entry-point execution
)

// Origin derive the EventOrigin of a trace.Event
func (e Event) Origin() EventOrigin {
	if e.ContextFlags.ContainerStarted {
		return ContainerOrigin
	}
	if e.Container.ID != "" {
		return ContainerInitOrigin
	}
	return HostOrigin
}
