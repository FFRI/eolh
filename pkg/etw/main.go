/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package etw

import (
	"eolh/pkg/detect"
	"eolh/pkg/trace"
	"fmt"

	"local.packages/golang-etw/etw"
)

type Event = etw.Event

func FindingToEvent(f detect.Finding) (*trace.Event, error) {
	s, ok := f.Event.Payload.(trace.Event)

	if !ok {
		return nil, fmt.Errorf("error converting finding to event: %s", f.SigMetadata.ID)
	}

	//eventID, found := events.Definitions.GetID(f.SigMetadata.EventName) // getDefinitionIDByName
	eventID := -1
	found := true
	if !found {
		return nil, fmt.Errorf("error finding event not found: %s", f.SigMetadata.EventName)
	}

	return newEvent(int(eventID), f, s), nil
}

func getMetadataFromSignatureMetadata(sigMetadata detect.SignatureMetadata) *trace.Metadata {
	metadata := &trace.Metadata{}

	metadata.Version = sigMetadata.Version
	metadata.Description = sigMetadata.Description
	metadata.Tags = sigMetadata.Tags

	properties := sigMetadata.Properties
	if sigMetadata.Properties == nil {
		properties = make(map[string]interface{})
	}

	metadata.Properties = properties
	metadata.Properties["signatureID"] = sigMetadata.ID
	metadata.Properties["signatureName"] = sigMetadata.Name

	return metadata
}

func newEvent(id int, f detect.Finding, s trace.Event) *trace.Event {
	metadata := getMetadataFromSignatureMetadata(f.SigMetadata)

	return &trace.Event{
		EventID:         id,
		EventName:       f.SigMetadata.EventName,
		Timestamp:       s.Timestamp,
		ProcessID:       s.ProcessID,
		ThreadID:        s.ThreadID,
		ParentProcessID: s.ParentProcessID,
		ProcessName:     s.ProcessName,
		HostName:        s.HostName,
		ContainerID:     s.ContainerID,
		Cmdline:         s.Cmdline,
		Container:       s.Container,
		Kubernetes:      s.Kubernetes,
		ContextFlags:    s.ContextFlags,
		Metadata:        metadata,
		Message:         f.Msg,
	}
}
