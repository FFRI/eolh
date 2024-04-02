/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package signatures

import (
	"eolh/pkg/detect"
	"eolh/pkg/protocol"
	"eolh/pkg/trace"
	"fmt"
	"os"
)

func IsPe(bytesArray []byte) bool {
	if len(bytesArray) >= 2 {
		if bytesArray[0] == 0x4d && bytesArray[1] == 0x5a {
			return true
		}
	}

	return false
}

// FakeSignature is a mock for the detect.Signature interface,
// it allows customization of methods through the fields.
// It can be used for tests.
type Drop struct {
	cb detect.SignatureHandler
}

func (sig *Drop) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "EOLH-1",
		Version:     "1",
		Name:        "New executable dropped in a container",
		EventName:   "dropped_exe_container",
		Description: "A new PE file is created in a container. This is normal behaviour in the early stages of container creation.",
		Properties: map[string]interface{}{
			"Severity": 0,
		},
	}, nil
}

func (sig *Drop) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{{
		Source: "eolh", Name: "*", Origin: "*",
	}}, nil
}

func (sig *Drop) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *Drop) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}
	if ee.IsHost {
		return nil
	}
	e := ee.RawEvent
	if e.EventData == nil {
		return nil
	}
	if e.System.Opcode.Value != 0 || e.System.Task.Value != 30 {
		return nil
	}
	if e.EventData == nil {
		return nil
	}
	f, ok := e.EventData["FileName"]
	if !ok {
		return nil
	}
	if f.(string) == "" {
		return nil
	}
	id := ee.ContainerID
	if id == "" {
		return nil
	}
	file, err := os.Open("\\\\?\\GLOBALROOT" + f.(string))
	if err != nil {
		return nil // Noisy
	}
	b := make([]byte, 2)
	n, _ := file.Read(b)
	if !IsPe(b[:n]) {
		return nil
	}
	metadata, err := sig.GetMetadata()
	if err != nil {
		return err
	}
	message := fmt.Sprintf("New Executable Dropped in container detected: FileName=%s", f.(string))
	sig.cb(detect.Finding{
		SigMetadata: metadata,
		Event:       event,
		Data:        nil,
		Msg:         message,
	})
	return nil
}

func (sig *Drop) OnSignal(signal detect.Signal) error {
	return nil
}

func (sig *Drop) Close() {}
