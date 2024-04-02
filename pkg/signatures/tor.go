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
	"strings"
)

// FakeSignature is a mock for the detect.Signature interface,
// it allows customization of methods through the fields.
// It can be used for tests.
type Tor struct {
	cb detect.SignatureHandler
}

func (sig *Tor) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "EOLH-4",
		Version:     "1",
		Name:        "Tor Executable",
		EventName:   "tor_executable",
		Description: "The Tor Executable is found.",
		Properties: map[string]interface{}{
			"Severity": 4,
		},
	}, nil
}

// todo: use ETW
func (sig *Tor) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{{
		Source: "eolh", Name: "*", Origin: "*",
	}}, nil
}

func (sig *Tor) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *Tor) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}
	e := ee.RawEvent
	if e.System.Opcode.Value != 1 {
		return nil
	}
	child := ee.ProcessName
	if child == "" {
		return nil
	}
	metadata, err := sig.GetMetadata()
	if err != nil {
		return err
	}
	if !strings.Contains(child, "tor.exe") {
		return nil
	}
	message := fmt.Sprintf("tor executable detected: %s", child)
	sig.cb(detect.Finding{
		SigMetadata: metadata,
		Event:       event,
		Data:        nil,
		Msg:         message,
	})
	return nil
}

func (sig *Tor) OnSignal(signal detect.Signal) error {
	return nil
}

func (sig *Tor) Close() {}
