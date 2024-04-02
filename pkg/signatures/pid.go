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
	"strconv"
)

// FakeSignature is a mock for the detect.Signature interface,
// it allows customization of methods through the fields.
// It can be used for tests.
type PidSpoofing struct {
	cb detect.SignatureHandler
}

func (sig *PidSpoofing) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "EOLH-2",
		Version:     "1",
		Name:        "PPID Spoofing",
		EventName:   "ppid_spoofing",
		Description: "An attacker can temper with parent process and hide the ture parent-child relationship to evade detection.",
		Properties: map[string]interface{}{
			"Severity": 3,
		},
	}, nil
}

func (sig *PidSpoofing) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{{
		Source: "eolh", Name: "*", Origin: "*",
	}}, nil
}

func (sig *PidSpoofing) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *PidSpoofing) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}
	e := ee.RawEvent
	if e.System.Opcode.Value != 1 {
		return nil
	}
	if e.EventData == nil {
		return nil
	}
	i, ok := e.EventData["ParentProcessID"]
	if !ok {
		return nil
	}
	pid := e.EventData["ProcessID"]
	i2 := e.System.Execution.ProcessID
	num, _ := strconv.ParseUint(i.(string), 10, 64)
	num32 := uint32(num)
	if num32 == i2 {
		return nil
	}
	metadata, err := sig.GetMetadata()
	if err != nil {
		return err
	}
	message := fmt.Sprintf("PPID Spoofing detected: PID=%s process started by PPID=%d rather than PPID=%d", pid, i2, num32)
	sig.cb(detect.Finding{
		SigMetadata: metadata,
		Event:       event,
		Data:        nil,
		Msg:         message,
	})
	return nil
}

func (sig *PidSpoofing) OnSignal(signal detect.Signal) error {
	return nil
}

func (sig *PidSpoofing) Close() {}
