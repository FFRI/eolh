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
type CryptoMiner struct {
	cb detect.SignatureHandler
}

func (sig *CryptoMiner) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "EOLH-3",
		Version:     "1",
		Name:        "Crypto Mining",
		EventName:   "crypto_mining",
		Description: "A crypto miner using the Stratum protocol is found.",
		Properties: map[string]interface{}{
			"Severity": 4,
		},
	}, nil
}

func (sig *CryptoMiner) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{{
		Source: "eolh", Name: "*", Origin: "*",
	}}, nil
}

func (sig *CryptoMiner) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *CryptoMiner) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}
	arg := ee.Cmdline
	if arg == "" {
		return nil
	}
	if !strings.Contains(arg, "stratum+tcp") && !strings.Contains(arg, "stratum2+tcp") && !strings.Contains(arg, "stratum+ssl") && !strings.Contains(arg, "stratum2+ssl") {
		return nil
	}
	metadata, err := sig.GetMetadata()
	if err != nil {
		return err
	}
	message := fmt.Sprintf("crypto miners using the Stratum protocol detected: %s", arg)
	sig.cb(detect.Finding{
		SigMetadata: metadata,
		Event:       event,
		Data:        nil,
		Msg:         message,
	})
	return nil
}

func (sig *CryptoMiner) OnSignal(signal detect.Signal) error {
	return nil
}

func (sig *CryptoMiner) Close() {}
