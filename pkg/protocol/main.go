/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package protocol

// Selector is a propriotary header used for filtering event subscriptions in the engine
type Selector struct {
	// Name indicates the name of the Event payload
	Name string
	// Origin indicates where the event was generated (host, container, pod), this may be empty depending on Source
	Origin string
	// Source indicates the producer of the Event (example: tracee, CNDR, K8SAuditLog...)
	Source string
}

type EventHeaders struct {
	// Selector is a propriotary header used for filtering event subscriptions in the engin
	Selector Selector

	// Custom additional custom headers, nil most of the time
	custom map[string]string
}

type Event struct {
	Headers EventHeaders
	Payload interface{}
}
