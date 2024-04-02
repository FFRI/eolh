/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package detect

import (
	"eolh/pkg/protocol"
	"errors"
)

type SignatureMetadata struct {
	ID          string
	Version     string
	Name        string
	EventName   string
	Description string
	Tags        []string
	Properties  map[string]interface{}
}

type Finding struct {
	Data        map[string]interface{}
	Event       protocol.Event // protocol.Event // Event is the causal event of the Finding
	SigMetadata SignatureMetadata
	Msg         string
}

type SignatureEventSelector struct {
	Source string
	Name   string
	Origin string
}

type SignatureHandler func(found Finding)

type DataSource interface {
	// Get a value from the data source. Make sure the key matches one of the keys allowed in Keys.
	// The following errors should be returned for the appropriate cases:
	//
	//	- ErrDataNotFound - When the key does not match to any existing data
	//	- ErrKeyNotSupported - When the key used does not match to a support key
	//	- Otherwise errors may vary.
	Get(interface{}) (map[string]interface{}, error)
	// Version of the data fetched. Whenever the schema has a breaking change the version should be incremented.
	// Consumers of the data source should verify they are running against a support version before using it.
	Version() uint
	// The types of keys the data source supports.
	Keys() []string
	// JSON Schema of the data source's result. All Get results should conform to the schema described.
	Schema() string
	// Namespace of the data source (to avoid ID collisions)
	Namespace() string
	// ID of the data source, any unique name works.
	ID() string
}

type Logger interface {
	Debugw(format string, v ...interface{})
	Infow(format string, v ...interface{})
	Warnw(format string, v ...interface{})
	Errorw(format string, v ...interface{})
}

type SignatureContext struct {
	Callback      SignatureHandler
	Logger        Logger
	GetDataSource func(namespace string, id string) (DataSource, bool)
}

type Signal interface{}

type Signature interface {
	// GetMetadata allows the signature to declare information about itself
	GetMetadata() (SignatureMetadata, error)
	// GetSelectedEvents allows the signature to declare which events it subscribes to
	GetSelectedEvents() ([]SignatureEventSelector, error)
	// Init allows the signature to initialize its internal state
	Init(ctx SignatureContext) error
	// Close cleans the signature after Init operation
	Close()
	// OnEvent allows the signature to process events passed by the Engine. this is the business logic of the signature
	OnEvent(event protocol.Event) error
	// OnSignal allows the signature to handle lifecycle events of the signature
	OnSignal(signal Signal) error
}

type SignalSourceComplete string

var ErrDataNotFound = errors.New("requested data was not found")
var ErrKeyNotSupported = errors.New("queried key is not supported")
