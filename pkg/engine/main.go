/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package engine

import (
	"context"
	"eolh/pkg/detect"
	"eolh/pkg/logger"
	"eolh/pkg/protocol"
	"fmt"
	"sync"
)

const ALL_EVENT_ORIGINS = "*"
const EVENT_CONTAINER_ORIGIN = "container"
const EVENT_HOST_ORIGIN = "host"
const ALL_EVENT_TYPES = "*"

type Config struct {
	// Enables the signatures engine to run in the events pipeline
	Enabled             bool
	SignatureBufferSize uint
	Signatures          []detect.Signature
	DataSources         []detect.DataSource
}

type EventSources struct {
	Eolh chan protocol.Event
}

type Engine struct {
	signatures      map[detect.Signature]chan protocol.Event
	signaturesIndex map[detect.SignatureEventSelector][]detect.Signature
	signaturesMutex sync.RWMutex
	inputs          EventSources
	output          chan detect.Finding
	waitGroup       sync.WaitGroup
	config          Config
	//stats            Stats
	dataSources      map[string]map[string]detect.DataSource
	dataSourcesMutex sync.RWMutex
	logger           logger.Logger
}

func (engine *Engine) checkCompletion() bool {
	if engine.inputs.Eolh == nil {
		engine.unloadAllSignatures()
		engine.waitGroup.Wait()
		return true
	}
	return false
}

func (engine *Engine) RegisterDataSource(dataSource detect.DataSource) error {
	engine.dataSourcesMutex.Lock()
	defer engine.dataSourcesMutex.Unlock()

	namespace := dataSource.Namespace()
	id := dataSource.ID()

	if _, ok := engine.dataSources[namespace]; !ok {
		engine.dataSources[namespace] = map[string]detect.DataSource{}
	}

	_, exists := engine.dataSources[namespace][id]
	if exists {
		return fmt.Errorf("failed to register data source: data source with name \"%s\" already exists in namespace \"%s\"", id, namespace)
	}
	engine.dataSources[namespace][id] = dataSource
	return nil
}

// matchHandler is a function that runs when a signature is matched
func (engine *Engine) matchHandler(res detect.Finding) {
	engine.output <- res
}

func (engine *Engine) GetDataSource(namespace string, id string) (detect.DataSource, bool) {
	engine.dataSourcesMutex.RLock()
	defer engine.dataSourcesMutex.RUnlock()

	namespaceCaches, ok := engine.dataSources[namespace]
	if !ok {
		return nil, false
	}

	cache, ok := namespaceCaches[id]

	return cache, ok
}

// loadSignature handles storing a signature in the Engine data structures
// It will return the signature ID as well as error.
func (engine *Engine) loadSignature(signature detect.Signature) (string, error) {
	metadata, err := signature.GetMetadata()
	if err != nil {
		return "", fmt.Errorf("error getting metadata: %w", err)
	}
	selectedEvents, err := signature.GetSelectedEvents()
	if err != nil {
		return "", fmt.Errorf("error getting selected events for signature %s: %w", metadata.Name, err)
	}
	// insert in engine.signatures map
	engine.signaturesMutex.RLock()
	if engine.signatures[signature] != nil {
		engine.signaturesMutex.RUnlock()
		// signature already exists
		return "", fmt.Errorf("failed to store signature: signature \"%s\" already loaded", metadata.Name)
	}
	engine.signaturesMutex.RUnlock()
	signatureCtx := detect.SignatureContext{
		Callback: engine.matchHandler,
		Logger:   logger.Current(),
		GetDataSource: func(namespace, id string) (detect.DataSource, bool) {
			return engine.GetDataSource(namespace, id)
		},
	}
	if err := signature.Init(signatureCtx); err != nil {
		// failed to initialize
		return "", fmt.Errorf("error initializing signature %s: %w", metadata.Name, err)
	}
	c := make(chan protocol.Event, engine.config.SignatureBufferSize)
	engine.signaturesMutex.Lock()
	engine.signatures[signature] = c
	engine.signaturesMutex.Unlock()

	// insert in engine.signaturesIndex map
	for _, selectedEvent := range selectedEvents {
		if selectedEvent.Name == "" {
			selectedEvent.Name = ALL_EVENT_TYPES
		}
		if selectedEvent.Origin == "" {
			selectedEvent.Origin = ALL_EVENT_ORIGINS
		}
		if selectedEvent.Source == "" {
			logger.Errorw("Signature " + metadata.Name + " doesn't declare an input source")
		} else {
			engine.signaturesMutex.Lock()
			engine.signaturesIndex[selectedEvent] = append(engine.signaturesIndex[selectedEvent], signature)
			engine.signaturesMutex.Unlock()
		}
	}
	return metadata.ID, nil
}

// signatureStart is the signature handling business logics.
func signatureStart(signature detect.Signature, c chan protocol.Event, wg *sync.WaitGroup) {
	wg.Add(1)
	for e := range c {
		if err := signature.OnEvent(e); err != nil {
			meta, _ := signature.GetMetadata()
			logger.Errorw("Handling event by signature " + meta.Name + ": " + err.Error())
		}
	}
	wg.Done()
}

// LoadSignature will call the internal signature loading logic and activate its handling business logics.
// It will return the signature ID as well as error.
func (engine *Engine) LoadSignature(signature detect.Signature) (string, error) {
	id, err := engine.loadSignature(signature)
	if err != nil {
		return id, err
	}
	engine.signaturesMutex.RLock()
	go signatureStart(signature, engine.signatures[signature], &engine.waitGroup)
	engine.signaturesMutex.RUnlock()

	return id, nil
}

func NewEngine(config Config, sources EventSources, output chan detect.Finding) (*Engine, error) {
	if sources.Eolh == nil || output == nil {
		return nil, fmt.Errorf("nil input received")
	}
	engine := Engine{
		waitGroup: sync.WaitGroup{},
		inputs:    sources,
		output:    output,
		config:    config,
	}
	engine.signaturesMutex.Lock()
	engine.signatures = make(map[detect.Signature]chan protocol.Event)
	engine.signaturesIndex = make(map[detect.SignatureEventSelector][]detect.Signature)
	engine.signaturesMutex.Unlock()

	engine.dataSourcesMutex.Lock()
	engine.dataSources = map[string]map[string]detect.DataSource{}
	engine.dataSourcesMutex.Unlock()

	for _, datasource := range config.DataSources {
		err := engine.RegisterDataSource(datasource)
		if err != nil {
			logger.Errorw("Loading signatures data source: " + err.Error())
		}
	}
	for _, sig := range config.Signatures {
		_, err := engine.loadSignature(sig)
		if err != nil {
			logger.Errorw("Loading signature: " + err.Error())
		}
	}
	return &engine, nil
}

func (engine *Engine) Start(ctx context.Context) {
	defer engine.unloadAllSignatures()
	engine.signaturesMutex.RLock()
	for s, c := range engine.signatures {
		engine.waitGroup.Add(1)
		go signatureStart(s, c, &engine.waitGroup)
	}
	engine.signaturesMutex.RUnlock()
	engine.consumeSources(ctx)
}

func (engine *Engine) consumeSources(ctx context.Context) {
	for {
		select {
		case event, ok := <-engine.inputs.Eolh:
			if !ok {
				engine.signaturesMutex.RLock()
				for sig := range engine.signatures {
					se, err := sig.GetSelectedEvents()
					if err != nil {
						engine.logger.Errorw("Getting selected events: " + err.Error())
						continue
					}
					for _, sel := range se {
						if sel.Source == "eolh" {
							_ = sig.OnSignal(detect.SignalSourceComplete("eolh"))
							break
						}
					}
				}
				engine.signaturesMutex.RUnlock()
				engine.inputs.Eolh = nil
				if engine.checkCompletion() {
					return
				}

				continue
			}
			engine.processEvent(event)

		case <-ctx.Done():
			goto drain
		}
	}

drain:
	// drain and process all remaining events
	for {
		select {
		case event := <-engine.inputs.Eolh:
			engine.processEvent(event)

		default:
			return
		}
	}
}

func (engine *Engine) unloadAllSignatures() {
	engine.signaturesMutex.Lock()
	defer engine.signaturesMutex.Unlock()
	for sig, c := range engine.signatures {
		sig.Close()
		close(c)
		delete(engine.signatures, sig)
	}
	engine.signaturesIndex = make(map[detect.SignatureEventSelector][]detect.Signature)
}

func (engine *Engine) dispatchEvent(s detect.Signature, event protocol.Event) {
	engine.signatures[s] <- event
}

func (engine *Engine) processEvent(event protocol.Event) {
	engine.signaturesMutex.RLock()
	defer engine.signaturesMutex.RUnlock()
	signatureSelector := detect.SignatureEventSelector{
		Source: event.Headers.Selector.Source,
		Name:   event.Headers.Selector.Name,
		Origin: event.Headers.Selector.Origin,
	}

	// Check the selector for every case and partial case

	// Match full selector
	for _, s := range engine.signaturesIndex[signatureSelector] {
		engine.dispatchEvent(s, event)
	}

	// Match partial selector, select for all origins
	partialSigEvtSelector := detect.SignatureEventSelector{
		Source: signatureSelector.Source,
		Name:   signatureSelector.Name,
		Origin: ALL_EVENT_ORIGINS,
	}
	for _, s := range engine.signaturesIndex[partialSigEvtSelector] {
		engine.dispatchEvent(s, event)
	}

	// Match partial selector, select for event names
	partialSigEvtSelector = detect.SignatureEventSelector{
		Source: signatureSelector.Source,
		Name:   ALL_EVENT_TYPES,
		Origin: signatureSelector.Origin,
	}
	for _, s := range engine.signaturesIndex[partialSigEvtSelector] {
		engine.dispatchEvent(s, event)
	}

	// Match partial selector, select for all origins and event names
	partialSigEvtSelector = detect.SignatureEventSelector{
		Source: signatureSelector.Source,
		Name:   ALL_EVENT_TYPES,
		Origin: ALL_EVENT_ORIGINS,
	}
	for _, s := range engine.signaturesIndex[partialSigEvtSelector] {
		engine.dispatchEvent(s, event)
	}
}
