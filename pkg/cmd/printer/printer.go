/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/
package printer

import (
	"bytes"
	"encoding/json"
	"eolh/pkg/logger"
	"eolh/pkg/trace"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	forward "github.com/IBM/fluent-forward-go/fluent/client"
)

type EventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	// Epilogue(stats metrics.Stats)
	// Print prints a single event
	Print(event trace.Event)
	// dispose of resources
	Close()
}

type jsonEventPrinter struct {
	out    io.WriteCloser
	logger logger.Logger
}

func New(cfg PrinterConfig) (EventPrinter, error) {
	var res EventPrinter
	kind := cfg.Kind

	if cfg.OutFile == nil {
		return res, fmt.Errorf("out file is not set")
	}

	switch {
	case kind == "json":
		res = &jsonEventPrinter{
			out: cfg.OutFile,
		}
	case kind == "forward":
		res = &forwardEventPrinter{
			outPath: cfg.OutPath,
		}
	case kind == "webhook":
		res = &webhookEventPrinter{
			outPath: cfg.OutPath,
		}
	}
	err := res.Init()
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (p jsonEventPrinter) Init() error { return nil }

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(event trace.Event) {
	eBytes, err := json.Marshal(event)
	if err != nil {
		p.logger.Errorw("Error marshaling event to json", "error", err)
	}
	fmt.Fprintln(p.out, string(eBytes))
}

func (p jsonEventPrinter) Close() {
}

type webhookEventPrinter struct {
	outPath string
	url     *url.URL
	timeout time.Duration
}

func getParameterValue(parameters url.Values, key string, defaultValue string) string {
	param, found := parameters[key]
	// Ensure we have a non-empty parameter set for this key
	if found && param[0] != "" {
		return param[0]
	}
	// Otherwise use the default value
	return defaultValue
}

func (ws *webhookEventPrinter) Init() error {
	u, err := url.Parse(ws.outPath)
	if err != nil {
		return fmt.Errorf("unable to parse URL %q: %v", ws.outPath, err)
	}
	ws.url = u

	parameters, _ := url.ParseQuery(ws.url.RawQuery)

	timeout := getParameterValue(parameters, "timeout", "10s")
	t, err := time.ParseDuration(timeout)
	if err != nil {
		return fmt.Errorf("unable to convert timeout value %q: %v", timeout, err)
	}
	ws.timeout = t

	return nil
}

func (ws *webhookEventPrinter) Preamble() {}

func (ws *webhookEventPrinter) Print(event trace.Event) {
	payload, err := json.Marshal(event)
	if err != nil {
		logger.Errorw("Error marshalling event", "error", err)
		return
	}

	client := http.Client{Timeout: ws.timeout}

	req, err := http.NewRequest(http.MethodPost, ws.url.String(), bytes.NewReader(payload))
	if err != nil {
		logger.Errorw("Error creating request", "error", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logger.Errorw("Error sending webhook", "error", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		logger.Errorw(fmt.Sprintf("Error sending webhook, http status: %d", resp.StatusCode))
	}

	_ = resp.Body.Close()
}

//func (ws *webhookEventPrinter) Epilogue(stats metrics.Stats) {}

func (ws *webhookEventPrinter) Close() {
}

type forwardEventPrinter struct {
	outPath string
	url     *url.URL
	client  *forward.Client
	// These parameters can be set up from the URL
	tag string `default:"eolh"`
}

func (p *forwardEventPrinter) Init() error {
	// Now parse the optional parameters with defaults and some basic verification
	u, err := url.Parse(p.outPath)
	if err != nil {
		return fmt.Errorf("unable to parse URL %q: %w", p.url, err)
	}
	p.url = u

	parameters, _ := url.ParseQuery(p.url.RawQuery)

	// Check if we have a tag set or default it
	p.tag = getParameterValue(parameters, "tag", "eolh")

	// Do we want to enable requireAck?
	requireAckString := getParameterValue(parameters, "requireAck", "false")
	requireAck, err := strconv.ParseBool(requireAckString)
	if err != nil {
		return fmt.Errorf("unable to convert requireAck value %q: %v", requireAckString, err)
	}

	// Timeout conversion from string
	timeoutValueString := getParameterValue(parameters, "connectionTimeout", "10s")
	connectionTimeout, err := time.ParseDuration(timeoutValueString)
	if err != nil {
		return fmt.Errorf("unable to convert connectionTimeout value %q: %v", timeoutValueString, err)
	}

	// We should have both username and password or neither for basic auth
	username := p.url.User.Username()
	password, isPasswordSet := p.url.User.Password()
	if username != "" && !isPasswordSet {
		return fmt.Errorf("missing basic auth configuration for Forward destination")
	}

	// Ensure we support tcp or udp protocols
	protocol := "tcp"
	if p.url.Scheme != "" {
		protocol = p.url.Scheme
	}
	if protocol != "tcp" && protocol != "udp" {
		return fmt.Errorf("unsupported protocol for Forward destination: %s", protocol)
	}

	// Extract the host (and port)
	address := p.url.Host
	logger.Infow("Attempting to connect to Forward destination", "url", address, "tag", p.tag)

	// Create a TCP connection to the forward receiver
	p.client = forward.New(forward.ConnectionOptions{
		Factory: &forward.ConnFactory{
			Network: protocol,
			Address: address,
		},
		RequireAck:        requireAck,
		ConnectionTimeout: connectionTimeout,
		AuthInfo: forward.AuthInfo{
			Username: username,
			Password: password,
		},
	})

	err = p.client.Connect()
	if err != nil {
		// The destination may not be available but may appear later so do not return an error here and just connect later.
		logger.Errorw("Error connecting to Forward destination", "url", p.url.String(), "error", err)
	}
	return nil
}

func (p *forwardEventPrinter) Preamble() {}

func (p *forwardEventPrinter) Print(event trace.Event) {
	if p.client == nil {
		logger.Errorw("Invalid Forward client")
		return
	}

	// The actual event is marshalled as JSON then sent with the other information (tag, etc.)
	eBytes, err := json.Marshal(event)
	if err != nil {
		logger.Errorw("Error marshaling event to json", "error", err)
	}

	record := map[string]interface{}{
		"event": string(eBytes),
	}

	err = p.client.SendMessage(p.tag, record)
	// Assuming all is well we continue but if the connection is dropped or some other error we retry
	if err != nil {
		logger.Errorw("Error writing to Forward destination", "destination", p.url.Host, "tag", p.tag, "error", err)
		// Try five times to reconnect and send before giving up
		// TODO: consider using go-kit for circuit break, retry, etc
		for attempts := 0; attempts < 5; attempts++ {
			// Attempt to reconnect (remote end may have dropped/restarted)
			err = p.client.Reconnect()
			if err == nil {
				// Re-attempt to send
				err = p.client.SendMessage(p.tag, record)
				if err == nil {
					break
				}
			}
		}
	}
}

// func (p *forwardEventPrinter) Epilogue(stats metrics.Stats) {}

func (p forwardEventPrinter) Close() {
	if p.client != nil {
		logger.Infow("Disconnecting from Forward destination", "url", p.url.Host, "tag", p.tag)
		if err := p.client.Disconnect(); err != nil {
			logger.Errorw("Disconnecting from Forward destination", "error", err)
		}
	}
}
