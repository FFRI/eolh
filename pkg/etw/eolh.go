/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package etw

import (
	"context"
	"eolh/pkg/containers"
	"eolh/pkg/engine"
	"eolh/pkg/events"
	"eolh/pkg/trace"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/Microsoft/go-winio/pkg/process"
	goprocess "github.com/shirou/gopsutil/v3/process"
	getw "local.packages/golang-etw/etw"
)

type eventConfig struct {
	submit uint64
	emit   uint64
}

type Eolh struct {
	session            *getw.RealTimeSession
	sigEngine          *engine.Engine
	events             map[events.ID]eventConfig
	eventsChannel      chan getw.Event
	eventProcessor     map[events.ID][]func(evt *trace.Event) error
	config             Config
	containers         *containers.Containers
	running            atomic.Bool
	done               chan struct{}
	eventsPool         *sync.Pool
	pid                int
	runtimePid         uint32
	runtimeContainerID string
	kubeletPid         uint32
	defenderPid        uint32
}

func New(cfg Config) *Eolh {
	eolh := &Eolh{
		session: getw.NewRealTimeSession("EolhEtw"),
		config:  cfg,
		done:    make(chan struct{}),
		pid:     os.Getpid(),
	}

	eolh.registerEventProcessors()
	return eolh
}

func (e *Eolh) Init() error {
	// Exclude noisy benign host processes.
	// TODO: Refactor me
	containerdProcess := make([]*goprocess.Process, 0)
	kubeletProcess := make([]*goprocess.Process, 0) // Prevent Infinite Loop
	defenderProcess := make([]*goprocess.Process, 0)
	processList, _ := process.EnumProcesses()
	for _, p := range processList {
		np, _ := goprocess.NewProcess(int32(p))
		name, _ := np.Name()
		if name == "containerd.exe" {
			containerdProcess = append(containerdProcess, np)
		}
		if name == "kubelet.exe" {
			kubeletProcess = append(kubeletProcess, np)
		}
		if name == "MsMpEng.exe" {
			defenderProcess = append(defenderProcess, np)
		}
	}
	if len(containerdProcess) != 1 {
		return fmt.Errorf("Error: containerd.exe")
	}
	if len(kubeletProcess) != 1 {
		return fmt.Errorf("Error: kubelet.exe")
	}
	if len(defenderProcess) != 1 {
		return fmt.Errorf("Error: MsMpEng.exe")
	}
	e.runtimePid = uint32(containerdProcess[0].Pid)
	e.kubeletPid = uint32(kubeletProcess[0].Pid)
	e.defenderPid = uint32(defenderProcess[0].Pid)

	c, _ := containers.New(e.config.Sockets)
	e.containers = c
	if err := e.containers.Populate(); err != nil {
		return fmt.Errorf("error initializing containers: %v", err)
	}
	metadata, err := e.containers.Enrich(int(e.runtimePid))
	if err != nil {
		return fmt.Errorf("error initializeing enrich: %v", err)
	}
	e.runtimeContainerID = metadata.ContainerId
	e.eventsChannel = make(chan getw.Event, 1000)
	e.eventsPool = &sync.Pool{
		New: func() interface{} {
			return &trace.Event{}
		},
	}
	for _, p := range e.config.Providers {
		if err := e.session.EnableProvider(getw.MustParseProvider(p)); err != nil {
			return err
		}
	}
	return nil
}

func (e *Eolh) Run(ctx context.Context) error {
	defer e.Close()
	c := getw.NewRealTimeConsumer(ctx)
	defer c.Stop()

	c.FromSessions(e.session)
	go func() {
		for ee := range c.Events {
			e.eventsChannel <- *ee
		}
	}()
	go e.handleEvents(ctx)
	if err := c.Start(); err != nil {
		return err
	}
	e.running.Store(true)
	<-ctx.Done()
	e.Close()
	if c.Err() != nil {
		return c.Err()
	}
	return nil
}

func (e *Eolh) Close() {
	if e.session != nil {
		e.session.Stop()
		e.session.DisableAllProviders()
	}
	e.running.Store(false)
	close(e.done)
}
