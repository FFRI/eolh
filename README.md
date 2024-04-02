# EOLH: Bring Security Observability to Windows Containers

Eolh is a security observability tool for Windows containers.

Currently Eolh is only tested on EKS.

See [the documentation](https://ffri.github.io/eolh-docs/) for details.

## Acknowledgment & LICENSE

Eolh is heavily based on [Tracee's code base (v0.16.0)](https://github.com/aquasecurity/tracee). Codes without our copyright notice are copyrighted by Aqua Security Software Ltd.

Tracee is licensed under the Apache License 2.0, so we provide the Tracee's license file and NOTICE file as `LICENSE.tracee` and `NOTICE` respectively.

The changes from Tracee are follows:
- Removed eBPF-related functionalities.
- Added ETW-related functionalities.
- Removed Linux-related functionalities.
- Added Windows-related functionalities.
- Simplified some functionalities.

<details>

<summary>Further details of the changes per files</summary>

### Removed 
- [GitHub Workflows](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/.github)
- [3rdparty](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/3rdparty)
- [brand](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/brand)
- [builder](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/builder)
- [deploy](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/deploy)
- [docs](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/docs)
- [examples](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/examples)
- [packaging](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/packaging)
- [pyroscope](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/performance/pyroscope)
- [signatures](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/signatures)
- [tests](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/tests)
- [types](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/types)
- [.clang-format](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/.clang-format)
- [.clang-tidy](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/.clang-tidy)
- [.dockerignore](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/.dockerignore)
- [.gitmodules](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/.gitmodules)
- [.revive.toml](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/.revive.toml)
- [Makefile](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/Makefile)
- [RELEASING.md](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/RELEASING.md)
- [Vagrantfile](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/Vagrantfile)
- [embedded-ebpf.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/embedded-ebpf.go)
- [embedded.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/embedded.go)
- [mkdocs.yml](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/mkdocs.yml)
- [staticcheck.conf](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/staticcheck.conf)
- [cmd/tracee/cmd/analyze.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/cmd/tracee/cmd/analyze.go)
- [cmd/tracee/cmd/list.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/cmd/tracee/cmd/list.go)
- [cmd/tracee-bench](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/cmd/tracee-bench)
- [cmd/tracee-gptdocs](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/cmd/tracee-gptdocs)
- [cmd/tracee-rules](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/cmd/tracee-rules)
- [pkg/bucketscache](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/bucketscache)
- [pkg/bufferdecoder](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/bufferdecoder)
- [pkg/capabilities](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/capabilities)
- [pkg/cgroup](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cgroup)
- [pkg/cmd/cobra/helper.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/cobra/helper.go)
- [pkg/cmd/cobra/helper_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/cobra/helper_test.go)
- [pkg/cmd/flags/server](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/server)
- [pkg/cmd/flags/cache](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/cache.go)
- [pkg/cmd/flags/capabilities.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/capabilities.go)
- [pkg/cmd/flags/capture.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/capture.go)
- [pkg/cmd/flags/config.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/config.go)
- [pkg/cmd/flags/containers.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/containers.go)
- [pkg/cmd/flags/errors.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/errors.go)
- [pkg/cmd/flags/filter.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/filter.go)
- [pkg/cmd/flags/filter_map.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/filter_map.go)
- [pkg/cmd/flags/filter_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/filter_test.go)
- [pkg/cmd/flags/flags_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/flags_test.go)
- [pkg/cmd/flags/help.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/help.go)
- [pkg/cmd/flags/logger.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/logger.go)
- [pkg/cmd/flags/logger_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/logger_test.go)
- [pkg/cmd/flags/policy.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/policy.go)
- [pkg/cmd/flags/policy_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/policy_test.go)
- [pkg/cmd/flags/rego.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/rego.go)
- [pkg/cmd/flags/tracee_ebpf_output.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/tracee_ebpf_output.go)
- [pkg/cmd/initialize](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/initialize)
- [pkg/cmd/printer/benchmarks](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/printer/benchmarks)
- [pkg/cmd/printer/policy.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/printer/policy.go)
- [pkg/cmd/printer/printer_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/printer/printer_test.go)
- [pkg/cmd/urfave](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/urfave)
- [pkg/cmd/gptdocs.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/gptdocs.go)
- [pkg/cmd/tracee_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/tracee_test.go)
- [pkg/config](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/config)
- [pkg/containers/runtime/crio.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/containers/runtime/crio.go)
- [pkg/containers/runtime/docker.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/containers/runtime/docker.go)
- [pkg/containers/path_resolver.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/containers/path_resolver.go)
- [pkg/containers/path_resolver_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/containers/path_resolver_test.go)
- [pkg/counter](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/counter)
- [pkg/ebpf/c](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/c)
- [pkg/ebpf/controlplane](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/controlplane)
- [pkg/ebpf/initialization](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/initialization)
- [pkg/ebpf/probes](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/probes)
- [pkg/ebpf/bpf_log.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/bpf_log.go)
- [pkg/ebpf/capture.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/capture.go)
- [pkg/ebpf/events_enrich.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/events_enrich.go)
- [pkg/ebpf/finding_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/finding_test.go)
- [pkg/ebpf/hidden_kernel_module.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/hidden_kernel_module.go)
- [pkg/ebpf/ksymbols.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/ksymbols.go)
- [pkg/ebpf/net_capture.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/net_capture.go)
- [pkg/ebpf/tracee_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/tracee_test.go)
- [pkg/ebpf/errfmt](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/errfmt)
- [pkg/events/derive](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/events/derive)
- [pkg/events/parse](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/events/parse)
- [pkg/events/queue](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/events/queue)
- [pkg/events/sorting](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/events/sorting)
- [pkg/events/trigger](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/events/trigger)
- [pkg/events/amd64.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/events/amd64.go)
- [pkg/events/arm64.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/events/arm64.go)
- [pkg/events/events_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/events/events_test.go)
- [pkg/events/parse_args.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/events/parse_args.go)
- [pkg/events/parse_args_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/events/parse_args_test.go)
- [pkg/events/usermode.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/events/usermode.go)
- [pkg/filters](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/filters)
- [pkg/metrics](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/metrics)
- [pkg/mount](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/mount)
- [pkg/pcaps](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/pcaps)
- [pkg/policy](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/policy)
- [pkg/server](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/server)
- [pkg/signatures/benchmark](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/benchmark)
- [pkg/signatures/celsig](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/celsig)
- [pkg/signatures/metrics](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/metrics)
- [pkg/signatures/rego](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/rego)
- [pkg/signatures/regosig/testdata](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/regosig/testdata)
- [pkg/signatures/regosig/aio.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/regosig/aio.go)
- [pkg/signatures/regosig/aio.rego](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/regosig/aio.rego)
- [pkg/signatures/regosig/aio_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/regosig/aio_test.go)
- [pkg/signatures/regosig/common_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/regosig/common_test.go)
- [pkg/signatures/regosig/mapper.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/regosig/mapper.go)
- [pkg/signatures/regosig/mapper_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/regosig/mapper_test.go)
- [pkg/signatures/regosig/traceerego_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/regosig/traceerego_test.go)
- [pkg/utils](https://github.com/aquasecurity/tracee/tree/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/utils)
- [types/detect/detect_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/types/detect/detect_test.go)
- [types/trace/network_trace.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/types/trace/network_trace.go)
- [types/trace/network_trace_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/types/trace/network_trace_test.go)
- [types/trace/trace_test.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/types/trace/trace_test.go)

### Add
- pkg/cmd/flags/etw.go
  - ETW Provider Flags
- diff.patch
  - A patch file for golang-etw
- Dockerfile
  - Dockerfile for Eolh
- LICENSE
  - Eolh's LICENSE

### Changed
- [Readme.md](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/Readme.md)
  - Renamed to README.md
  - Changed to description of Eolh
- [cmd/tracee/main.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/cmd/tracee/main.go)
  - Renamed to cmd/main.go and added error handling
- [cmd/tracee/cmd/root.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/cmd/tracee/cmd/root.go)
  - Renamed to cmd/cmd/root.go
  - Changed cli flags
  - Changed so that `Execute` function returns an error
- [cmd/tracee/cmd/version.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/cmd/tracee/cmd/version.go)
  - Renamed to cmd/cmd/version.go
  - Changed so that the version command will print Eolh's version
- [pkg/cmd/cobra/cobra.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/cobra/cobra.go)
  - Renamed to pkg/cmd/cobra/main.go
  - Changed so that it provides `GetEolhRunner` function instead of `GetTraceeRunner`
- [pkg/cmd/flags/output.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/flags/output.go)
  - Remove functions except output and printer flags
- [pkg/cmd/flags/printer/broadcast.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/printer/broadcast.go)
  - Remove `Epilogue`
- [pkg/cmd/flags/printer/printer.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/printer/printer.go)
  - Remove `Epilogue`
- [pkg/cmd/tracee.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/cmd/tracee.go)
  - Renamed to pkg/cmd/main.go
  - Changed `Run` function for Eolh.
  - Removed functions not used by Eolh.
- [pkg/containers/runtime/containerd.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/containers/runtime/containerd.go)
  - Changed to use Windows named pipes for communication with containerd
  - Changed to use session identifiers
- [pkg/containers/runtime/runtime.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/containers/runtime/runtime.go)
  - Removed crio and podman support
- [pkg/containers/runtime/sockets.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/containers/runtime/sockets.go)
  - Removed docker, crio and podman support
  - Use a named pipe to communicate with containerd
- [pkg/containers/containers.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/containers/containers.go) and [pkg/containers/datasource.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/containers/datasource.go)
  - Merged into pkg/containers/main.go
  - Removed cgroup-related and eBPF-related functions
- [pkg/containers/service.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/containers/service.go)
  - Added `Populate` function
- [pkg/ebpf/events_pipeline.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/events_pipeline.go) and [pkg/epbf/events_processor.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/events_processor.go)
  - Merged into pkg/etw/events_pipeline.go
  - Removed some functions
- [pkg/ebpf/finding.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/finding.go)
  - Renamed to pkg/etw/main.go
  - Removed some functions
- [pkg/ebpf/signature_engine.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/signature_engine.go)
  - Renamed to pkg/etw/engine.go
  - Removed the metrics-related process
- [pkg/ebpf/tracee.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/ebpf/tracee.go)
  - Renamed to pkg/etw/eolh.go
  - Removed some functions
  - Use ETW instead of eBPF
- [pkg/events/events.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/events/events.go)
  - Removed all functions, constants and types except `ID` and `Event`
- [pkg/logger/callerinfo.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/logger/callerinfo.go)
  - Rename traceeIndex to eolhIndex
- [pkg/signatures/regosig/traceerego.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/regosig/traceerego.go)
  - Renamed to pkg/signatures/regosig/eolhrego.go
  - Replace `tracee_*` to `eolh_*`
- [pkg/signatures/signature/signature.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/pkg/signatures/signature/signature.go)
  - Renamed to pkg/signatures/signature.go
  - Removed the plugin system (because the plugin system dose not work on Windows)
  - Removed some functions
- [types/detect/detect.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/types/detect/detect.go)
  - Renamed to pkg/detect/main.go
  - The import path was modified to match Eolh
- [types/protocol/protocol.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/types/protocol/protocol.go)
  - Renamed to pkg/protocol/main.go
  - Removed some functions
- [types/trace/trace.go](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/types/trace/trace.go)
  - Renamed to pkg/trace/main.go
  - Removed some functions
- [.gitignore](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/.gitignore)
  - The subject item was updated to match Eolh.
- [LICENSE](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/LICENSE)
  - Renamed to LICENSE.tracee
- [go.mod](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/go.mod)
  - Updated dependencies
- [go.sum](https://github.com/aquasecurity/tracee/blob/63d54191bae5cce218ee30df4ca6e778dd11a502/go.sum)
  - Updated dependencies
</details>