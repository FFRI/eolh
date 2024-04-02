/*
Copyright (c) Aqua Security Software Ltd.
Licensed under Apache License 2.0, see LICENCE.tracee and NOTICE.

Copyright (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
Licensed under Apache License 2.0, see LICENCE.
*/

package runtime

import (
	"context"
	"encoding/json"
	"eolh/pkg/logger"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	winio "github.com/Microsoft/go-winio"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/namespaces"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const defaultTimeoutWindows = 200 * time.Second

type containerdEnricher struct {
	containers containers.Store
	images     cri.ImageServiceClient
	namespaces namespaces.Store
	client     *containerd.Client
	service    cri.RuntimeServiceClient
}

const (
	tcpProtocol   = "tcp"
	npipeProtocol = "npipe"

	maxMsgSize = 1024 * 1024 * 16
)

func tcpDial(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, tcpProtocol, addr)
}

func npipeDial(ctx context.Context, addr string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, addr)
}

func parseEndpoint(endpoint string) (string, string, error) {
	// url.Parse doesn't recognize \, so replace with / first.
	endpoint = strings.Replace(endpoint, "\\", "/", -1)
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", err
	}

	if u.Scheme == "tcp" {
		return "tcp", u.Host, nil
	} else if u.Scheme == "npipe" {
		if strings.HasPrefix(u.Path, "//./pipe") {
			return "npipe", u.Path, nil
		}

		// fallback host if not provided.
		host := u.Host
		if host == "" {
			host = "."
		}
		return "npipe", fmt.Sprintf("//%s%s", host, u.Path), nil
	} else if u.Scheme == "" {
		return "", "", fmt.Errorf("Using %q as endpoint is deprecated, please consider using full url format", endpoint)
	} else {
		return u.Scheme, "", fmt.Errorf("protocol %q not supported", u.Scheme)
	}
}

func GetAddressAndDialer(endpoint string) (string, func(ctx context.Context, addr string) (net.Conn, error), error) {
	protocol, addr, err := parseEndpoint(endpoint)
	if err != nil {
		return "", nil, err
	}

	if protocol == tcpProtocol {
		return addr, tcpDial, nil
	}

	if protocol == npipeProtocol {
		return addr, npipeDial, nil
	}

	return "", nil, fmt.Errorf("only support tcp and npipe endpoint")
}

func ContainerdEnricher(socket string) (ContainerEnricher, error) {
	enricher := containerdEnricher{}

	client, err := containerd.New(socket)
	if err != nil {
		return nil, err
	}
	socket_npipe := "npipe://./pipe/containerd-containerd"
	addr, dialer, err := GetAddressAndDialer(socket_npipe)
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(dialer), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize)))
	if err != nil {
		if errC := client.Close(); errC != nil {
			logger.Errorw("Closing containerd connection", "error", errC)
		}
		return nil, err
	}
	enricher.images = cri.NewImageServiceClient(conn)
	enricher.containers = client.ContainerService()
	enricher.namespaces = client.NamespaceService()
	enricher.client = client
	enricher.service = cri.NewRuntimeServiceClient(conn)
	return &enricher, nil
}

func (e *containerdEnricher) Get(ctx context.Context, containerId string) (ContainerMetadata, error) {
	metadata := ContainerMetadata{
		ContainerId: containerId,
	}
	nsList, err := e.namespaces.List(ctx)
	if err != nil {
		return metadata, fmt.Errorf("failed to fetch namespaces %s", err.Error())
	}
	for _, namespace := range nsList {
		nsCtx := namespaces.WithNamespace(ctx, namespace)

		// if containers is not in current namespace, search the next one
		container, err := e.containers.Get(nsCtx, containerId)
		if err != nil {
			continue
		}

		imageName := container.Image
		imageDigest := container.Image
		image := container.Image
		// DO Check!!
		_, err1 := e.images.ImageStatus(ctx, &cri.ImageStatusRequest{
			Image: &cri.ImageSpec{
				Image: image,
			},
		})

		if err1 != nil {
			logger.Debugw("ImageStatus Error", "error", err1.Error())
		}
		// container may not have image name as id, if so fetch from the sha256 id
		if strings.HasPrefix(image, "sha256:") {
			imageInfo, err := e.images.ImageStatus(ctx, &cri.ImageStatusRequest{
				Image: &cri.ImageSpec{
					Image: strings.TrimPrefix(image, "sha256:"),
				},
			})
			if err != nil {
				logger.Infow("SHA256err %v", err.Error())
				imageName = image
				imageDigest = image
			} else {
				if len(imageInfo.Image.RepoTags) > 0 {
					imageName = imageInfo.Image.RepoTags[0]
				}
				if len(imageInfo.Image.RepoDigests) > 0 {
					imageDigest = imageInfo.Image.RepoTags[0]
				}
			}
		}

		// if in k8s we can extract pod info from labels
		if container.Labels != nil {
			labels := container.Labels

			metadata.Pod = PodMetadata{
				Name:      labels[PodNameLabel],
				Namespace: labels[PodNamespaceLabel],
				UID:       labels[PodUIDLabel],
				Sandbox:   e.isSandbox(labels),
			}

			// containerd containers normally have no names unless set from k8s
			metadata.Name = labels[ContainerNameLabel]
		}
		metadata.Image = imageName
		metadata.ImageDigest = imageDigest

		return metadata, nil
	}

	return metadata, fmt.Errorf("failed to find container in any namespace")
}

func (e *containerdEnricher) isSandbox(labels map[string]string) bool {
	return labels[ContainerTypeContainerdLabel] == "sandbox"
}

func (e *containerdEnricher) FindContainer(procid int32) string {
	processSI, _ := GetSIOfProcess(procid)
	containers, _ := e.client.Containers(context.Background())
	for _, c := range containers {
		res, _ := e.service.ContainerStatus(context.Background(), &cri.ContainerStatusRequest{
			ContainerId: c.ID(),
		})
		pid := res.Info["pid"]
		num, _ := strconv.ParseUint(pid, 10, 64)
		num32 := int32(num)
		containerSi, _ := GetSIOfProcess(num32)
		if processSI == containerSi {
			return c.ID()
		}
	}
	return ""
}

type Info struct {
	Pid int `json:"pid"`
}

func (e *containerdEnricher) Populate() (map[uint32]CRInfo, error) {
	crMap := make(map[uint32]CRInfo)
	res, err := e.service.ListContainers(namespaces.WithNamespace(context.Background(), "k8s.io"), &cri.ListContainersRequest{})
	if err != nil {
		logger.Debugw("ListContainersError", "error", err.Error())
	}
	for _, c := range res.Containers {
		metadata := ContainerMetadata{
			ContainerId: c.Id,
			Name:        c.Metadata.Name,
		}
		imageName := c.Image.Image
		imageDigest := c.Image.Image
		image := c.Image.Image
		if strings.HasPrefix(image, "sha256:") {
			imageInfo, err := e.images.ImageStatus(context.Background(), &cri.ImageStatusRequest{
				Image: &cri.ImageSpec{
					Image: strings.TrimPrefix(image, "sha256:"),
				},
			})
			if err != nil {
				logger.Infow("SHA256err %v", err.Error())
				imageName = image
				imageDigest = image
			} else {
				if len(imageInfo.Image.RepoTags) > 0 {
					imageName = imageInfo.Image.RepoTags[0]
				}
				if len(imageInfo.Image.RepoDigests) > 0 {
					imageDigest = imageInfo.Image.RepoTags[0]
				}
			}
		}
		if c.Labels != nil {
			labels := c.Labels
			metadata.Pod = PodMetadata{
				Name:      labels[PodNameLabel],
				Namespace: labels[PodNamespaceLabel],
				UID:       labels[PodUIDLabel],
				Sandbox:   e.isSandbox(labels),
			}

			// containerd containers normally have no names unless set from k8s
			metadata.Name = labels[ContainerNameLabel]
		}
		metadata.Image = imageName
		metadata.ImageDigest = imageDigest

		res, err := e.service.ContainerStatus(namespaces.WithNamespace(context.Background(), "k8s.io"), &cri.ContainerStatusRequest{
			ContainerId: c.Id,
			Verbose:     true,
		})
		if err != nil {
			// Maybe Exited
			logger.Errorw(err.Error())
			continue
		}
		if res.Status.State == cri.ContainerState_CONTAINER_CREATED {
			continue
		}
		var jsonObj Info
		_ = json.Unmarshal([]byte(res.Info["info"]), &jsonObj)
		pid := jsonObj.Pid
		if err != nil {
			logger.Errorw(err.Error())
			continue
		}
		si, err := GetSIOfProcess(int32(pid))
		if err != nil {

			continue
		}

		crMap[si] = CRInfo{
			Container: metadata,
			Runtime:   FromString("containerd"),
			ProcessID: int(pid),
		}
	}

	return crMap, nil
}

type CRInfo struct {
	Container ContainerMetadata
	Runtime   RuntimeId
	ProcessID int
}

func GetSIOfProcess(procid int32) (uint32, error) {
	var sessionID uint32
	err := windows.ProcessIdToSessionId(uint32(procid), &sessionID)

	if err != nil {
		return 0, err
	}
	return sessionID, nil
}
