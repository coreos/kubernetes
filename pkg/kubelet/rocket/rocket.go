/*
Copyright 2014 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rocket

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/coreos/go-systemd/dbus"
	"github.com/coreos/go-systemd/unit"
	"github.com/golang/glog"
)

var (
	tmpDirPath = "/tmp"
)

type RocketRuntime struct {
	systemd  *dbus.Conn
	endpoint string
}

func NewRocketRuntime(endpoint string) (*RocketRuntime, error) {
	systemd, err := dbus.New()
	if err != nil {
		return nil, err
	}
	return &RocketRuntime{
		systemd:  systemd,
		endpoint: endpoint,
	}, nil
}

func (r *RocketRuntime) runCommand(stdout bool, subCommand string, args ...string) ([]byte, error) {
	glog.V(4).Info("run command:", subCommand, args)
	var allArgs []string
	allArgs = append(allArgs, subCommand)
	allArgs = append(allArgs, args...)
	cmd := exec.Command(r.endpoint, allArgs...)
	if !stdout {
		return nil, cmd.Start()
	}
	return cmd.Output()
}

func (r *RocketRuntime) constructRunCmd(uuid string) string {
	return fmt.Sprintf("%s %s %s", r.endpoint, "run-prepared", uuid)
}

func (r *RocketRuntime) podToUnits(pod *api.BoundPod) ([]*unit.UnitOption, error) {
	b, err := json.Marshal(pod)
	if err != nil {
		return nil, err
	}

	units := []*unit.UnitOption{
		{
			Section: "Unit",
			Name:    "Description",
			Value:   "k8s_rocket_pod",
		},

		{
			Section: "Install",
			Name:    "WantedBy",
			Value:   "multi-user.target", // TODO(yifan): Hardcode.
		},
		{
			Section: "X-K8S",
			Name:    "POD",
			Value:   string(b),
		},
	}
	return units, nil
}

type PodStatus struct {
	State string
}

func (r *RocketRuntime) getPodsStatus() (map[string]*PodStatus, error) {
	status := make(map[string]*PodStatus)
	output, err := r.runCommand(true, "list", "--no-legend")
	glog.V(4).Infof("list output: %s", string(output))
	if err != nil {
		return nil, err
	}

	if len(output) == 0 { // No containers running.
		return nil, nil
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		tuples := strings.Split(strings.TrimSpace(line), "\t")
		if len(tuples) != 3 { // HARDCODE, non state line.
			continue
		}
		status[tuples[0]] = &PodStatus{
			State: tuples[2],
		}
	}
	return status, nil
}

func (r *RocketRuntime) unitFileToPod(fname string) (*api.Pod, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pod api.Pod
	opts, err := unit.Deserialize(f)
	if err != nil {
		return nil, err
	}

	var rktID string
	for _, opt := range opts {
		if opt.Section != "X-K8S" {
			continue
		}
		if opt.Name == "RocketID" {
			rktID = opt.Value
		}
		if opt.Name == "POD" {
			// NOTE: In fact we unmarshal from a serialized
			// api.BoundPod type here.
			err = json.Unmarshal([]byte(opt.Value), &pod)
			if err != nil {
				return nil, err
			}
		}
	}

	// TODO(yifan): Cache the list result
	podState := "unknown"
	pods, err := r.getPodsStatus()
	if err == nil {
		if _, found := pods[rktID]; !found {
			return nil, fmt.Errorf("pod not running from rkt list")
		}
		podState = pods[rktID].State
	}

	fmt.Println("pod state", rktID, podState)

	pod.Status.Info = make(map[string]api.ContainerStatus)
	for _, container := range pod.Spec.Containers {
		switch podState {
		case "running":
			pod.Status.Info[container.Name] = api.ContainerStatus{
				State: api.ContainerState{
					Running: &api.ContainerStateRunning{},
				},
			}
		case "embryo", "preparing", "prepared":
			pod.Status.Info[container.Name] = api.ContainerStatus{
				State: api.ContainerState{
					Waiting: &api.ContainerStateWaiting{},
				},
			}
		case "exited", "deleting", "gone":
			pod.Status.Info[container.Name] = api.ContainerStatus{
				State: api.ContainerState{
					Termination: &api.ContainerStateTerminated{},
				},
			}
		default:
			panic("Unexpected state")
		}
	}
	return &pod, nil
}

func (r *RocketRuntime) preparePod(pod *api.BoundPod) (string, error) {
	units, err := r.podToUnits(pod)
	if err != nil {
		return "", err
	}

	// Get the pod's uuid.
	var images []string
	for _, c := range pod.Spec.Containers {
		images = append(images, c.Image)
	}
	output, err := r.runCommand(true, "prepare", images...)
	if err != nil {
		return "", err
	}
	uuid := strings.TrimSpace(string(output))
	if uuid == "" {
		panic("expect uuid returned, but get nothing")
	}
	fmt.Println("Prepare uuid:", uuid)

	units = append(units,
		&unit.UnitOption{
			Section: "X-K8S",
			Name:    "RocketID",
			Value:   uuid,
		},
		&unit.UnitOption{
			Section: "Service",
			Name:    "ExecStart",
			Value:   r.constructRunCmd(uuid),
		},
	)

	// Save the unit file.
	name := fmt.Sprintf("K8S_%s_%s.service", pod.Name, pod.Namespace)
	unitFile, err := os.Create(path.Join(tmpDirPath, name))
	if err != nil {
		return "", err
	}
	defer unitFile.Close()

	_, err = io.Copy(unitFile, unit.Serialize(units))
	if err != nil {
		return "", err
	}

	// Enable unit file.
	_, _, err = r.systemd.EnableUnitFiles([]string{path.Join(tmpDirPath, name)}, true, true)
	if err != nil {
		return "", err
	}
	return name, err
}

func (r *RocketRuntime) ListPods() ([]*api.Pod, error) {
	glog.V(4).Infof("Listing pod")
	var pods []*api.Pod

	units, err := r.systemd.ListUnits()
	if err != nil {
		return nil, err
	}
	for _, u := range units {
		if strings.HasPrefix(u.Name, "K8S") {
			pod, err := r.unitFileToPod(path.Join(tmpDirPath, u.Name))
			if err != nil {
				// TODO(yifan) log.
				fmt.Println("WARNING", err)
				continue
			}
			pods = append(pods, pod)
		}
	}
	return pods, nil
}

func (r *RocketRuntime) RunPod(pod *api.BoundPod) error {
	name, err := r.preparePod(pod)
	if err != nil {
		glog.Errorf("Error preparePod: %v", err)
		return err
	}

	ch := make(chan string)
	glog.V(4).Infof("Starting Unit: %s", name)

	_, err = r.systemd.StartUnit(name, "replace", ch)
	if err != nil {
		glog.Error("Error StartUnit: %v", err)
		return err
	}
	if status := <-ch; status != "done" {
		return fmt.Errorf("unexpected return status %s", status)
	}
	return nil
}

func (r *RocketRuntime) KillPod(pod *api.Pod) error {
	glog.V(4).Infof("Killing pod: name %s", pod.Name)
	name := fmt.Sprintf("K8S_%s_%s.service", pod.Name, pod.Namespace)

	_, err := r.systemd.DisableUnitFiles([]string{path.Join(tmpDirPath, name)}, true)
	if err != nil {
		return err
	}
	r.systemd.KillUnit(name, 9)
	if err = r.systemd.ResetFailedUnit(name); err != nil {
		return err
	}
	return nil
}
