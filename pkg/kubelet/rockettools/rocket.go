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

package rockettools

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/coreos/go-systemd/dbus"
	"github.com/coreos/go-systemd/unit"
	"github.com/fsouza/go-dockerclient"
)

var (
	tmpACIDir           = "/tmp/"
	tmpUnitDir          = "/tmp/"
	containerNamePrefix = "k8s" // Sync with dockertools/docker.go
	pathToRocket        = "/home/yifan/gopher/src/github.com/coreos/rocket/bin/rkt"
)

func pathExists(path string) bool {
	if _, err := os.Stat(tmpACIDir); os.IsNotExist(err) {
		return false
	}
	return true
}

func attachSuffix(name, suffix string) string {
	return fmt.Sprintf("%s.%s", name, suffix)
}

// PrepareContainer prepares a container by generating a systemd unit file.
// It takes a docker.CreateContainerOptions to get the name, image of the container,
// On success, it will return the name of the container.
func PrepareContainer(opts docker.CreateContainerOptions) (string, error) {
	if !pathExists(tmpACIDir) {
		if err := os.MkdirAll(tmpACIDir, 0755); err != nil {
			return "", err
		}
	}

	if !pathExists(tmpUnitDir) {
		if err := os.MkdirAll(tmpACIDir, 0755); err != nil {
			return "", err
		}
	}

	// Generate a systemd unit file and store it somewhere.
	units := []*unit.UnitOption{
		{
			Section: "Unit",
			Name:    "Description",
			Value:   opts.Name,
		},
		{
			Section: "Service",
			Name:    "ExecStart",
			// rkt run ...
			Value: fmt.Sprintf("%s %s %s", pathToRocket, "run", fmt.Sprintf("%s://%s", "docker", opts.Config.Image)),
		},
		{
			Section: "Install",
			Name:    "WantedBy",
			Value:   "multi-user.target", // TODO: Hardcoded...
		},
	}
	unitFile := attachSuffix(path.Join(tmpUnitDir, opts.Name), "service")
	f, err := os.Create(unitFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	_, err = io.Copy(f, unit.Serialize(units))
	if err != nil {
		return "", err
	}
	return opts.Name, err
}

// StartContainer starts a container. It takes the container's name and assumes
// the unit file is already created. Then it will enable and start the unit.
func StartContainer(containerName string, hc *docker.HostConfig) error {
	unitFile := attachSuffix(containerName, "service")

	// Enable and start the unit.
	systemd, err := dbus.New()
	if err != nil {
		return err
	}
	defer systemd.Close()

	_, _, err = systemd.EnableUnitFiles([]string{path.Join(tmpUnitDir, unitFile)}, true, true)
	if err != nil {
		return err
	}

	ch := make(chan string)
	_, err = systemd.StartUnit(unitFile, "replace", ch)
	if err != nil {
		return err
	}
	if <-ch != "done" {
		return fmt.Errorf("Job is not done successfully")
	}
	return nil
}

// StopContainer stops a container by stop and disable the unit.
func StopContainer(containerName string) error {
	unitFile := attachSuffix(containerName, "service")

	// Stop and disable unit.
	systemd, err := dbus.New()
	if err != nil {
		return err
	}
	defer systemd.Close()

	ch := make(chan string)
	_, err = systemd.StopUnit(unitFile, "replace", ch)
	if err != nil {
		return err
	}
	if <-ch != "done" {
		return fmt.Errorf("Job is not done successfully")
	}

	_, err = systemd.DisableUnitFiles([]string{unitFile}, true)
	if err != nil {
		return err
	}
	return nil
}

// ListContainers lists the service names of containers.
func ListContainers() ([]string, error) {
	systemd, err := dbus.New()
	if err != nil {
		return nil, err
	}
	defer systemd.Close()

	unitStats, err := systemd.ListUnits()
	if err != nil {
		return nil, err
	}

	var containers []string
	for _, us := range unitStats {
		if strings.HasPrefix(us.Name, containerNamePrefix) {
			containers = append(containers, us.Name)
		}
	}
	return containers, nil
}
