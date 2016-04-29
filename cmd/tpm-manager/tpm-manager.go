/*
Copyright 2014 The Kubernetes Authors All rights reserved.
Copyright 2015 CoreOS, Inc

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

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/pflag"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/componentconfig"
	"k8s.io/kubernetes/pkg/client/cache"
	"k8s.io/kubernetes/pkg/client/leaderelection"
	"k8s.io/kubernetes/pkg/client/record"
	"k8s.io/kubernetes/pkg/client/restclient"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/controller/framework"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/flag"
	nodeutil "k8s.io/kubernetes/pkg/util/node"
	"k8s.io/kubernetes/pkg/util/tpm"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/pkg/watch"
)

// Flag a node as untrusted
func invalidateNode(node *api.Node) error {
	if node.ObjectMeta.Annotations == nil {
		node.ObjectMeta.Annotations = make(map[string]string)
	}
        newTaints := []api.Taint{}
        untrustedTaint := api.Taint{
                Key:    "Untrusted",
                Value:  "true",
                Effect: api.TaintEffectNoSchedule,
        }
        taints, err := api.GetTaintsFromNodeAnnotations(node.Annotations)
        for _, taint := range taints {
                if taint.Key == "Untrusted" {
                        continue
                }
                newTaints = append(newTaints, taint)
        }
        newTaints = append(newTaints, untrustedTaint)
        jsonContent, err := json.Marshal(newTaints)
        node.Annotations[api.TaintsAnnotationKey] = string(jsonContent)
        return err
}

func validateNode(node *api.Node) error {
	if node.ObjectMeta.Annotations == nil {
		node.ObjectMeta.Annotations = make(map[string]string)
	}
        newTaints := []api.Taint{}
        taints, err := api.GetTaintsFromNodeAnnotations(node.Annotations)
        for _, taint := range taints {
                if taint.Key == "Untrusted" {
                        continue
                }
                newTaints = append(newTaints, taint)
        }
        jsonContent, err := json.Marshal(newTaints)
        node.Annotations[api.TaintsAnnotationKey] = string(jsonContent)
        return err
}

func isTrusted(node *api.Node) bool {
	if node.ObjectMeta.Annotations == nil {
		node.ObjectMeta.Annotations = make(map[string]string)
	}
	taints, err := api.GetTaintsFromNodeAnnotations(node.Annotations)
	if err != nil {
		return false
	}
        for _, taint := range taints {
                if taint.Key == "Untrusted" {
			return false
		}
	}
	return true
}

func getPolicy() (err error) {
	manager.pcrconfigs = make([]map[string]tpm.PCRConfig, 0)

	if manager.pcrconfig != "" {
		pcrdata := make(map[string]tpm.PCRConfig)
		pcrconfig, err := ioutil.ReadFile(manager.pcrconfig)
		if err != nil {
			glog.Errorf("Unable to read valid PCR configuration %s: %v", manager.pcrconfig, err)
		}
		err = json.Unmarshal(pcrconfig, &pcrdata)
		if err != nil {
			glog.Errorf("Unable to parse valid PCR configuration %s: %v", manager.pcrconfig, err)
		}
		for pcr, _ := range pcrdata {
			pcrtmp := pcrdata[pcr]
			pcrtmp.Source = manager.pcrconfig
			pcrdata[pcr] = pcrtmp
		}
		manager.pcrconfigs = append(manager.pcrconfigs, pcrdata)
	} else if manager.pcrconfigdir != "" {
		err = filepath.Walk(manager.pcrconfigdir, func(path string, f os.FileInfo, err error) error {
			if f.IsDir() {
				return nil
			}
			pcrconfig, err := ioutil.ReadFile(path)
			if err != nil {
				glog.Errorf("Unable to read PCR configuration %s: %v", path, err)
				return err
			}
			pcrdata := make(map[string]tpm.PCRConfig)
			err = json.Unmarshal(pcrconfig, &pcrdata)
			if err != nil {
				glog.Errorf("Unable to parse valid PCR configuration %s: %v", path, err)
				return err
			}
			for pcr, _ := range pcrdata {
				pcrtmp := pcrdata[pcr]
				pcrtmp.Source = path
				pcrdata[pcr] = pcrtmp
			}
			manager.pcrconfigs = append(manager.pcrconfigs, pcrdata)
			return nil
		})
	} else {
		manager.pcrconfigs, err = manager.tpmhandler.GetPolicies()
		if err != nil {
			glog.Errorf("Unable to obtain PCR configuration: %v", err)
			return nil
		}
	}
	return nil
}

func verifyNode(node *api.Node) (err error) {
	address, err := nodeutil.GetNodeHostIP(node)
	if err != nil {
		return err
	}
	host := fmt.Sprintf("%s:23179", address.String())
	tpmdata, err := manager.tpmhandler.Get(host, manager.allowunknown)
	if err != nil {
		glog.Errorf("Unable to obtain TPM data for node %s: %v", address.String(), err)
		invalidateNode(node)
		return nil
	}
	quote, log, err := tpm.Quote(tpmdata)
	if err != nil {
		glog.Errorf("Unable to obtain TPM quote for node %s: %v", address.String(), err)
		invalidateNode(node)
		return nil
	}

	err = tpm.ValidateLog(log, quote)
	if err != nil {
		glog.Errorf("TPM event log does not match quote for node %s", address.String())
		invalidateNode(node)
		return nil
	}

	logstate, err := tpm.ValidatePCRs(log, quote, manager.pcrconfigs)
	jsonlog, _ := json.Marshal(logstate)
	if node.ObjectMeta.Annotations == nil {
		node.ObjectMeta.Annotations = make(map[string]string)
	}
	node.ObjectMeta.Annotations["tpm.coreos.com/logstate"] = string(jsonlog)
	if err != nil {
		glog.Errorf("TPM quote PCRs don't validate for node %s", address.String())
		invalidateNode(node)
		return nil
	}

	glog.Errorf("TPM quote for node %s validates", address.String())
	validateNode(node)
	return nil
}

func verifyAndUpdate(node *api.Node) {
	verifyNode(node)

	// The state that the node will be updated to
	newstate := isTrusted(node)
	newnode, err := manager.client.Nodes().Get(node.Name)
	if err != nil {
		glog.Errorf("Unable to obtain node state for %s: %v", node.Name, err)
		return
	}
	if newnode.ObjectMeta.Annotations == nil {
		newnode.ObjectMeta.Annotations = make(map[string]string)
	}
	currenttime := time.Now().Unix()

	// If we're transitioning state, update the metadata
	if isTrusted(newnode) != newstate {
		if newstate == false {
			newnode.ObjectMeta.Annotations["tpm.coreos.com/untrustedsince"] = strconv.FormatInt(currenttime, 10)
			newnode.ObjectMeta.Annotations["tpm.coreos.com/trustedsince"] = ""
		} else {
			newnode.ObjectMeta.Annotations["tpm.coreos.com/untrustedsince"] = ""
			newnode.ObjectMeta.Annotations["tpm.coreos.com/trustedsince"] = strconv.FormatInt(currenttime, 10)
		}
	}

	newnode.ObjectMeta.Annotations["tpm.coreos.com/validationtime"] = strconv.FormatInt(currenttime, 10)

	// Ensure that the new node is tainted appropriately
	if newstate == true {
		validateNode(newnode)
	} else {
		invalidateNode(newnode)
	}
	newnode.ObjectMeta.Annotations["tpm.coreos.com/logstate"] = node.ObjectMeta.Annotations["tpm.coreos.com/logstate"]
	newnode, err = manager.client.Nodes().Update(newnode)
	if err != nil {
		glog.Errorf("Unable to update node state for %s: %v", node.Name, err)
		return
	}
}

func verifyAllNodes() {
	nodes, err := manager.client.Nodes().List(api.ListOptions{})
	if err != nil {
		return
	}
	for _, node := range nodes.Items {
		verifyAndUpdate(&node)
	}
}

func reverify() {
	select {
	case <-time.After(time.Duration(manager.recurring) * time.Second):
		verifyAllNodes()
	case <-manager.recurringChan:
	}
}

type TPMManager struct {
	Master        string
	Kubeconfig    string
	tpmhandler    tpm.TPMHandler
	pcrconfig     string
	pcrconfigdir  string
	allowunknown  bool
	recurring     int
	client        *client.Client
	policyTimer   *time.Timer
	leaderelect   componentconfig.LeaderElectionConfiguration
	recurringChan chan int
	pcrconfigs    []map[string]tpm.PCRConfig
}

var manager TPMManager

func addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&manager.Master, "master", manager.Master, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	fs.StringVar(&manager.Kubeconfig, "kubeconfig", manager.Kubeconfig, "Path to kubeconfig file with authorization and master location information.")
	fs.StringVar(&manager.pcrconfig, "pcrconfig", manager.pcrconfig, "Path to a single PCR config file")
	fs.StringVar(&manager.pcrconfigdir, "pcrconfigdir", manager.pcrconfigdir, "Path to a PCR config directory")
	fs.BoolVar(&manager.allowunknown, "allowunknown", false, "Allow unknown TPMs to join the cluster")
	fs.IntVar(&manager.recurring, "reverify", 0, "Periodocally reverify nodes after this many seconds")
}

func updateConfig(configmap *api.ConfigMap) {
	if configmap.Data["allowunknown"] != "" {
		allowunknown, err := strconv.ParseBool(configmap.Data["allowunknown"])
		if err == nil {
			manager.allowunknown = allowunknown
		}
	}
	if configmap.Data["reverify"] != "" {
		reverify, err := strconv.Atoi(configmap.Data["reverify"])
		if err == nil {
			manager.recurring = reverify
			select {
			case manager.recurringChan <- reverify:
			default:
			}
		}
	}
}

func run(stop <-chan struct{}) {
	_, nodeController := framework.NewInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return manager.client.Nodes().List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return manager.client.Nodes().Watch(options)
			},
		},
		&api.Node{},
		controller.NoResyncPeriodFunc(),
		framework.ResourceEventHandlerFuncs{
			AddFunc:    nodeAddFn,
			UpdateFunc: nodeUpdateFn,
			DeleteFunc: nodeDeleteFn,
		},
	)

	_, configController := framework.NewInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return manager.client.ConfigMaps("default").List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return manager.client.ConfigMaps("default").Watch(options)
			},
		},
		&api.ConfigMap{},
		controller.NoResyncPeriodFunc(),
		framework.ResourceEventHandlerFuncs{
			AddFunc:    configAddFn,
			UpdateFunc: configUpdateFn,
			DeleteFunc: configDeleteFn,
		},
	)

	_, policyController := framework.NewInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return manager.tpmhandler.PolicyClient.List(&options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return manager.tpmhandler.PolicyClient.Watch(&options)
			},
		},
		&runtime.Unstructured{},
		controller.NoResyncPeriodFunc(),
		framework.ResourceEventHandlerFuncs{
			AddFunc:    policyAddFn,
			UpdateFunc: policyUpdateFn,
			DeleteFunc: policyDeleteFn,
		},
	)
	fmt.Printf("Starting\n")
	getPolicy()
	go reverify()
	go nodeController.Run(wait.NeverStop)
	go configController.Run(wait.NeverStop)
	go policyController.Run(wait.NeverStop)
	select {}
	fmt.Printf("Returned\n")
}

func main() {
	var tpmhandler tpm.TPMHandler
	var config restclient.Config

	//	config, err := clientcmd.BuildConfigFromFlags(manager.Master, manager.Kubeconfig)
	err := client.SetKubernetesDefaults(&config)
	if err != nil {
		fmt.Errorf("Unable to create client configuration: %v", err)
	}
	config.Host = "http://localhost:8080"
	client, err := client.New(&config)
	if err != nil {
		fmt.Printf("Unable to create client: %v", err)
		return
	}
	tpmhandler.Setup(&config)

	configmap, err := client.ConfigMaps("default").Get("tpm-manager.coreos.com")
	if err == nil && configmap != nil {
		updateConfig(configmap)
	}

	addFlags(pflag.CommandLine)
	leaderelection.BindFlags(&manager.leaderelect, pflag.CommandLine)
	flag.InitFlags()

	manager.client = client
	manager.tpmhandler = tpmhandler
	manager.recurringChan = make(chan int)

	if !manager.leaderelect.LeaderElect {
		run(nil)
	}

	id, err := os.Hostname()
	if err != nil {
		fmt.Printf("Unable to obtain hostname: %v", err)
		return
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.Infof)
	eventBroadcaster.StartRecordingToSink(client.Events(""))
	recorder := eventBroadcaster.NewRecorder(api.EventSource{Component: "tpm-manager"})

	leaderelection.RunOrDie(leaderelection.LeaderElectionConfig{
		EndpointsMeta: api.ObjectMeta{
			Namespace: "",
			Name:      "tpm-manager",
		},
		Client:        client,
		Identity:      id,
		EventRecorder: recorder,
		LeaseDuration: manager.leaderelect.LeaseDuration.Duration,
		RenewDeadline: manager.leaderelect.RenewDeadline.Duration,
		RetryPeriod:   manager.leaderelect.RetryPeriod.Duration,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: run,
			OnStoppedLeading: func() {
				glog.Fatalf("leaderelection lost")
			},
		},
	})
}

func nodeAddFn(obj interface{}) {
	fmt.Printf("New node\n")
	node, ok := obj.(*api.Node)
	if !ok {
		return
	}
	fmt.Printf("Verifying\n")
	verifyAndUpdate(node)
}

func nodeUpdateFn(oldObj, newObj interface{}) {
}

func nodeDeleteFn(obj interface{}) {
}

func configAddFn(obj interface{}) {
	fmt.Printf("New config\n")
	configmap, ok := obj.(*api.ConfigMap)
	if !ok {
		return
	}
	if configmap.Name != "tpm-manager.coreos.com" {
		return
	}
	fmt.Printf("Updating\n")
	updateConfig(configmap)
}

func configUpdateFn(oldObj, newObj interface{}) {
	fmt.Printf("Updated config\n")
	configmap, ok := newObj.(*api.ConfigMap)
	if !ok {
		return
	}
	if configmap.Name != "tpm-manager.coreos.com" {
		return
	}
	fmt.Printf("Updating\n")
	updateConfig(configmap)
}

func configDeleteFn(obj interface{}) {
}

func updatePolicy() {
	getPolicy()
	verifyAllNodes()
}

func scheduleVerification() {
	if manager.policyTimer != nil {
		manager.policyTimer.Stop()
	}
	manager.policyTimer = time.AfterFunc(time.Second, updatePolicy)
}

func policyAddFn(obj interface{}) {
	fmt.Printf("New policy\n")
	scheduleVerification()
}

func policyUpdateFn(oldobj, newobj interface{}) {
	fmt.Printf("Updated policy\n")
	scheduleVerification()
}

func policyDeleteFn(obj interface{}) {
	fmt.Printf("Deleted policy\n")
	scheduleVerification()
}
