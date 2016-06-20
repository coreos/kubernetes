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

const TaintKey string = "Untrusted"
const LogState string = "tpm.coreos.com/logstate"
const UntrustedSince string = "tpm.coreos.com/untrustedsince"
const TrustedSince string = "tpm.coreos.com/trustedsince"
const ValidationTime string = "tpm.coreos.com/validationtime"
const ConfigName string = "tpm-manager.coreos.com"

// Flag a node as untrusted
func invalidateNode(node *api.Node) error {
	if node.ObjectMeta.Annotations == nil {
		node.ObjectMeta.Annotations = make(map[string]string)
	}
	newTaints := []api.Taint{}
	untrustedTaint := api.Taint{
		Key:    TaintKey,
		Value:  "true",
		Effect: api.TaintEffectNoSchedule,
	}
	taints, err := api.GetTaintsFromNodeAnnotations(node.Annotations)
	for _, taint := range taints {
		if taint.Key == TaintKey {
			continue
		}
		newTaints = append(newTaints, taint)
	}
	newTaints = append(newTaints, untrustedTaint)
	jsonContent, err := json.Marshal(newTaints)
	if err == nil {
		node.Annotations[api.TaintsAnnotationKey] = string(jsonContent)
	}
	return err
}

func trustNode(node *api.Node) error {
	if node.ObjectMeta.Annotations == nil {
		node.ObjectMeta.Annotations = make(map[string]string)
	}
	newTaints := []api.Taint{}
	taints, err := api.GetTaintsFromNodeAnnotations(node.Annotations)
	for _, taint := range taints {
		if taint.Key == TaintKey {
			continue
		}
		newTaints = append(newTaints, taint)
	}
	jsonContent, err := json.Marshal(newTaints)
	if err == nil {
		node.Annotations[api.TaintsAnnotationKey] = string(jsonContent)
	}
	return err
}

func isTrusted(node *api.Node) bool {
	if node.ObjectMeta.Annotations == nil {
		return true
	}
	taints, err := api.GetTaintsFromNodeAnnotations(node.Annotations)
	if err != nil {
		return false
	}
	for _, taint := range taints {
		if taint.Key == TaintKey {
			return false
		}
	}
	return true
}

func loadPolicy() (err error) {
	manager.pcrConfigs = make([]map[string]tpm.PCRConfig, 0)

	if manager.pcrConfig != "" {
		pcrdata := make(map[string]tpm.PCRConfig)
		pcrConfig, err := ioutil.ReadFile(manager.pcrConfig)
		if err != nil {
			return fmt.Errorf("Unable to read valid PCR configuration %s: %v", manager.pcrConfig, err)
		}
		err = json.Unmarshal(pcrConfig, &pcrdata)
		if err != nil {
			return fmt.Errorf("Unable to parse valid PCR configuration %s: %v", manager.pcrConfig, err)
		}
		for pcrKey, pcrVal := range pcrdata {
			pcrtmp := pcrVal
			pcrtmp.Source = manager.pcrConfig
			pcrdata[pcrKey] = pcrtmp
		}
		manager.pcrConfigs = append(manager.pcrConfigs, pcrdata)
	} else if manager.pcrConfigDir != "" {
		err = filepath.Walk(manager.pcrConfigDir, func(path string, f os.FileInfo, err error) error {
			if f.IsDir() {
				return nil
			}
			pcrConfig, err := ioutil.ReadFile(path)
			if err != nil {
				glog.Errorf("Unable to read PCR configuration %s: %v", path, err)
			}
			pcrdata := make(map[string]tpm.PCRConfig)
			err = json.Unmarshal(pcrConfig, &pcrdata)
			if err != nil {
				glog.Errorf("Unable to parse valid PCR configuration %s: %v", path, err)
			}
			for pcr, _ := range pcrdata {
				pcrtmp := pcrdata[pcr]
				pcrtmp.Source = path
				pcrdata[pcr] = pcrtmp
			}
			manager.pcrConfigs = append(manager.pcrConfigs, pcrdata)
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		manager.pcrConfigs, err = manager.tpmhandler.GetPolicies()
		if err != nil {
			glog.Errorf("Unable to obtain PCR configuration: %v", err)
			return nil
		}
	}
	return nil
}

func updateAnnotations(node *api.Node, log string) {
	if node.ObjectMeta.Annotations == nil {
		node.ObjectMeta.Annotations = make(map[string]string)
	}
	node.ObjectMeta.Annotations[LogState] = log
}

func verifyNode(node *api.Node) error {
	address, err := nodeutil.GetNodeHostIP(node)
	if err != nil {
		return err
	}
	host := fmt.Sprintf("%s:23179", address.String())
	tpmdata, err := manager.tpmhandler.Get(host, manager.allowUnknown)
	if err != nil {
		invalidateNode(node)
		return fmt.Errorf("Invalidating Node: Unable to obtain TPM data for node %s: %v", address.String(), err)
	}
	quote, log, err := tpm.Quote(tpmdata)
	if err != nil {
		invalidateNode(node)
		return fmt.Errorf("Invalidating Node: Unable to obtain TPM quote for node %s: %v", address.String(), err)
	}

	err = tpm.ValidateLog(log, quote)
	if err != nil {
		invalidateNode(node)
		return fmt.Errorf("Invalidating Node: TPM event log does not match quote for node %s", address.String())
	}

	// Don't handle this error immediately - we want to update the annotations even if validation failed
	logstate, err := tpm.ValidatePCRs(log, quote, manager.pcrConfigs)
	jsonlog, jsonerr := json.Marshal(logstate)

	if jsonerr != nil {
		updateAnnotations(node, string(jsonlog))
	}

	if err != nil {
		invalidateNode(node)
		return fmt.Errorf("Invalidating Node: Unable to validate quote for node %s", address.String())
	}

	// If we've got this far then the node is trustworthy
	trustNode(node)
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
			newnode.ObjectMeta.Annotations[UntrustedSince] = strconv.FormatInt(currenttime, 10)
			newnode.ObjectMeta.Annotations[TrustedSince] = ""
		} else {
			newnode.ObjectMeta.Annotations[UntrustedSince] = ""
			newnode.ObjectMeta.Annotations[TrustedSince] = strconv.FormatInt(currenttime, 10)
		}
	}

	newnode.ObjectMeta.Annotations[ValidationTime] = strconv.FormatInt(currenttime, 10)

	// Ensure that the new node is tainted appropriately
	if newstate == true {
		trustNode(newnode)
	} else {
		invalidateNode(newnode)
	}
	newnode.ObjectMeta.Annotations[LogState] = node.ObjectMeta.Annotations[LogState]
	newnode, err = manager.client.Nodes().Update(newnode)
	if err != nil {
		glog.Errorf("Unable to update node state for %s: %v", node.Name, err)
		return
	}
}

func verifyAllNodes() {
	nodes, err := manager.client.Nodes().List(api.ListOptions{})
	if err != nil {
		glog.Errorf("Unable to obtain list of nodes")
		return
	}
	for _, node := range nodes.Items {
		verifyAndUpdate(&node)
	}
}

func reverify() {
	for {
		select {
		case <-time.After(time.Duration(manager.recurring) * time.Second):
			verifyAllNodes()
		case <-manager.recurringChan:
		}
	}
}

type TPMManager struct {
	Master        string
	Kubeconfig    string
	tpmhandler    tpm.TPMHandler
	pcrConfig     string
	pcrConfigDir  string
	allowUnknown  bool
	recurring     int
	client        *client.Client
	policyTimer   *time.Timer
	leaderelect   componentconfig.LeaderElectionConfiguration
	recurringChan chan int
	pcrConfigs    []map[string]tpm.PCRConfig
}

var manager TPMManager

func addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&manager.Master, "master", manager.Master, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	fs.StringVar(&manager.Kubeconfig, "kubeconfig", manager.Kubeconfig, "Path to kubeconfig file with authorization and master location information.")
	fs.StringVar(&manager.pcrConfig, "pcrConfig", manager.pcrConfig, "Path to a single PCR config file")
	fs.StringVar(&manager.pcrConfigDir, "pcrConfigDir", manager.pcrConfigDir, "Path to a PCR config directory")
	fs.BoolVar(&manager.allowUnknown, "allowUnknown", false, "Allow unknown TPMs to join the cluster")
	fs.IntVar(&manager.recurring, "reverify", 0, "Periodocally reverify nodes after this many seconds")
}

func updateConfig(configmap *api.ConfigMap) {
	if configmap.Data["allowUnknown"] != "" {
		allowUnknown, err := strconv.ParseBool(configmap.Data["allowUnknown"])
		if err == nil {
			manager.allowUnknown = allowUnknown
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
			AddFunc: nodeAddFn,
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
	loadPolicy()
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
	config.APIPath = "apis/coreos.com"
	client, err := client.New(&config)
	if err != nil {
		fmt.Printf("Unable to create client: %v", err)
		os.Exit(1)
	}
	err = tpmhandler.Setup(&config)
	if err != nil {
		fmt.Printf("Unable to set up TPM handler: %v", err)
		os.Exit(1)
	}
	configmap, err := client.ConfigMaps("default").Get(ConfigName)
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
		run(wait.NeverStop)
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
			Namespace: "default",
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
	node, ok := obj.(*api.Node)
	if !ok {
		glog.Errorf("Node add got a non-Node")
		return
	}
	verifyAndUpdate(node)
}

func configAddFn(obj interface{}) {
	configmap, ok := obj.(*api.ConfigMap)
	if !ok {
		glog.Errorf("Config add got a non-ConfigMap")
		return
	}
	if configmap.Name != ConfigName {
		return
	}
	updateConfig(configmap)
}

func configUpdateFn(oldObj, newObj interface{}) {
	configAddFn(newObj)
}

func updatePolicy() {
	loadPolicy()
	verifyAllNodes()
}

func scheduleVerification() {
	if manager.policyTimer != nil {
		manager.policyTimer.Stop()
	}
	manager.policyTimer = time.AfterFunc(time.Second, updatePolicy)
}

func policyAddFn(obj interface{}) {
	scheduleVerification()
}

func policyUpdateFn(oldobj, newobj interface{}) {
	scheduleVerification()
}

func policyDeleteFn(obj interface{}) {
	scheduleVerification()
}
