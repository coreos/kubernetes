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

package admit

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
        apierrors "k8s.io/kubernetes/pkg/api/errors"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	nodeutil "k8s.io/kubernetes/pkg/util/node"
	"k8s.io/kubernetes/pkg/util/tpm"
)

func init() {
	admission.RegisterPlugin("TPMAdmit", func(client clientset.Interface, config io.Reader) (admission.Interface, error) {
		return NewTPMAdmit(client, config), nil
	})	
}

// TPMAdmit is an implementation of admission.Interface which performs TPM-based validation of the request
type tpmAdmit struct{
	handler tpm.TPMHandler
	client clientset.Interface
	pcrconfig string
	allowunknown bool
}

// Flag a node as untrusted and unschedulable
func invalidateNode(node *api.Node) {
	node.Spec.Unschedulable = true
	node.Spec.Untrusted = true
}

func (t *tpmAdmit) validateNode(node *api.Node) (err error) {
	address, err := nodeutil.GetNodeHostIP(node)
	if err != nil{
		return err
	}
	host := fmt.Sprintf("%s:23179", address.String())
	tpmdata, err := t.handler.Get(host, t.allowunknown)
	if err != nil {
		glog.Errorf("Unable to obtain TPM data for node %s", address.String())
		invalidateNode(node)
		return nil
	}
	quote, log, err := tpm.Quote(tpmdata)
	if err != nil {
		glog.Errorf("Unable to obtain TPM quote for node %s", address.String())
		invalidateNode(node)
		return nil
	}
	pcrconfig, err := ioutil.ReadFile(t.pcrconfig)
	if err != nil {
		glog.Errorf("Unable to read valid PCR configuration %v", err)
		invalidateNode(node)
		return nil
	}
	var pcrdata map[string]tpm.PCRConfig
	err = json.Unmarshal(pcrconfig, &pcrdata)
	if err != nil {
		glog.Errorf("Unable to parse valid PCR configuration: %v", err)
		return fmt.Errorf("Can't parse PCR config: %v", err)
	}
	err = tpm.ValidateLog(log, quote)
	if err != nil {
		glog.Errorf("TPM event log does not match quote for node %s", address.String())
		invalidateNode(node)
		return nil
	}

	err = tpm.ValidatePCRs(log, quote, pcrdata)
	if err != nil {
		glog.Errorf("TPM quote PCRs don't validate for node %s", address.String())
		invalidateNode(node)
		return nil
	}

	node.Spec.Untrusted = false
	return nil
}

func (t *tpmAdmit) Admit(a admission.Attributes) (err error) {
	if a.GetKind() != api.Kind("Node") {
		return nil
	}

	node, ok := a.GetObject().(*api.Node)
	if !ok {
		glog.Errorf("Object is %v", a.GetObject())
		return apierrors.NewBadRequest("Resource was marked with kind Node but was unable to be converted")
	}

	if a.GetOperation() == admission.Create {
		err = t.validateNode(node)
	} else if a.GetOperation() == admission.Update {
		old, err := t.client.Core().Nodes().Get(node.ObjectMeta.Name)
		if err == nil && old.Spec.Untrusted == true {
			err = t.validateNode(node)
		}
	}

	if err != nil {
		return admission.NewForbidden(a, err)
	}

	return nil
}

func (tpmAdmit) Handles(operation admission.Operation) bool {
	if operation == admission.Create || operation == admission.Update {
		return true
	}
	return false
}

func revalidate(t *tpmAdmit, delay int) {
	for range time.Tick(time.Second * time.Duration(delay)) {
		nodes, err := t.client.Core().Nodes().List(api.ListOptions{})
		if err != nil {
			continue
		}
		for _, node := range nodes.Items {
			state := node.Spec.Untrusted
			t.validateNode(&node)
			if node.Spec.Untrusted != state {
				t.client.Core().Nodes().Update(&node)
			}
		}
	}
}

// NewTPMAdmit creates a new TPMAdmit handler
func NewTPMAdmit(c clientset.Interface, config io.Reader) admission.Interface {
	var tpmhandler tpm.TPMHandler
	var pcrconfig string
	var allowunknown bool
	tpmhandler.Setup()

	jsondata, err := ioutil.ReadAll(config)
	if err != nil {
		return nil
	}
	var configdata map[string]interface{}
	err = json.Unmarshal(jsondata, &configdata)
	if err != nil {
		return nil
	}
	if configdata["tpmadmit.pcrconfig"] != nil {
		pcrconfig = configdata["tpmadmit.pcrconfig"].(string)
	}
	if configdata["tpmadmit.allowunknown"] != nil {
		allowunknown = configdata["tpmadmit.allowunknown"].(bool)
	}
	tpmadmit := &tpmAdmit{
		handler: tpmhandler,
		client: c,
		pcrconfig: pcrconfig,
		allowunknown: allowunknown,
	}
	if configdata["tpmadmit.recurring"] != nil {
		go revalidate(tpmadmit, int(configdata["tpmadmit.recurring"].(float64)))
	}
	return tpmadmit
}
