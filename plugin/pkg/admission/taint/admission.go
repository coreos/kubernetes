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

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	apierrors "k8s.io/kubernetes/pkg/api/errors"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
)

const untrusted string = "tpm.coreos.com/untrusted"

func init() {
	admission.RegisterPlugin("TaintAdmit", func(client clientset.Interface, config io.Reader) (admission.Interface, error) {
		return NewTaintAdmit(client, config), nil
	})
}

// TaintAdmit is an implementation of admission.Interface which taints nodes at creation time
type taintAdmit struct {
	client clientset.Interface
}

// Determine whether a node is untrusted
func isUntrusted(node *api.Node) (bool, error) {
	taints, err := api.GetTaintsFromNodeAnnotations(node.Annotations)
	if err != nil {
		return false, err
	}
	for _, taint := range taints {
		if taint.Key == "Untrusted" {
			return true, nil
		}
	}
	return false, nil
}

// Flag a node as untrusted
func invalidateNode(node *api.Node) error {
	if node.Annotations == nil {
		node.Annotations = make(map[string]string)
	}
	taints, err := api.GetTaintsFromNodeAnnotations(node.Annotations)
	newTaints := []api.Taint{}
	untrustedTaint := api.Taint{
		Key:    "untrusted",
		Value:  "true",
		Effect: api.TaintEffectNoSchedule,
	}
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

func (t *taintAdmit) Admit(a admission.Attributes) (err error) {
	kind := a.GetKind().GroupKind()

	if kind != api.Kind("Node") && kind != api.Kind("ConfigMap") {
		return nil
	}

	configmap, err := t.client.Core().ConfigMaps("default").Get("taint.coreos.com")
	if err != nil {
		return apierrors.NewBadRequest("Unable to obtain configmap")
	}

	if configmap == nil || configmap.Data["taint"] != "true" {
		return nil
	}

	user := a.GetUserInfo()

	if kind == api.Kind("ConfigMap") {
		name := a.GetName()
		// A create operation may not provide a name directly, so pull it out
		// of the object if we didn't get one
		if name == "" {
			configmap, ok := a.GetObject().(*api.ConfigMap)
			if !ok {
				glog.Errorf("Object is %v", a.GetObject())
				return apierrors.NewBadRequest("Resource was marked with kind ConfigMap but was unable to be converted")
			}
			name = configmap.Name
		}
		// Only permit direct API access to modify these, otherwise noeds can
		// circumvent security policy
		if name == "taint.coreos.com" || name == "tpm.coreos.com" {
			if user != nil {
				return apierrors.NewBadRequest("Unauthorised attempt to modify taint configuration")
			}
		}
		return nil
	}

	operation := a.GetOperation()
	if operation != admission.Create && operation != admission.Update {
		return nil
	}

	node, ok := a.GetObject().(*api.Node)
	if !ok {
		glog.Errorf("Object is %v", a.GetObject())
		return apierrors.NewBadRequest("Resource was marked with kind Node but was unable to be converted")
	}

	if operation == admission.Create {
		err := invalidateNode(node)
		if err != nil {
			return fmt.Errorf("Unable to invalidate node: %v", err)
		}
		return nil
	}

	// If an external update tries to switch a node from untrusted to trusted, force it back to untrusted
	untrusted, err := isUntrusted(node)
	if err != nil {
		return fmt.Errorf("Unable to identify node trusted status: %v", err)
	}
	if user != nil && untrusted == false {
		oldNode, err := t.client.Core().Nodes().Get(node.Name)
		if err != nil {
			return fmt.Errorf("Attempting to update a node that doesn't exist? %v", err)
		}
		oldUntrusted, err := isUntrusted(oldNode)
		if err != nil || oldUntrusted {
			glog.Errorf("User %v attempted to flag untrusted node %v as trusted", user, node.Name)
			invalidateNode(node)
		}
	}
	return nil
}

func (taintAdmit) Handles(operation admission.Operation) bool {
	return true
}

// NewTaintAdmit creates a new TaintAdmit handler
func NewTaintAdmit(c clientset.Interface, config io.Reader) admission.Interface {
	taintadmit := &taintAdmit{
		client: c,
	}
	return taintadmit
}
