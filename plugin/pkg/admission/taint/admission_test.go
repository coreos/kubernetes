/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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

package taint

import (
	"encoding/json"
	"testing"

	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	//	"k8s.io/kubernetes/pkg/api/rest"
	"k8s.io/kubernetes/pkg/auth/user"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/fake"
	"k8s.io/kubernetes/pkg/client/testing/core"
	"k8s.io/kubernetes/pkg/runtime"
)

func TestAdmission(t *testing.T) {
	testcases := map[string]struct {
		kind         string
		name         string
		user         user.Info
		failcase     bool
		checktrusted bool
		trusted      bool
		tolerate     bool
		object       runtime.Object
		operation    admission.Operation
	}{"tainted": {
		kind:         "Node",
		name:         "name",
		user:         &user.DefaultInfo{},
		failcase:     false,
		checktrusted: true,
		trusted:      false,
		object:       &api.Node{},
		operation:    admission.Create,
	},
		"untainted": {
			kind:         "Node",
			name:         "name",
			user:         nil,
			failcase:     false,
			checktrusted: true,
			trusted:      true,
			object:       &api.Node{},
			operation:    admission.Create,
		},
		"alterconfig": {
			kind:      "ConfigMap",
			name:      "taint.coreos.com",
			user:      &user.DefaultInfo{},
			failcase:  true,
			object:    &api.ConfigMap{},
			operation: admission.Update,
		},
		"trustedalterconfig": {
			kind:      "ConfigMap",
			name:      "taint.coreos.com",
			user:      nil,
			failcase:  false,
			object:    &api.ConfigMap{},
			operation: admission.Update,
		},
		"updatenode": {
			kind:      "Node",
			name:      "",
			user:      &user.DefaultInfo{},
			failcase:  true,
			object:    &api.Node{},
			operation: admission.Update,
		},
		"trustedupdatenode": {
			kind:      "Node",
			name:      "",
			user:      nil,
			failcase:  false,
			object:    &api.Node{},
			operation: admission.Update,
		},
		"updatepod": {
			kind:      "Pod",
			name:      "",
			user:      &user.DefaultInfo{},
			failcase:  true,
			object:    &api.Pod{},
			tolerate:  true,
			operation: admission.Update,
		},
		"trustedupdatepod": {
			kind:      "Pod",
			name:      "",
			user:      nil,
			failcase:  false,
			object:    &api.Pod{},
			tolerate:  true,
			operation: admission.Update,
		},
	}
	mockClient := &fake.Clientset{}
	mockClient.AddReactor("get", "configmaps", func(action core.Action) (bool, runtime.Object, error) {
		taintdata := make(map[string]string)
		taintdata["taint"] = "true"
		configmap := &api.ConfigMap{Data: taintdata}
		if action.(core.GetAction).GetName() == "taint.coreos.com" {
			return true, configmap, nil
		} else {
			t.Errorf("Received request for %v", action.GetResource())
			return true, nil, nil
		}
	})
	mockClient.AddReactor("get", "nodes", func(action core.Action) (bool, runtime.Object, error) {
		node := &api.Node{}
		invalidateNode(node)
		return true, node, nil
	})
	mockClient.AddReactor("get", "pods", func(action core.Action) (bool, runtime.Object, error) {
		pod := &api.Pod{}
		return true, pod, nil
	})
	handler := NewTaintAdmit(mockClient, nil)

	for name, tc := range testcases {
		if tc.tolerate {
			pod, _ := tc.object.(*api.Pod)
			tolerations := []api.Toleration{}
			untrustedTolerate := api.Toleration{
				Key:   TaintKey,
				Value: "true",
			}
			tolerations = append(tolerations, untrustedTolerate)
			jsonContent, _ := json.Marshal(tolerations)
			pod.Annotations = make(map[string]string)
			pod.Annotations[api.TolerationsAnnotationKey] = string(jsonContent)
		}
		err := handler.Admit(admission.NewAttributesRecord(tc.object, nil, api.Kind(tc.kind).WithVersion("v1"), "namespace", tc.name, api.Resource("resource").WithVersion("version"), "subresource", tc.operation, tc.user))
		if (tc.failcase == true && err == nil) || (tc.failcase == false && err != nil) {
			t.Errorf("Unexpected failure status %v for %s\n", err, name)
		}
		if tc.checktrusted {
			node, _ := tc.object.(*api.Node)
			trusted, _ := isTrusted(node)
			if trusted != tc.trusted {
				t.Errorf("Unexpected trust state %v for %s\n", trusted, name)
			}
		}
	}
}
