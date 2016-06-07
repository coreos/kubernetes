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
	"errors"
	"fmt"
	"io"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/apis/rbac/validation"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/rbac/unversioned"
	"k8s.io/kubernetes/pkg/runtime"

	apierrors "k8s.io/kubernetes/pkg/api/errors"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
)

const untrusted string = "tpm.coreos.com/untrusted"

func newRbacClient(client clientset.Interface) validation.AuthorizationRuleResolver {
	c := &rbacClient{client.Rbac()}
	return validation.NewDefaultRuleResolver(c, c, c, c)
}

type rbacClient struct {
	client unversioned.RbacInterface
}

func (c *rbacClient) GetClusterRole(ctx api.Context, id string) (*rbac.ClusterRole, error) {
	return c.client.ClusterRoles().Get(id)
}

func (c *rbacClient) ListClusterRoleBindings(ctx api.Context, options *api.ListOptions) (*rbac.ClusterRoleBindingList, error) {
	return c.client.ClusterRoleBindings().List(*options)
}

func (c *rbacClient) GetRole(ctx api.Context, id string) (*rbac.Role, error) {
	ns, ok := api.NamespaceFrom(ctx)
	if !ok {
		return nil, errors.New("no namespace found")
	}
	role, err := c.client.Roles(ns).Get(id)
	if err != nil {
		return nil, fmt.Errorf("get role: %v", err)
	}
	return role, nil
}

func (c *rbacClient) ListRoleBindings(ctx api.Context, options *api.ListOptions) (*rbac.RoleBindingList, error) {
	ns, ok := api.NamespaceFrom(ctx)
	if !ok {
		return nil, errors.New("no namespace found")
	}
	roleBindings, err := c.client.RoleBindings(ns).List(*options)
	if err != nil {
		return nil, fmt.Errorf("list role bindings: %v", err)
	}
	return roleBindings, nil
}

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

func toleratesUntrusted(pod *api.Pod) (bool, error) {
	tolerations, err := api.GetTolerationsFromPodAnnotations(pod.Annotations)
	if err != nil {
		return false, err
	}
	for _, toleration := range tolerations {
		if toleration.Key == "Untrusted" {
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
		Key:    "Untrusted",
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

	if kind != api.Kind("Node") && kind != api.Kind("ConfigMap") && kind != api.Kind("Pod") {
		return nil
	}

	configmap, err := t.client.Core().ConfigMaps("default").Get("taint.coreos.com")
	if err != nil {
		return apierrors.NewBadRequest("Unable to obtain configmap")
	}

	if configmap == nil || configmap.Data["taint"] != "true" {
		return nil
	}

	namespace := a.GetNamespace()
	user := a.GetUserInfo()
	tpmAdmin := false

	if user == nil {
		// Allow access over the insecure socket to do anything
		tpmAdmin = true
	} else {
		// Otherwise check whether the user has a role that provides the tpmadmin attribute
		rbac := newRbacClient(t.client)
		ctx := api.WithUser(api.WithNamespace(api.NewContext(), "default"), user)
		rules, err := rbac.GetEffectivePolicyRules(ctx)
		if err == nil {
			for _, rule := range rules {
				restrictions, ok := rule.AttributeRestrictions.(*runtime.Unknown)
				if ok && string(restrictions.Raw) == "tpmadmin" {
					tpmAdmin = true
					break
				}
			}
		} else {
			glog.Errorf("Unable to obtain user rules: %v", err)
		}
	}

	// Allow admin users or request over the insecure socket to do whatever they want
	if tpmAdmin == true {
		glog.Errorf("TPMadmin = true")
		return nil
	}

	// Unprivileged users aren't allowed to perform actions that would alter the trust state
	switch kind {
	case api.Kind("ConfigMap"):
		name := a.GetName()
		// A create operation may not provide a name directly, so pull it out of the object if we didn't get one
		if name == "" {
			configmap, ok := a.GetObject().(*api.ConfigMap)
			if !ok {
				return apierrors.NewBadRequest("Resource was marked with kind ConfigMap but couldn't be type converted")
			}
			name = configmap.Name
		}
		// Only permit TPM admins to modify these, otherwise nodes can circumvent security policy
		if name == "taint.coreos.com" || name == "tpm.coreos.com" {
				return apierrors.NewBadRequest("Unauthorised attempt to modify taint configuration")
		}
		return nil
	case api.Kind("Node"):
		operation := a.GetOperation()
		if operation != admission.Create && operation != admission.Update {
			return nil
		}

		node, ok := a.GetObject().(*api.Node)
		if !ok {
			return apierrors.NewBadRequest("Resource was marked with kind Node but couldn't be type converted")
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
		if untrusted == false {
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
	case api.Kind("Pod"):
		operation := a.GetOperation()
		if operation != admission.Update {
			return nil
		}
		pod, ok := a.GetObject().(*api.Pod)
		if !ok {
			return apierrors.NewBadRequest("Resource was marked with kind Pod but couldn't be type converted")
		}
		tolerates, err := toleratesUntrusted(pod)
		if err != nil {
			return fmt.Errorf("Unable to identify pod toleration status: %v", err)
		}
		if tolerates == true {
			oldPod, err := t.client.Core().Pods(namespace).Get(pod.Name)
			if err != nil {
				return fmt.Errorf("Attempting to update a pod that doesn't exist? %v", err)
			}
			oldTolerates, err := toleratesUntrusted(oldPod)
			if err != nil || oldTolerates == false {
				glog.Errorf("User %v attempted to flag pod %v as tolerating untrusted nodes", user, pod.Name)
				return apierrors.NewBadRequest("Invalid attempt to declare that a pod tolerates untrusted nodes")
			}
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
