/*
Copyright 2019 The Kubernetes Authors.

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

package fake

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	core "k8s.io/kubernetes/pkg/apis/core"
)

// FakePodTemplates implements PodTemplateInterface
type FakePodTemplates struct {
	Fake *FakeCore
	ns   string
}

var podtemplatesResource = schema.GroupVersionResource{Group: "", Version: "", Resource: "podtemplates"}

var podtemplatesKind = schema.GroupVersionKind{Group: "", Version: "", Kind: "PodTemplate"}

// Get takes name of the podTemplate, and returns the corresponding podTemplate object, and an error if there is any.
func (c *FakePodTemplates) Get(name string, options v1.GetOptions) (result *core.PodTemplate, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(podtemplatesResource, c.ns, name), &core.PodTemplate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*core.PodTemplate), err
}

// List takes label and field selectors, and returns the list of PodTemplates that match those selectors.
func (c *FakePodTemplates) List(opts v1.ListOptions) (result *core.PodTemplateList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(podtemplatesResource, podtemplatesKind, c.ns, opts), &core.PodTemplateList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &core.PodTemplateList{}
	for _, item := range obj.(*core.PodTemplateList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested podTemplates.
func (c *FakePodTemplates) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(podtemplatesResource, c.ns, opts))

}

// Create takes the representation of a podTemplate and creates it.  Returns the server's representation of the podTemplate, and an error, if there is any.
func (c *FakePodTemplates) Create(podTemplate *core.PodTemplate) (result *core.PodTemplate, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(podtemplatesResource, c.ns, podTemplate), &core.PodTemplate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*core.PodTemplate), err
}

// Update takes the representation of a podTemplate and updates it. Returns the server's representation of the podTemplate, and an error, if there is any.
func (c *FakePodTemplates) Update(podTemplate *core.PodTemplate) (result *core.PodTemplate, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(podtemplatesResource, c.ns, podTemplate), &core.PodTemplate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*core.PodTemplate), err
}

// Delete takes name of the podTemplate and deletes it. Returns an error if one occurs.
func (c *FakePodTemplates) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(podtemplatesResource, c.ns, name), &core.PodTemplate{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakePodTemplates) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(podtemplatesResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &core.PodTemplateList{})
	return err
}

// Patch applies the patch and returns the patched podTemplate.
func (c *FakePodTemplates) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *core.PodTemplate, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(podtemplatesResource, c.ns, name, data, subresources...), &core.PodTemplate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*core.PodTemplate), err
}
