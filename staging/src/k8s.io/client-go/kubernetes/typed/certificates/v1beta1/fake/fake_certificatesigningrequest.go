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
	v1beta1 "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeCertificateSigningRequests implements CertificateSigningRequestInterface
type FakeCertificateSigningRequests struct {
	Fake *FakeCertificatesV1beta1
}

var certificatesigningrequestsResource = schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1beta1", Resource: "certificatesigningrequests"}

var certificatesigningrequestsKind = schema.GroupVersionKind{Group: "certificates.k8s.io", Version: "v1beta1", Kind: "CertificateSigningRequest"}

// Get takes name of the certificateSigningRequest, and returns the corresponding certificateSigningRequest object, and an error if there is any.
func (c *FakeCertificateSigningRequests) Get(name string, options v1.GetOptions) (result *v1beta1.CertificateSigningRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(certificatesigningrequestsResource, name), &v1beta1.CertificateSigningRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.CertificateSigningRequest), err
}

// List takes label and field selectors, and returns the list of CertificateSigningRequests that match those selectors.
func (c *FakeCertificateSigningRequests) List(opts v1.ListOptions) (result *v1beta1.CertificateSigningRequestList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(certificatesigningrequestsResource, certificatesigningrequestsKind, opts), &v1beta1.CertificateSigningRequestList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1beta1.CertificateSigningRequestList{}
	for _, item := range obj.(*v1beta1.CertificateSigningRequestList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested certificateSigningRequests.
func (c *FakeCertificateSigningRequests) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(certificatesigningrequestsResource, opts))
}

// Create takes the representation of a certificateSigningRequest and creates it.  Returns the server's representation of the certificateSigningRequest, and an error, if there is any.
func (c *FakeCertificateSigningRequests) Create(certificateSigningRequest *v1beta1.CertificateSigningRequest) (result *v1beta1.CertificateSigningRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(certificatesigningrequestsResource, certificateSigningRequest), &v1beta1.CertificateSigningRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.CertificateSigningRequest), err
}

// Update takes the representation of a certificateSigningRequest and updates it. Returns the server's representation of the certificateSigningRequest, and an error, if there is any.
func (c *FakeCertificateSigningRequests) Update(certificateSigningRequest *v1beta1.CertificateSigningRequest) (result *v1beta1.CertificateSigningRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(certificatesigningrequestsResource, certificateSigningRequest), &v1beta1.CertificateSigningRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.CertificateSigningRequest), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeCertificateSigningRequests) UpdateStatus(certificateSigningRequest *v1beta1.CertificateSigningRequest) (*v1beta1.CertificateSigningRequest, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(certificatesigningrequestsResource, "status", certificateSigningRequest), &v1beta1.CertificateSigningRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.CertificateSigningRequest), err
}

// Delete takes name of the certificateSigningRequest and deletes it. Returns an error if one occurs.
func (c *FakeCertificateSigningRequests) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(certificatesigningrequestsResource, name), &v1beta1.CertificateSigningRequest{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCertificateSigningRequests) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(certificatesigningrequestsResource, listOptions)

	_, err := c.Fake.Invokes(action, &v1beta1.CertificateSigningRequestList{})
	return err
}

// Patch applies the patch and returns the patched certificateSigningRequest.
func (c *FakeCertificateSigningRequests) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1beta1.CertificateSigningRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(certificatesigningrequestsResource, name, data, subresources...), &v1beta1.CertificateSigningRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.CertificateSigningRequest), err
}
