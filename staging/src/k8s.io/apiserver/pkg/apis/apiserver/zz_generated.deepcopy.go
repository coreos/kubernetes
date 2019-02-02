// +build !ignore_autogenerated

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

// This file was autogenerated by deepcopy-gen. Do not edit it manually!

package apiserver

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdmissionConfiguration) DeepCopyInto(out *AdmissionConfiguration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.Plugins != nil {
		in, out := &in.Plugins, &out.Plugins
		*out = make([]AdmissionPluginConfiguration, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdmissionConfiguration.
func (in *AdmissionConfiguration) DeepCopy() *AdmissionConfiguration {
	if in == nil {
		return nil
	}
	out := new(AdmissionConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AdmissionConfiguration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	} else {
		return nil
	}
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdmissionPluginConfiguration) DeepCopyInto(out *AdmissionPluginConfiguration) {
	*out = *in
	if in.Configuration != nil {
		in, out := &in.Configuration, &out.Configuration
		if *in == nil {
			*out = nil
		} else {
			*out = new(runtime.Unknown)
			(*in).DeepCopyInto(*out)
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdmissionPluginConfiguration.
func (in *AdmissionPluginConfiguration) DeepCopy() *AdmissionPluginConfiguration {
	if in == nil {
		return nil
	}
	out := new(AdmissionPluginConfiguration)
	in.DeepCopyInto(out)
	return out
}
