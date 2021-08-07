/*
Copyright 2021 The Kubernetes Authors.

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

package builder

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// EtcdGroupVersion is group version used for control plane objects.
	EtcdGroupVersion = schema.GroupVersion{Group: "etcd.cluster.x-k8s.io", Version: "v1beta1"}

	// GenericEtcdKind is the Kind for the GenericEtcd.
	GenericEtcdKind = "GenericEtcd"
	// GenericEtcdCRD is a generic control plane CRD.
	GenericEtcdCRD = testEtcdCRD(EtcdGroupVersion.WithKind(GenericEtcdKind))
)

func testEtcdCRD(gvk schema.GroupVersionKind) *apiextensionsv1.CustomResourceDefinition {
	return generateCRD(gvk, map[string]apiextensionsv1.JSONSchemaProps{
		"metadata": {
			// NOTE: in CRD there is only a partial definition of metadata schema.
			// Ref https://github.com/kubernetes-sigs/controller-tools/blob/59485af1c1f6a664655dad49543c474bb4a0d2a2/pkg/crd/gen.go#L185
			Type: "object",
		},
		"spec": etcdSpecSchema,
		"status": {
			Type: "object",
			Properties: map[string]apiextensionsv1.JSONSchemaProps{
				// mandatory fields from the Cluster API contract
				"ready":       {Type: "boolean"},
				"initialized": {Type: "boolean"},
				"endpoints":   {Type: "string"},
			},
		},
	})
}

var etcdSpecSchema = apiextensionsv1.JSONSchemaProps{
	Type:       "object",
	Properties: map[string]apiextensionsv1.JSONSchemaProps{},
}

// EtcdPlaneBuilder holds the variables and objects needed to build a generic object for cluster.spec.ManagedExternalEtcdRef.
type EtcdPlaneBuilder struct {
	obj *unstructured.Unstructured
}

// Etcd returns a EtcdBuilder with the given name and Namespace.
func Etcd(namespace, name string) *EtcdPlaneBuilder {
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion(EtcdGroupVersion.String())
	obj.SetKind(GenericEtcdKind)
	obj.SetNamespace(namespace)
	obj.SetName(name)
	return &EtcdPlaneBuilder{
		obj: obj,
	}
}

// Build generates an Unstructured object from the information passed to the EtcdPlaneBuilder.
func (c *EtcdPlaneBuilder) Build() *unstructured.Unstructured {
	return c.obj
}
