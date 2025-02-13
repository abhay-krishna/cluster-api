//go:build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

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

// Code generated by controller-gen. DO NOT EDIT.

package upstreamv1beta1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *APIEndpoint) DeepCopyInto(out *APIEndpoint) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new APIEndpoint.
func (in *APIEndpoint) DeepCopy() *APIEndpoint {
	if in == nil {
		return nil
	}
	out := new(APIEndpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *APIServer) DeepCopyInto(out *APIServer) {
	*out = *in
	in.ControlPlaneComponent.DeepCopyInto(&out.ControlPlaneComponent)
	if in.CertSANs != nil {
		in, out := &in.CertSANs, &out.CertSANs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TimeoutForControlPlane != nil {
		in, out := &in.TimeoutForControlPlane, &out.TimeoutForControlPlane
		*out = new(v1.Duration)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new APIServer.
func (in *APIServer) DeepCopy() *APIServer {
	if in == nil {
		return nil
	}
	out := new(APIServer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BootstrapToken) DeepCopyInto(out *BootstrapToken) {
	*out = *in
	if in.Token != nil {
		in, out := &in.Token, &out.Token
		*out = new(BootstrapTokenString)
		**out = **in
	}
	if in.TTL != nil {
		in, out := &in.TTL, &out.TTL
		*out = new(v1.Duration)
		**out = **in
	}
	if in.Expires != nil {
		in, out := &in.Expires, &out.Expires
		*out = (*in).DeepCopy()
	}
	if in.Usages != nil {
		in, out := &in.Usages, &out.Usages
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Groups != nil {
		in, out := &in.Groups, &out.Groups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BootstrapToken.
func (in *BootstrapToken) DeepCopy() *BootstrapToken {
	if in == nil {
		return nil
	}
	out := new(BootstrapToken)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BootstrapTokenDiscovery) DeepCopyInto(out *BootstrapTokenDiscovery) {
	*out = *in
	if in.CACertHashes != nil {
		in, out := &in.CACertHashes, &out.CACertHashes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BootstrapTokenDiscovery.
func (in *BootstrapTokenDiscovery) DeepCopy() *BootstrapTokenDiscovery {
	if in == nil {
		return nil
	}
	out := new(BootstrapTokenDiscovery)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BootstrapTokenString) DeepCopyInto(out *BootstrapTokenString) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BootstrapTokenString.
func (in *BootstrapTokenString) DeepCopy() *BootstrapTokenString {
	if in == nil {
		return nil
	}
	out := new(BootstrapTokenString)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BottlerocketAdmin) DeepCopyInto(out *BottlerocketAdmin) {
	*out = *in
	out.ImageMeta = in.ImageMeta
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BottlerocketAdmin.
func (in *BottlerocketAdmin) DeepCopy() *BottlerocketAdmin {
	if in == nil {
		return nil
	}
	out := new(BottlerocketAdmin)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BottlerocketBootSettings) DeepCopyInto(out *BottlerocketBootSettings) {
	*out = *in
	if in.BootKernelParameters != nil {
		in, out := &in.BootKernelParameters, &out.BootKernelParameters
		*out = make(map[string][]string, len(*in))
		for key, val := range *in {
			var outVal []string
			if val == nil {
				(*out)[key] = nil
			} else {
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = make([]string, len(*in))
				copy(*out, *in)
			}
			(*out)[key] = outVal
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BottlerocketBootSettings.
func (in *BottlerocketBootSettings) DeepCopy() *BottlerocketBootSettings {
	if in == nil {
		return nil
	}
	out := new(BottlerocketBootSettings)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BottlerocketBootstrap) DeepCopyInto(out *BottlerocketBootstrap) {
	*out = *in
	out.ImageMeta = in.ImageMeta
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BottlerocketBootstrap.
func (in *BottlerocketBootstrap) DeepCopy() *BottlerocketBootstrap {
	if in == nil {
		return nil
	}
	out := new(BottlerocketBootstrap)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BottlerocketBootstrapContainer) DeepCopyInto(out *BottlerocketBootstrapContainer) {
	*out = *in
	out.ImageMeta = in.ImageMeta
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BottlerocketBootstrapContainer.
func (in *BottlerocketBootstrapContainer) DeepCopy() *BottlerocketBootstrapContainer {
	if in == nil {
		return nil
	}
	out := new(BottlerocketBootstrapContainer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BottlerocketControl) DeepCopyInto(out *BottlerocketControl) {
	*out = *in
	out.ImageMeta = in.ImageMeta
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BottlerocketControl.
func (in *BottlerocketControl) DeepCopy() *BottlerocketControl {
	if in == nil {
		return nil
	}
	out := new(BottlerocketControl)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BottlerocketHostContainer) DeepCopyInto(out *BottlerocketHostContainer) {
	*out = *in
	out.ImageMeta = in.ImageMeta
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BottlerocketHostContainer.
func (in *BottlerocketHostContainer) DeepCopy() *BottlerocketHostContainer {
	if in == nil {
		return nil
	}
	out := new(BottlerocketHostContainer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BottlerocketKernelSettings) DeepCopyInto(out *BottlerocketKernelSettings) {
	*out = *in
	if in.SysctlSettings != nil {
		in, out := &in.SysctlSettings, &out.SysctlSettings
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BottlerocketKernelSettings.
func (in *BottlerocketKernelSettings) DeepCopy() *BottlerocketKernelSettings {
	if in == nil {
		return nil
	}
	out := new(BottlerocketKernelSettings)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BottlerocketKubernetesSettings) DeepCopyInto(out *BottlerocketKubernetesSettings) {
	*out = *in
	if in.AllowedUnsafeSysctls != nil {
		in, out := &in.AllowedUnsafeSysctls, &out.AllowedUnsafeSysctls
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.ClusterDNSIPs != nil {
		in, out := &in.ClusterDNSIPs, &out.ClusterDNSIPs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BottlerocketKubernetesSettings.
func (in *BottlerocketKubernetesSettings) DeepCopy() *BottlerocketKubernetesSettings {
	if in == nil {
		return nil
	}
	out := new(BottlerocketKubernetesSettings)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BottlerocketSettings) DeepCopyInto(out *BottlerocketSettings) {
	*out = *in
	if in.Kubernetes != nil {
		in, out := &in.Kubernetes, &out.Kubernetes
		*out = new(BottlerocketKubernetesSettings)
		(*in).DeepCopyInto(*out)
	}
	if in.Kernel != nil {
		in, out := &in.Kernel, &out.Kernel
		*out = new(BottlerocketKernelSettings)
		(*in).DeepCopyInto(*out)
	}
	if in.Boot != nil {
		in, out := &in.Boot, &out.Boot
		*out = new(BottlerocketBootSettings)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BottlerocketSettings.
func (in *BottlerocketSettings) DeepCopy() *BottlerocketSettings {
	if in == nil {
		return nil
	}
	out := new(BottlerocketSettings)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertBundle) DeepCopyInto(out *CertBundle) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertBundle.
func (in *CertBundle) DeepCopy() *CertBundle {
	if in == nil {
		return nil
	}
	out := new(CertBundle)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterConfiguration) DeepCopyInto(out *ClusterConfiguration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.Pause = in.Pause
	out.BottlerocketBootstrap = in.BottlerocketBootstrap
	out.BottlerocketAdmin = in.BottlerocketAdmin
	out.BottlerocketControl = in.BottlerocketControl
	in.Proxy.DeepCopyInto(&out.Proxy)
	in.RegistryMirror.DeepCopyInto(&out.RegistryMirror)
	in.Etcd.DeepCopyInto(&out.Etcd)
	out.Networking = in.Networking
	in.APIServer.DeepCopyInto(&out.APIServer)
	in.ControllerManager.DeepCopyInto(&out.ControllerManager)
	in.Scheduler.DeepCopyInto(&out.Scheduler)
	out.DNS = in.DNS
	if in.FeatureGates != nil {
		in, out := &in.FeatureGates, &out.FeatureGates
		*out = make(map[string]bool, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.BottlerocketHostContainers != nil {
		in, out := &in.BottlerocketHostContainers, &out.BottlerocketHostContainers
		*out = make([]BottlerocketHostContainer, len(*in))
		copy(*out, *in)
	}
	if in.BottlerocketCustomBootstrapContainers != nil {
		in, out := &in.BottlerocketCustomBootstrapContainers, &out.BottlerocketCustomBootstrapContainers
		*out = make([]BottlerocketBootstrapContainer, len(*in))
		copy(*out, *in)
	}
	if in.Bottlerocket != nil {
		in, out := &in.Bottlerocket, &out.Bottlerocket
		*out = new(BottlerocketSettings)
		(*in).DeepCopyInto(*out)
	}
	if in.CertBundles != nil {
		in, out := &in.CertBundles, &out.CertBundles
		*out = make([]CertBundle, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterConfiguration.
func (in *ClusterConfiguration) DeepCopy() *ClusterConfiguration {
	if in == nil {
		return nil
	}
	out := new(ClusterConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterConfiguration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterStatus) DeepCopyInto(out *ClusterStatus) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.APIEndpoints != nil {
		in, out := &in.APIEndpoints, &out.APIEndpoints
		*out = make(map[string]APIEndpoint, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterStatus.
func (in *ClusterStatus) DeepCopy() *ClusterStatus {
	if in == nil {
		return nil
	}
	out := new(ClusterStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterStatus) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ControlPlaneComponent) DeepCopyInto(out *ControlPlaneComponent) {
	*out = *in
	if in.ExtraArgs != nil {
		in, out := &in.ExtraArgs, &out.ExtraArgs
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.ExtraVolumes != nil {
		in, out := &in.ExtraVolumes, &out.ExtraVolumes
		*out = make([]HostPathMount, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ControlPlaneComponent.
func (in *ControlPlaneComponent) DeepCopy() *ControlPlaneComponent {
	if in == nil {
		return nil
	}
	out := new(ControlPlaneComponent)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DNS) DeepCopyInto(out *DNS) {
	*out = *in
	out.ImageMeta = in.ImageMeta
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DNS.
func (in *DNS) DeepCopy() *DNS {
	if in == nil {
		return nil
	}
	out := new(DNS)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Discovery) DeepCopyInto(out *Discovery) {
	*out = *in
	if in.BootstrapToken != nil {
		in, out := &in.BootstrapToken, &out.BootstrapToken
		*out = new(BootstrapTokenDiscovery)
		(*in).DeepCopyInto(*out)
	}
	if in.File != nil {
		in, out := &in.File, &out.File
		*out = new(FileDiscovery)
		**out = **in
	}
	if in.Timeout != nil {
		in, out := &in.Timeout, &out.Timeout
		*out = new(v1.Duration)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Discovery.
func (in *Discovery) DeepCopy() *Discovery {
	if in == nil {
		return nil
	}
	out := new(Discovery)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Etcd) DeepCopyInto(out *Etcd) {
	*out = *in
	if in.Local != nil {
		in, out := &in.Local, &out.Local
		*out = new(LocalEtcd)
		(*in).DeepCopyInto(*out)
	}
	if in.External != nil {
		in, out := &in.External, &out.External
		*out = new(ExternalEtcd)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Etcd.
func (in *Etcd) DeepCopy() *Etcd {
	if in == nil {
		return nil
	}
	out := new(Etcd)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExternalEtcd) DeepCopyInto(out *ExternalEtcd) {
	*out = *in
	if in.Endpoints != nil {
		in, out := &in.Endpoints, &out.Endpoints
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalEtcd.
func (in *ExternalEtcd) DeepCopy() *ExternalEtcd {
	if in == nil {
		return nil
	}
	out := new(ExternalEtcd)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FileDiscovery) DeepCopyInto(out *FileDiscovery) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FileDiscovery.
func (in *FileDiscovery) DeepCopy() *FileDiscovery {
	if in == nil {
		return nil
	}
	out := new(FileDiscovery)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HostPathMount) DeepCopyInto(out *HostPathMount) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HostPathMount.
func (in *HostPathMount) DeepCopy() *HostPathMount {
	if in == nil {
		return nil
	}
	out := new(HostPathMount)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageMeta) DeepCopyInto(out *ImageMeta) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageMeta.
func (in *ImageMeta) DeepCopy() *ImageMeta {
	if in == nil {
		return nil
	}
	out := new(ImageMeta)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InitConfiguration) DeepCopyInto(out *InitConfiguration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.BootstrapTokens != nil {
		in, out := &in.BootstrapTokens, &out.BootstrapTokens
		*out = make([]BootstrapToken, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	in.NodeRegistration.DeepCopyInto(&out.NodeRegistration)
	out.LocalAPIEndpoint = in.LocalAPIEndpoint
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InitConfiguration.
func (in *InitConfiguration) DeepCopy() *InitConfiguration {
	if in == nil {
		return nil
	}
	out := new(InitConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *InitConfiguration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JoinConfiguration) DeepCopyInto(out *JoinConfiguration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.Pause = in.Pause
	out.BottlerocketBootstrap = in.BottlerocketBootstrap
	out.BottlerocketAdmin = in.BottlerocketAdmin
	out.BottlerocketControl = in.BottlerocketControl
	in.Proxy.DeepCopyInto(&out.Proxy)
	in.RegistryMirror.DeepCopyInto(&out.RegistryMirror)
	in.NodeRegistration.DeepCopyInto(&out.NodeRegistration)
	in.Discovery.DeepCopyInto(&out.Discovery)
	if in.ControlPlane != nil {
		in, out := &in.ControlPlane, &out.ControlPlane
		*out = new(JoinControlPlane)
		**out = **in
	}
	if in.BottlerocketCustomHostContainers != nil {
		in, out := &in.BottlerocketCustomHostContainers, &out.BottlerocketCustomHostContainers
		*out = make([]BottlerocketHostContainer, len(*in))
		copy(*out, *in)
	}
	if in.BottlerocketCustomBootstrapContainers != nil {
		in, out := &in.BottlerocketCustomBootstrapContainers, &out.BottlerocketCustomBootstrapContainers
		*out = make([]BottlerocketBootstrapContainer, len(*in))
		copy(*out, *in)
	}
	if in.Bottlerocket != nil {
		in, out := &in.Bottlerocket, &out.Bottlerocket
		*out = new(BottlerocketSettings)
		(*in).DeepCopyInto(*out)
	}
	if in.CertBundles != nil {
		in, out := &in.CertBundles, &out.CertBundles
		*out = make([]CertBundle, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JoinConfiguration.
func (in *JoinConfiguration) DeepCopy() *JoinConfiguration {
	if in == nil {
		return nil
	}
	out := new(JoinConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *JoinConfiguration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JoinControlPlane) DeepCopyInto(out *JoinControlPlane) {
	*out = *in
	out.LocalAPIEndpoint = in.LocalAPIEndpoint
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JoinControlPlane.
func (in *JoinControlPlane) DeepCopy() *JoinControlPlane {
	if in == nil {
		return nil
	}
	out := new(JoinControlPlane)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LocalEtcd) DeepCopyInto(out *LocalEtcd) {
	*out = *in
	out.ImageMeta = in.ImageMeta
	if in.ExtraArgs != nil {
		in, out := &in.ExtraArgs, &out.ExtraArgs
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.ServerCertSANs != nil {
		in, out := &in.ServerCertSANs, &out.ServerCertSANs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.PeerCertSANs != nil {
		in, out := &in.PeerCertSANs, &out.PeerCertSANs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LocalEtcd.
func (in *LocalEtcd) DeepCopy() *LocalEtcd {
	if in == nil {
		return nil
	}
	out := new(LocalEtcd)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Mirror) DeepCopyInto(out *Mirror) {
	*out = *in
	if in.Endpoints != nil {
		in, out := &in.Endpoints, &out.Endpoints
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Mirror.
func (in *Mirror) DeepCopy() *Mirror {
	if in == nil {
		return nil
	}
	out := new(Mirror)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Networking) DeepCopyInto(out *Networking) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Networking.
func (in *Networking) DeepCopy() *Networking {
	if in == nil {
		return nil
	}
	out := new(Networking)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodeRegistrationOptions) DeepCopyInto(out *NodeRegistrationOptions) {
	*out = *in
	if in.Taints != nil {
		in, out := &in.Taints, &out.Taints
		*out = make([]corev1.Taint, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.KubeletExtraArgs != nil {
		in, out := &in.KubeletExtraArgs, &out.KubeletExtraArgs
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeRegistrationOptions.
func (in *NodeRegistrationOptions) DeepCopy() *NodeRegistrationOptions {
	if in == nil {
		return nil
	}
	out := new(NodeRegistrationOptions)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Pause) DeepCopyInto(out *Pause) {
	*out = *in
	out.ImageMeta = in.ImageMeta
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Pause.
func (in *Pause) DeepCopy() *Pause {
	if in == nil {
		return nil
	}
	out := new(Pause)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProxyConfiguration) DeepCopyInto(out *ProxyConfiguration) {
	*out = *in
	if in.NoProxy != nil {
		in, out := &in.NoProxy, &out.NoProxy
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProxyConfiguration.
func (in *ProxyConfiguration) DeepCopy() *ProxyConfiguration {
	if in == nil {
		return nil
	}
	out := new(ProxyConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RegistryMirrorConfiguration) DeepCopyInto(out *RegistryMirrorConfiguration) {
	*out = *in
	if in.Mirrors != nil {
		in, out := &in.Mirrors, &out.Mirrors
		*out = make([]Mirror, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RegistryMirrorConfiguration.
func (in *RegistryMirrorConfiguration) DeepCopy() *RegistryMirrorConfiguration {
	if in == nil {
		return nil
	}
	out := new(RegistryMirrorConfiguration)
	in.DeepCopyInto(out)
	return out
}
