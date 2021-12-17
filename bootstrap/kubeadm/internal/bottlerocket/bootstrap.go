// This file defines the core bootstrap templates required
// to bootstrap Bottlerocket
package bottlerocket

const (
	adminContainerInitTemplate = `{{ define "adminContainerInitSettings" -}}
[settings.host-containers.admin]
enabled = true
user-data = "{{.AdminContainerUserData}}"
{{- end -}}
`
	kubernetesInitTemplate = `{{ define "kubernetesInitSettings" -}}
[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "{{.PauseContainerSource}}"
{{- end -}}
`

	bootstrapHostContainerTemplate = `{{define "bootstrapHostContainerSettings" -}}
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "{{.BootstrapContainerSource}}"
user-data = "{{.BootstrapContainerUserData}}"
{{- end -}}
`
	networkInitTemplate = `{{ define "networkInitSettings" -}}
[settings.network]
https-proxy = "{{.HTTPSProxyEndpoint}}"
no-proxy = [{{stringsJoin .NoProxyEndpoints "," }}]
{{- end -}}
`
	registryMirrorTemplate = `{{ define "registryMirrorSettings" -}}
[settings.container-registry.mirrors]
"public.ecr.aws" = ["https://{{.RegistryMirrorEndpoint}}"]
{{- end -}}
`
	registryMirrorCACertTemplate = `{{ define "registryMirrorCACertSettings" -}}
[settings.pki.registry-mirror-ca]
data = "{{.RegistryMirrorCACert}}"
trusted=true
{{- end -}}
`
	nodeLabelsTemplate = `{{ define "nodeLabelSettings" -}}
[settings.kubernetes.node-labels]
{{.NodeLabels}}
{{- end -}}
`
	taintsTemplate = `{{ define "taintsTemplate" -}}
[settings.kubernetes.node-taints]
{{.Taints}}
{{- end -}}
`

	bottlerocketNodeInitSettingsTemplate = `{{template "bootstrapHostContainerSettings" .}}

{{template "adminContainerInitSettings" .}}

{{template "kubernetesInitSettings" .}}

{{- if (ne .HTTPSProxyEndpoint "")}}
{{template "networkInitSettings" .}}
{{- end -}}

{{- if (ne .RegistryMirrorEndpoint "")}}
{{template "registryMirrorSettings" .}}
{{- end -}}

{{- if (ne .RegistryMirrorCACert "")}}
{{template "registryMirrorCACertSettings" .}}
{{- end -}}

{{- if (ne .NodeLabels "")}}
{{template "nodeLabelSettings" .}}
{{- end -}}

{{- if (ne .Taints "")}}
{{template "taintsTemplate" .}}
{{- end -}}
`
)
