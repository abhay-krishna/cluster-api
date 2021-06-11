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
no-proxy = "{{.NoProxyEndpoints}}"
{{- end -}}
`
	bottlerocketNodeInitSettingsTemplate = `{{template "bootstrapHostContainerSettings" .}}

{{template "adminContainerInitSettings" .}}

{{template "kubernetesInitSettings" .}}

{{- if (ne .HTTPSProxyEndpoint "")}}
{{template "networkInitSettings" .}}
{{- end -}}
`
)
