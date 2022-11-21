// This file defines the core bootstrap templates required
// to bootstrap Bottlerocket
package bottlerocket

const (
	kubernetesInitTemplate = `{{ define "kubernetesInitSettings" -}}
[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "{{.PauseContainerSource}}"
{{- if (ne .ProviderId "")}}
provider-id = "{{.ProviderId}}"
{{- end -}}
{{- end -}}
`

	hostContainerTemplate = `{{define "hostContainerSettings" -}}
[settings.host-containers.{{.Name}}]
enabled = true
superpowered = {{.Superpowered}}
{{- if (ne (imageUrl .ImageMeta) "")}}
source = "{{imageUrl .ImageMeta}}"
{{- end -}}
{{- if (ne .UserData "")}}
user-data = "{{.UserData}}"
{{- end -}}
{{- end -}}
`

	hostContainerSliceTemplate = `{{define "hostContainerSlice" -}}
{{- range $hContainer := .HostContainers }}
{{template "hostContainerSettings" $hContainer }}
{{- end -}}
{{- end -}}
`

	bootstrapContainerTemplate = `{{ define "bootstrapContainerSettings" -}}
[settings.bootstrap-containers.{{.Name}}]
essential = {{.Essential}}
mode = "{{.Mode}}"
{{- if (ne (imageUrl .ImageMeta) "")}}
source = "{{imageUrl .ImageMeta}}"
{{- end -}}
{{- if (ne .UserData "")}}
user-data = "{{.UserData}}"
{{- end -}}
{{- end -}}
`

	bootstrapContainerSliceTemplate = `{{ define "bootstrapContainerSlice" -}}
{{- range $bContainer := .BootstrapContainers }}
{{template "bootstrapContainerSettings" $bContainer }}
{{- end -}}
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

	bottlerocketNodeInitSettingsTemplate = `{{template "hostContainerSlice" .}}

{{template "kubernetesInitSettings" .}}

{{- if .BootstrapContainers}}
{{template "bootstrapContainerSlice" .}}
{{- end -}}

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
