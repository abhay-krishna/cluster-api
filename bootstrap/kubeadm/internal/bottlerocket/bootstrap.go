// This file defines the core bootstrap templates required
// to bootstrap Bottlerocket
package bottlerocket

const (
	hostContainerTemplate = `{{define "hostContainerSettings" -}}
[settings.host-containers.{{.Name}}]
enabled = true
superpowered = {{.Superpowered}}
{{- if (ne (imageURL .ImageMeta) "")}}
source = "{{imageURL .ImageMeta}}"
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
{{- if (ne (imageURL .ImageMeta) "")}}
source = "{{imageURL .ImageMeta}}"
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
	registryMirrorTemplate = `{{ define "registryMirrorSettings" -}}
{{- range $orig, $mirror := .RegistryMirrorMap }}
[[settings.container-registry.mirrors]]
registry = "{{ $orig }}"
endpoint = [{{stringsJoin $mirror "," }}]
{{- end -}}
{{- end -}}
`
	registryMirrorCACertTemplate = `{{ define "registryMirrorCACertSettings" -}}
[settings.pki.registry-mirror-ca]
data = "{{.RegistryMirrorCACert}}"
trusted=true
{{- end -}}
`
	// We need to assign creds for "public.ecr.aws" because host-ctr expects credentials to be assigned
	// to "public.ecr.aws" rather than the mirror's endpoint
	// TODO: Once the bottlerocket fixes are in we need to remove the "public.ecr.aws" creds
	registryMirrorCredentialsTemplate = `{{define "registryMirrorCredentialsSettings" -}}
{{- range $orig, $mirror := .RegistryMirrorMap }}
{{- if (eq $orig "public.ecr.aws")}}
[[settings.container-registry.credentials]]
registry = "{{ $orig }}"
username = "{{$.RegistryMirrorUsername}}"
password = "{{$.RegistryMirrorPassword}}"
{{- end }}
{{- end }}
[[settings.container-registry.credentials]]
registry = "{{.RegistryMirrorEndpoint}}"
username = "{{.RegistryMirrorUsername}}"
password = "{{.RegistryMirrorPassword}}"
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

	ntpTemplate = `{{ define "ntpSettings" -}}
[settings.ntp]
time-servers = [{{stringsJoin .NTPServers ", " }}]
{{- end -}}
`

	certsTemplate = `{{ define "certsSettings" -}}
[settings.pki.{{.Name}}]
data = "{{.Data}}"
trusted = true
{{- end -}}
`
	certBundlesSliceTemplate = `{{ define "certBundlesSlice" -}}
{{- range $cBundle := .CertBundles }}
{{template "certsSettings" $cBundle }}
{{- end -}}
{{- end -}}
`

	bottlerocketNodeInitSettingsTemplate = `{{template "hostContainerSlice" .}}

{{- if .BootstrapContainers}}
{{template "bootstrapContainerSlice" .}}
{{- end -}}

{{- if .RegistryMirrorMap}}
{{template "registryMirrorSettings" .}}
{{- end -}}

{{- if (ne .RegistryMirrorCACert "")}}
{{template "registryMirrorCACertSettings" .}}
{{- end -}}

{{- if and (ne .RegistryMirrorUsername "") (ne .RegistryMirrorPassword "")}}
{{template "registryMirrorCredentialsSettings" .}}
{{- end -}}

{{- if (ne .NodeLabels "")}}
{{template "nodeLabelSettings" .}}
{{- end -}}

{{- if (ne .Taints "")}}
{{template "taintsTemplate" .}}
{{- end -}}

{{- if .NTPServers}}
{{template "ntpSettings" .}}
{{- end -}}

{{- if .CertBundles}}
{{template "certBundlesSlice" .}}
{{- end -}}
`
)
