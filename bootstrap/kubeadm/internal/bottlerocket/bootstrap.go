// This file defines the core bootstrap templates required
// to bootstrap Bottlerocket
package bottlerocket

const (
	kubernetesInitTemplate = `{{ define "kubernetesInitSettings" -}}
[settings.kubernetes]
{{- if .ClusterDomain }}
cluster-domain = "{{.ClusterDomain}}"
{{- else }}
cluster-domain = "cluster.local"
{{- end }}
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "{{.PauseContainerSource}}"
{{- if (ne .ProviderID "")}}
provider-id = "{{.ProviderID}}"
{{- end -}}
{{- if .AllowedUnsafeSysctls }}
allowed-unsafe-sysctls = [{{stringsJoin .AllowedUnsafeSysctls ", " }}]
{{- end -}}
{{- if .ClusterDNSIPs }}
cluster-dns-ip = [{{stringsJoin .ClusterDNSIPs ", " }}]
{{- end -}}
{{- if ne .CPUCFSQuota nil }}
cpu-cfs-quota-enforced = {{ .CPUCFSQuota }}
{{- end -}}
{{- if .MaxPods }}
max-pods = {{.MaxPods}}
{{- end -}}
{{- if .ContainerLogMaxFiles }}
container-log-max-files = {{.ContainerLogMaxFiles}}
{{- end -}}
{{- if .ContainerLogMaxSize }}
container-log-max-size = "{{.ContainerLogMaxSize}}"
{{- end -}}
{{- if .CPUManagerPolicy }}
cpu-manager-policy = "{{.CPUManagerPolicy}}"
{{- if .CPUManagerPolicyOptions }}
{{- range $key, $value := .CPUManagerPolicyOptions }}
{{- if (eq $key "full-pcpus-only")}}
cpu-manager-policy-options = ["{{ $key }}"]
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- if .CPUManagerReconcilePeriod }}
cpu-manager-reconcile-period = {{.CPUManagerReconcilePeriod}}
{{- end -}}
{{- if .EventBurst }}
event-burst = {{.EventBurst}}
{{- end -}}
{{- if .EventRecordQPS }}
event-qps = {{.EventRecordQPS}}
{{- end -}}
{{- if .EvictionMaxPodGracePeriod }}
eviction-max-pod-grace-period = {{.EvictionMaxPodGracePeriod}}
{{- end -}}
{{- if .ImageGCHighThresholdPercent }}
image-gc-high-threshold-percent = {{.ImageGCHighThresholdPercent}}
{{- end -}}
{{- if .ImageGCLowThresholdPercent }}
image-gc-low-threshold-percent = {{.ImageGCLowThresholdPercent}}
{{- end -}}
{{- if .KubeAPIBurst }}
kube-api-burst = {{.KubeAPIBurst}}
{{- end -}}
{{- if .KubeAPIQPS }}
kube-api-qps = {{.KubeAPIQPS}}
{{- end -}}
{{- if .MemoryManagerPolicy }}
memory-manager-policy = "{{.MemoryManagerPolicy}}"
{{- end -}}
{{- if .PodPidsLimit }}
pod-pids-limit = {{.PodPidsLimit}}
{{- end -}}
{{- if .RegistryBurst }}
registry-burst = {{.RegistryBurst}}
{{- end -}}
{{- if .RegistryPullQPS }}
registry-qps = {{.RegistryPullQPS}}
{{- end -}}
{{- if .ShutdownGracePeriod }}
shutdown-grace-period = {{.ShutdownGracePeriod}}
{{- end -}}
{{- if .ShutdownGracePeriodCriticalPods }}
shutdown-grace-period-for-critical-pods = {{.ShutdownGracePeriodCriticalPods}}
{{- end -}}
{{- if .TopologyManagerPolicy }}
topology-manager-policy = "{{.TopologyManagerPolicy}}"
{{- end -}}
{{- if .TopologyManagerScope }}
topology-manager-scope = "{{.TopologyManagerScope}}"
{{- end -}}
{{- end -}}
`

	evictionHardTemplate = `{{ define "evictionHardSettings" -}}
[settings.kubernetes.eviction-hard]
{{- range $key, $value := .EvictionHard }}
"{{ $key }}" = "{{ $value }}"
{{- end }}
{{- end }}
`

	evictionSoftTemplate = `{{ define "evictionSoftSettings" -}}
[settings.kubernetes.eviction-soft]
{{- range $key, $value := .EvictionSoft }}
"{{ $key }}" = "{{ $value }}"
{{- end }}
{{- end }}
`

	evictionSoftGracePeriodTemplate = `{{ define "evictionSoftGracePeriodSettings" -}}
[settings.kubernetes.eviction-soft-grace-period]
{{- range $key, $value := .EvictionSoftGracePeriod }}
"{{ $key }}" = "{{ $value }}"
{{- end }}
{{- end }}
`

	kubeReservedTemplate = `{{ define "kubeReservedSettings" -}}
[settings.kubernetes.kube-reserved]
{{- range $key, $value := .KubeReserved }}
{{ $key }} = "{{ $value }}"
{{- end }}
{{- end }}
`

	systemReservedTemplate = `{{ define "systemReservedSettings" -}}
[settings.kubernetes.system-reserved]
{{- range $key, $value := .SystemReserved }}
{{ $key }} = "{{ $value }}"
{{- end -}}
{{- end -}}
`

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
	networkInitTemplate = `{{ define "networkInitSettings" -}}
[settings.network]
hostname = "{{.Hostname}}"
{{- if (ne .HTTPSProxyEndpoint "")}}
https-proxy = "{{.HTTPSProxyEndpoint}}"
no-proxy = [{{stringsJoin .NoProxyEndpoints "," }}]
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

	sysctlSettingsTemplate = `{{ define "sysctlSettingsTemplate" -}}
[settings.kernel.sysctl]
{{.SysctlSettings}}
{{- end -}}
`

	bootSettingsTemplate = `{{ define "bootSettings" -}}
[settings.boot]
reboot-to-reconcile = true

[settings.boot.kernel-parameters]
{{.BootKernel}}
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

{{template "kubernetesInitSettings" .}}

{{- if .EvictionHard}}
{{template "evictionHardSettings" .}}
{{- end}}

{{- if .EvictionSoft}}
{{template "evictionSoftSettings" .}}
{{- end}}

{{- if .EvictionSoftGracePeriod}}
{{template "evictionSoftGracePeriodSettings" .}}
{{- end}}

{{- if .KubeReserved}}
{{template "kubeReservedSettings" .}}
{{- end}}

{{- if .SystemReserved}}
{{template "systemReservedSettings" .}}
{{- end}}

{{template "networkInitSettings" .}}

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

{{- if (ne .SysctlSettings "")}}
{{template "sysctlSettingsTemplate" .}}
{{- end -}}

{{- if .BootKernel}}
{{template "bootSettings" .}}
{{- end -}}

{{- if .CertBundles}}
{{template "certBundlesSlice" .}}
{{- end -}}
`
)
