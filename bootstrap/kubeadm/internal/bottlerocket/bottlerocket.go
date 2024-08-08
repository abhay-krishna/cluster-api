package bottlerocket

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	bootstrapv1 "sigs.k8s.io/cluster-api/bootstrap/kubeadm/api/v1beta1"
)

const (
	standardJoinCommand = "kubeadm join --config /tmp/kubeadm-join-config.yaml %s"
	cloudConfigHeader   = `## template: jinja
#cloud-config
`
)

// BottlerocketConfig is the Bottlerocket configuration for a machine.
type BottlerocketConfig struct {
	Pause                                 bootstrapv1.Pause
	BottlerocketBootstrap                 bootstrapv1.BottlerocketBootstrap
	BottlerocketAdmin                     bootstrapv1.BottlerocketAdmin
	BottlerocketControl                   bootstrapv1.BottlerocketControl
	BottlerocketSettings                  *bootstrapv1.BottlerocketSettings
	ProxyConfiguration                    bootstrapv1.ProxyConfiguration
	RegistryMirrorConfiguration           bootstrapv1.RegistryMirrorConfiguration
	KubeletExtraArgs                      map[string]string
	Taints                                []corev1.Taint
	BottlerocketCustomHostContainers      []bootstrapv1.BottlerocketHostContainer
	BottlerocketCustomBootstrapContainers []bootstrapv1.BottlerocketBootstrapContainer
	NTPServers                            []string
	Hostname                              string
	CertBundle                            []bootstrapv1.CertBundle
	RegistryMirrorCredentials
}

// SettingsInput is the input for the Bottlerocket settings template.
type SettingsInput struct {
	NetworkSettings NetworkSettings    `toml:"network,omitempty"`
	Kubernetes      KubernetesSettings `toml:"kubernetes,omitempty"`
	Kernel          KernelSettings     `toml:"kernel,omitempty"`
	Boot            BootSettings       `toml:"boot,omitempty"`

	PauseContainerSource   string
	RegistryMirrorEndpoint string
	RegistryMirrorCACert   string
	RegistryMirrorUsername string
	RegistryMirrorPassword string
	NodeLabels             string
	NTPServers             []string
	Taints                 string
	HostContainers         []bootstrapv1.BottlerocketHostContainer
	BootstrapContainers    []bootstrapv1.BottlerocketBootstrapContainer
	CertBundles            []bootstrapv1.CertBundle
	RegistryMirrorMap      map[string][]string
}

// InitSettingsInput is the high level settings struct for the toml we are generating.
type InitSettingsInput struct {
	InitSettings *InitSettings `toml:"settings,omitempty"`
}

// InitSettings has all the other settings defined in the structure that Bottlerocket
// expects settings toml to be in.
type InitSettings struct {
	Kubernetes      *KubernetesSettings `toml:"kubernetes,omitempty"`
	Kernel          *KernelSettings     `toml:"kernel,omitempty"`
	Boot            *BootSettings       `toml:"boot,omitempty"`
	NetworkSettings *NetworkSettings    `toml:"network,omitempty"`
}

// NetworkSettings exposes and sets the settings for Network field under Settings.
type NetworkSettings struct {
	Hostname           string   `toml:"hostname,omitempty"`
	HTTPSProxyEndpoint string   `toml:"https-proxy,omitempty"`
	NoProxyEndpoints   []string `toml:"no-proxy,omitempty"`
}

// KernelSettings exposes and sets the settings for Kernel field under Settings.
type KernelSettings struct {
	SysctlSettings map[string]string `toml:"sysctl,omitempty"`
}

// BootSettings exposes and sets the settings for Boot field under Settings.
type BootSettings struct {
	RebootToReconcile bool                `toml:"reboot-to-reconcile,omitempty"`
	BootKernel        map[string][]string `toml:"kernel-parameters,omitempty"`
}

// KubernetesSettings exposes and sets the settings for Kubernetes field under Settings.
type KubernetesSettings struct {
	AllowedUnsafeSysctls            []string `toml:"allowed-unsafe-sysctls,omitempty"`
	AuthenticationMode              string   `toml:"authentication-mode,omitempty"`
	ClusterDNSIPs                   []string `toml:"cluster-dns-ip,omitempty"`
	ClusterDomain                   string   `toml:"cluster-domain,omitempty"`
	ContainerLogMaxFiles            *int     `toml:"container-log-max-files,omitempty"`
	ContainerLogMaxSize             string   `toml:"container-log-max-size,omitempty"`
	CPUCFSQuota                     *bool    `toml:"cpu-cfs-quota-enforced,omitempty"`
	CPUManagerPolicy                string   `toml:"cpu-manager-policy,omitempty"`
	CPUManagerPolicyOptions         []string `toml:"cpu-manager-policy-options,omitempty"`
	CPUManagerReconcilePeriod       string   `toml:"cpu-manager-reconcile-period,omitempty"`
	EventBurst                      *int     `toml:"event-burst,omitempty"`
	EventRecordQPS                  *int     `toml:"event-qps,omitempty"`
	EvictionMaxPodGracePeriod       *int     `toml:"eviction-max-pod-grace-period,omitempty"`
	ImageGCHighThresholdPercent     *int     `toml:"image-gc-high-threshold-percent,omitempty"`
	ImageGCLowThresholdPercent      *int     `toml:"image-gc-low-threshold-percent,omitempty"`
	KubeAPIBurst                    *int     `toml:"kube-api-burst,omitempty"`
	KubeAPIQPS                      *int     `toml:"kube-api-qps,omitempty"`
	MaxPods                         *int     `toml:"max-pods,omitempty"`
	MemoryManagerPolicy             string   `toml:"memory-manager-policy,omitempty"`
	PodInfraContainerImage          string   `toml:"pod-infra-container-image"`
	PodPidsLimit                    *int64   `toml:"pod-pids-limit,omitempty"`
	ProviderID                      string   `toml:"provider-id,omitempty"`
	RegistryBurst                   *int     `toml:"registry-burst,omitempty"`
	RegistryPullQPS                 *int     `toml:"registry-qps,omitempty"`
	ServerTLSBootstrap              bool     `toml:"server-tls-bootstrap"`
	ShutdownGracePeriod             string   `toml:"shutdown-grace-period,omitempty"`
	ShutdownGracePeriodCriticalPods string   `toml:"shutdown-grace-period-for-critical-pods,omitempty"`
	StandaloneMode                  bool     `toml:"standalone-mode,omitempty"`
	TopologyManagerPolicy           string   `toml:"topology-manager-policy,omitempty"`
	TopologyManagerScope            string   `toml:"topology-manager-scope,omitempty"`

	EvictionHard            map[string]string `toml:"eviction-hard,omitempty"`
	EvictionSoft            map[string]string `toml:"eviction-soft,omitempty"`
	EvictionSoftGracePeriod map[string]string `toml:"eviction-soft-grace-period,omitempty"`
	KubeReserved            map[string]string `toml:"kube-reserved,omitempty"`
	SystemReserved          map[string]string `toml:"system-reserved,omitempty"`
}

// HostPath holds the path and type of a host path volume.
type HostPath struct {
	Path string
	Type string
}

// RegistryMirrorCredentials holds registry mirror credentials to be configured on bottlerocket nodes.
type RegistryMirrorCredentials struct {
	Username string
	Password string
}

func generateBootstrapContainerUserData(kind string, tpl string, data interface{}) ([]byte, error) {
	tm := template.New(kind).Funcs(defaultTemplateFuncMap)
	if _, err := tm.Parse(filesTemplate); err != nil {
		return nil, errors.Wrap(err, "failed to parse files template")
	}

	t, err := tm.Parse(tpl)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse %s template", kind)
	}

	var out bytes.Buffer
	if err := t.Execute(&out, data); err != nil {
		return nil, errors.Wrapf(err, "failed to generate %s template", kind)
	}

	return out.Bytes(), nil
}

func generateAdminContainerUserData(kind string, tpl string, data interface{}) ([]byte, error) {
	tm := template.New(kind)
	if _, err := tm.Parse(usersTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse users - %s template", kind)
	}
	t, err := tm.Parse(tpl)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse %s template", kind)
	}
	var out bytes.Buffer
	if err := t.Execute(&out, data); err != nil {
		return nil, errors.Wrapf(err, "failed to generate %s template", kind)
	}
	return out.Bytes(), nil
}

func imageURL(containerLocation bootstrapv1.ImageMeta) string {
	if containerLocation.ImageRepository != "" && containerLocation.ImageTag != "" {
		return fmt.Sprintf("%s:%s", containerLocation.ImageRepository, containerLocation.ImageTag)
	}
	return ""
}

func generateNodeUserData(kind string, tpl string, data interface{}) ([]byte, error) {
	tm := template.New(kind).Funcs(template.FuncMap{
		"stringsJoin": strings.Join,
		"imageURL":    imageURL,
	})
	if _, err := tm.Parse(hostContainerTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse hostContainerSettings %s template", kind)
	}
	if _, err := tm.Parse(hostContainerSliceTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse hostContainerSettingsSlice %s template", kind)
	}
	if _, err := tm.Parse(bootstrapContainerTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse bootstrapContainerSettings %s template", kind)
	}
	if _, err := tm.Parse(bootstrapContainerSliceTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse bootstrapContainerSettingsSlice %s template", kind)
	}
	if _, err := tm.Parse(registryMirrorTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse registry mirror %s template", kind)
	}
	if _, err := tm.Parse(registryMirrorCACertTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse registry mirror ca cert %s template", kind)
	}
	if _, err := tm.Parse(registryMirrorCredentialsTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse registry mirror credentials %s template", kind)
	}
	if _, err := tm.Parse(nodeLabelsTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse node labels %s template", kind)
	}
	if _, err := tm.Parse(taintsTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse taints %s template", kind)
	}
	if _, err := tm.Parse(ntpTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse NTP %s template", kind)
	}
	if _, err := tm.Parse(certsTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse certs %s template", kind)
	}
	if _, err := tm.Parse(certBundlesSliceTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse cert bundles %s template", kind)
	}
	t, err := tm.Parse(tpl)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse %s template", kind)
	}

	var out bytes.Buffer
	if err := t.Execute(&out, data); err != nil {
		return nil, errors.Wrapf(err, "failed to generate %s template", kind)
	}
	return out.Bytes(), nil
}

// getBottlerocketNodeUserData returns the userdata for the host bottlerocket in toml format
func getBottlerocketNodeUserData(bootstrapContainerUserData []byte, users []bootstrapv1.User, config *BottlerocketConfig) ([]byte, error) {
	// base64 encode the bootstrapContainer's user data
	b64BootstrapContainerUserData := base64.StdEncoding.EncodeToString(bootstrapContainerUserData)

	// Parse out all the ssh authorized keys
	sshAuthorizedKeys := getAllAuthorizedKeys(users)

	// generate the userdata for the admin container
	adminContainerUserData, err := generateAdminContainerUserData("InitAdminContainer", usersTemplate, sshAuthorizedKeys)
	if err != nil {
		return nil, err
	}
	b64AdminContainerUserData := base64.StdEncoding.EncodeToString(adminContainerUserData)

	hostContainers := []bootstrapv1.BottlerocketHostContainer{
		{
			Name:         "admin",
			Superpowered: true,
			ImageMeta:    config.BottlerocketAdmin.ImageMeta,
			UserData:     b64AdminContainerUserData,
		},
		{
			Name:         "kubeadm-bootstrap",
			Superpowered: true,
			ImageMeta:    config.BottlerocketBootstrap.ImageMeta,
			UserData:     b64BootstrapContainerUserData,
		},
	}

	if config.BottlerocketControl.ImageRepository != "" && config.BottlerocketControl.ImageTag != "" {
		hostContainers = append(hostContainers, bootstrapv1.BottlerocketHostContainer{
			Name:         "control",
			Superpowered: false,
			ImageMeta:    config.BottlerocketControl.ImageMeta,
		})
	}

	if len(config.BottlerocketCustomHostContainers) != 0 {
		hostContainers = append(hostContainers, config.BottlerocketCustomHostContainers...)
	}

	bottlerocketInput := &SettingsInput{
		PauseContainerSource: fmt.Sprintf("%s:%s", config.Pause.ImageRepository, config.Pause.ImageTag),
		NodeLabels:           parseNodeLabels(config.KubeletExtraArgs["node-labels"]), // empty string if it does not exist
		Taints:               parseTaints(config.Taints),                              // empty string if it does not exist
		HostContainers:       hostContainers,
		BootstrapContainers:  config.BottlerocketCustomBootstrapContainers,
	}

	// When RegistryMirrorConfiguration.Endpoint is specified, we default the mirror to public.ecr.aws.
	// This was done for backward compatability, since public.ecr.aws was the only supported registry before.
	// For existing customers this ensures that their nodes dont rollout, unless more mirrors are specified explicitly.
	// If RegistryMirrorConfiguration.Endpoint is not specified, we iterate the RegistryMirrorConfiguration.Mirrors to setup the mirrors.
	bottlerocketInput.RegistryMirrorMap = make(map[string][]string)
	endpointRegex := regexp.MustCompile(`^(https?:\/\/)?[\w\.\:\-]+`)
	if config.RegistryMirrorConfiguration.Endpoint != "" {
		bottlerocketInput.RegistryMirrorMap["public.ecr.aws"] = []string{strconv.Quote(config.RegistryMirrorConfiguration.Endpoint)}
		if endpoint := endpointRegex.FindStringSubmatch(config.RegistryMirrorConfiguration.Endpoint); endpoint != nil {
			bottlerocketInput.RegistryMirrorEndpoint = endpoint[0]
		}
	} else if len(config.RegistryMirrorConfiguration.Mirrors) > 0 {
		for _, mirror := range config.RegistryMirrorConfiguration.Mirrors {
			for _, endpoint := range mirror.Endpoints {
				bottlerocketInput.RegistryMirrorMap[mirror.Registry] = append(bottlerocketInput.RegistryMirrorMap[mirror.Registry], strconv.Quote(endpoint))
			}
		}

		// Right now we support only one private registry. Hence defaulting to first entry.
		if endpoint := endpointRegex.FindStringSubmatch(config.RegistryMirrorConfiguration.Mirrors[0].Endpoints[0]); endpoint != nil {
			bottlerocketInput.RegistryMirrorEndpoint = endpoint[0]
		}
	}

	if config.RegistryMirrorConfiguration.CACert != "" {
		bottlerocketInput.RegistryMirrorCACert = base64.StdEncoding.EncodeToString([]byte(config.RegistryMirrorConfiguration.CACert))
	}
	if config.RegistryMirrorCredentials.Username != "" && config.RegistryMirrorCredentials.Password != "" {
		bottlerocketInput.RegistryMirrorUsername = config.RegistryMirrorCredentials.Username
		bottlerocketInput.RegistryMirrorPassword = config.RegistryMirrorCredentials.Password
	}
	if len(config.NTPServers) > 0 {
		for _, ntp := range config.NTPServers {
			bottlerocketInput.NTPServers = append(bottlerocketInput.NTPServers, strconv.Quote(ntp))
		}
	}

	if config.CertBundle != nil {
		for _, cert := range config.CertBundle {
			cert.Data = base64.StdEncoding.EncodeToString([]byte(cert.Data))
			bottlerocketInput.CertBundles = append(bottlerocketInput.CertBundles, cert)
		}
	}

	nodeUserData, err := generateNodeUserData("InitBottlerocketNode", bottlerocketNodeInitSettingsTemplate, bottlerocketInput)
	if err != nil {
		return nil, err
	}

	settings := InitSettingsInput{}
	initSettings := &InitSettings{}

	nwSettings, err := getNetworkSettings(config)
	if err != nil {
		return nil, err
	}
	initSettings.NetworkSettings = nwSettings

	kubernetesSettings, err := getKubernetesSettings(config, bottlerocketInput)
	if err != nil {
		return nil, err
	}
	initSettings.Kubernetes = kubernetesSettings

	if config.BottlerocketSettings != nil {
		kernelSettings := getKernelSettings(config)
		if kernelSettings != nil {
			initSettings.Kernel = kernelSettings
		}

		bootSettings := getBootSettings(config)
		if bootSettings != nil {
			initSettings.Boot = bootSettings
		}
	}

	settings.InitSettings = initSettings

	settingsTOML, err := toml.Marshal(settings)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal toml data for %v", settings)
	}

	settingsTOML = append(settingsTOML, nodeUserData...)

	return settingsTOML, nil
}

func getKernelSettings(config *BottlerocketConfig) *KernelSettings {
	if config.BottlerocketSettings.Kernel == nil {
		return nil
	}

	bottlerocketKernelSettings := &KernelSettings{
		SysctlSettings: config.BottlerocketSettings.Kernel.SysctlSettings,
	}

	return bottlerocketKernelSettings
}

func getBootSettings(config *BottlerocketConfig) *BootSettings {
	if config.BottlerocketSettings.Boot == nil {
		return nil
	}
	bottlerocketBootSettings := &BootSettings{
		RebootToReconcile: true,
		BootKernel:        config.BottlerocketSettings.Boot.BootKernelParameters,
	}

	return bottlerocketBootSettings
}

func getNetworkSettings(config *BottlerocketConfig) (*NetworkSettings, error) {
	networkSettings := &NetworkSettings{
		Hostname:           config.Hostname,
		HTTPSProxyEndpoint: config.ProxyConfiguration.HTTPSProxy,
	}
	if len(config.ProxyConfiguration.NoProxy) > 0 {
		networkSettings.NoProxyEndpoints = append(networkSettings.NoProxyEndpoints, config.ProxyConfiguration.NoProxy...)
	}

	return networkSettings, nil
}

func getKubernetesSettings(config *BottlerocketConfig, settingsInput *SettingsInput) (*KubernetesSettings, error) {
	kubernetesSettings := &KubernetesSettings{
		AuthenticationMode:     "tls",
		ClusterDomain:          "cluster.local",
		PodInfraContainerImage: settingsInput.PauseContainerSource,
		ProviderID:             config.KubeletExtraArgs["provider-id"],
		ServerTLSBootstrap:     false,
		StandaloneMode:         true,
	}

	if config.BottlerocketSettings != nil {
		if config.BottlerocketSettings.Kubernetes != nil {
			kubernetesSettings.AllowedUnsafeSysctls = append(kubernetesSettings.AllowedUnsafeSysctls, config.BottlerocketSettings.Kubernetes.AllowedUnsafeSysctls...)
			kubernetesSettings.ClusterDNSIPs = append(kubernetesSettings.ClusterDNSIPs, config.BottlerocketSettings.Kubernetes.ClusterDNSIPs...)
			if config.BottlerocketSettings.Kubernetes.ClusterDomain != "" {
				kubernetesSettings.ClusterDomain = config.BottlerocketSettings.Kubernetes.ClusterDomain
			}
			kubernetesSettings.ContainerLogMaxFiles = config.BottlerocketSettings.Kubernetes.ContainerLogMaxFiles
			kubernetesSettings.ContainerLogMaxSize = config.BottlerocketSettings.Kubernetes.ContainerLogMaxSize
			if config.BottlerocketSettings.Kubernetes.CPUCFSQuota != nil {
				kubernetesSettings.CPUCFSQuota = config.BottlerocketSettings.Kubernetes.CPUCFSQuota
			}
			kubernetesSettings.CPUManagerPolicy = config.BottlerocketSettings.Kubernetes.CPUManagerPolicy
			cpuManagerOptions := config.BottlerocketSettings.Kubernetes.CPUManagerPolicyOptions
			if cpuManagerOptions != nil {
				kubernetesSettings.CPUManagerPolicyOptions = []string{}
				for key, val := range cpuManagerOptions {
					if val == "true" {
						kubernetesSettings.CPUManagerPolicyOptions = append(kubernetesSettings.CPUManagerPolicyOptions, key)
					}
				}
			}
			if config.BottlerocketSettings.Kubernetes.CPUManagerReconcilePeriod != nil {
				kubernetesSettings.CPUManagerReconcilePeriod = config.BottlerocketSettings.Kubernetes.CPUManagerReconcilePeriod.Duration.String()
			}
			kubernetesSettings.EventBurst = config.BottlerocketSettings.Kubernetes.EventBurst
			kubernetesSettings.EventRecordQPS = config.BottlerocketSettings.Kubernetes.EventRecordQPS
			kubernetesSettings.EvictionHard = config.BottlerocketSettings.Kubernetes.EvictionHard
			kubernetesSettings.EvictionMaxPodGracePeriod = config.BottlerocketSettings.Kubernetes.EvictionMaxPodGracePeriod
			kubernetesSettings.EvictionSoft = config.BottlerocketSettings.Kubernetes.EvictionSoft
			kubernetesSettings.EvictionSoftGracePeriod = config.BottlerocketSettings.Kubernetes.EvictionSoftGracePeriod
			kubernetesSettings.ImageGCHighThresholdPercent = config.BottlerocketSettings.Kubernetes.ImageGCHighThresholdPercent
			kubernetesSettings.ImageGCLowThresholdPercent = config.BottlerocketSettings.Kubernetes.ImageGCLowThresholdPercent
			kubernetesSettings.KubeAPIBurst = config.BottlerocketSettings.Kubernetes.KubeAPIBurst
			kubernetesSettings.KubeAPIQPS = config.BottlerocketSettings.Kubernetes.KubeAPIQPS
			kubernetesSettings.KubeReserved = config.BottlerocketSettings.Kubernetes.KubeReserved
			kubernetesSettings.MaxPods = config.BottlerocketSettings.Kubernetes.MaxPods
			kubernetesSettings.MemoryManagerPolicy = config.BottlerocketSettings.Kubernetes.MemoryManagerPolicy
			kubernetesSettings.ProviderID = config.KubeletExtraArgs["provider-id"]
			kubernetesSettings.PodPidsLimit = config.BottlerocketSettings.Kubernetes.PodPidsLimit
			kubernetesSettings.RegistryBurst = config.BottlerocketSettings.Kubernetes.RegistryBurst
			kubernetesSettings.RegistryPullQPS = config.BottlerocketSettings.Kubernetes.RegistryPullQPS
			if config.BottlerocketSettings.Kubernetes.ShutdownGracePeriod != nil {
				kubernetesSettings.ShutdownGracePeriod = config.BottlerocketSettings.Kubernetes.ShutdownGracePeriod.Duration.String()
			}
			if config.BottlerocketSettings.Kubernetes.ShutdownGracePeriodCriticalPods != nil {
				kubernetesSettings.ShutdownGracePeriodCriticalPods = config.BottlerocketSettings.Kubernetes.ShutdownGracePeriodCriticalPods.Duration.String()
			}
			kubernetesSettings.SystemReserved = config.BottlerocketSettings.Kubernetes.SystemReserved
			kubernetesSettings.TopologyManagerPolicy = config.BottlerocketSettings.Kubernetes.TopologyManagerPolicy
			kubernetesSettings.TopologyManagerScope = config.BottlerocketSettings.Kubernetes.TopologyManagerScope
		}
	}

	return kubernetesSettings, nil
}

// bottlerocket configuration accepts taints in the format
// "key" = ["value:Effect", "value2:Effect2"]
func parseTaints(taints []corev1.Taint) string {
	if len(taints) == 0 {
		return ""
	}
	taintValueEffectTemplate := "\"%v:%v\""
	taintsMap := make(map[string][]string)
	for _, taint := range taints {
		valueEffectString := fmt.Sprintf(taintValueEffectTemplate, taint.Value, taint.Effect)
		taintsMap[taint.Key] = append(taintsMap[taint.Key], valueEffectString)
	}

	var taintsToml strings.Builder
	for k, v := range taintsMap {
		// write the taint key and opening bracket: '"key" = ['
		taintKey := fmt.Sprintf("\"%v\" = [", k)
		taintsToml.WriteString(taintKey)

		// write the value:effect mappings: '"value1:Effect1", "value2:Effect2"'
		taintValueEffectMappings := strings.Join(v, ",")
		taintsToml.WriteString(taintValueEffectMappings)

		// close the brackets and go to a new line
		taintsToml.WriteString("]")
		taintsToml.WriteString("\n")
	}
	return taintsToml.String()
}

func parseNodeLabels(nodeLabels string) string {
	if nodeLabels == "" {
		return ""
	}
	nodeLabelsToml := ""
	nodeLabelsList := strings.Split(nodeLabels, ",")
	for _, nodeLabel := range nodeLabelsList {
		keyVal := strings.Split(nodeLabel, "=")
		if len(keyVal) == 2 {
			nodeLabelsToml += fmt.Sprintf("\"%v\" = \"%v\"\n", keyVal[0], keyVal[1])
		}
	}
	return nodeLabelsToml
}

// Parses through all the users and return list of all user's authorized ssh keys
func getAllAuthorizedKeys(users []bootstrapv1.User) string {
	var sshAuthorizedKeys []string
	for _, user := range users {
		if len(user.SSHAuthorizedKeys) != 0 {
			for _, key := range user.SSHAuthorizedKeys {
				quotedKey := "\"" + key + "\""
				sshAuthorizedKeys = append(sshAuthorizedKeys, quotedKey)
			}
		}
	}
	return strings.Join(sshAuthorizedKeys, ",")
}

func patchKubeVipFile(writeFiles []bootstrapv1.File) ([]bootstrapv1.File, error) {
	var patchedFiles []bootstrapv1.File
	for _, file := range writeFiles {
		if file.Path == "/etc/kubernetes/manifests/kube-vip.yaml" {
			// unmarshal the yaml file from contents
			pod := &corev1.Pod{}
			err := yaml.Unmarshal([]byte(file.Content), pod)
			if err != nil {
				return nil, errors.Wrap(err, "unmarshalling yaml content from kube-vip")
			}

			// Patch the spec.Volume mount path
			f := corev1.HostPathFile
			pod.Spec.Volumes[0].HostPath.Type = &f

			// Marshall back into yaml and override
			patchedYaml, err := yaml.Marshal(pod)
			if err != nil {
				return nil, errors.Wrap(err, "marshalling patched kube-vip yaml")
			}
			file.Content = string(patchedYaml)
		}
		patchedFiles = append(patchedFiles, file)
	}
	return patchedFiles, nil
}
