package bottlerocket

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	bootstrapv1 "sigs.k8s.io/cluster-api/bootstrap/kubeadm/api/v1beta1"
)

const (
	minimalUserData = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"

[settings.network]
hostname = "hostname"`

	nodeLabelslUserData = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"

[settings.network]
hostname = "hostname"
[settings.kubernetes.node-labels]
"KEY1" = "VAL1"
"KEY2" = "VAL2"
"KEY3" = "VAL3"
`

	taintsUserData = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"

[settings.network]
hostname = "hostname"
[settings.kubernetes.node-taints]
"KEY1" = ["VAL1:NoSchedule"]
`

	proxyUserData = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"

[settings.network]
hostname = "hostname"
https-proxy = "HTTPS_PROXY"
no-proxy = ["no_proxy1","no_proxy2","no_proxy3"]`

	registryMirrorUserData = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"

[settings.network]
hostname = "hostname"

[[settings.container-registry.mirrors]]
registry = "public.ecr.aws"
endpoint = ["REGISTRY_ENDPOINT"]
[settings.pki.registry-mirror-ca]
data = "UkVHSVNUUllfQ0E="
trusted=true`

	registryMirrorAndAuthUserData = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"

[settings.network]
hostname = "hostname"

[[settings.container-registry.mirrors]]
registry = "public.ecr.aws"
endpoint = ["REGISTRY_ENDPOINT"]
[settings.pki.registry-mirror-ca]
data = "UkVHSVNUUllfQ0E="
trusted=true

[[settings.container-registry.credentials]]
registry = "public.ecr.aws"
username = "admin"
password = "pass"
[[settings.container-registry.credentials]]
registry = "REGISTRY_ENDPOINT"
username = "admin"
password = "pass"`

	ntpUserData = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"

[settings.network]
hostname = "hostname"
[settings.ntp]
time-servers = ["1.2.3.4", "time-a.capi.com", "time-b.capi.com"]`

	kubernetesSettingsUserData = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"
allowed-unsafe-sysctls = ["net.core.somaxconn", "net.ipv4.ip_local_port_range"]
cluster-dns-ip = ["1.2.3.4", "4.3.2.1"]
max-pods = 100

[settings.network]
hostname = "hostname"`

	customBootstrapUserData = `
[settings.host-containers.admin]
enabled = true
superpowered = true
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"

[settings.network]
hostname = "hostname"

[settings.bootstrap-containers.BOOTSTRAP]
essential = false
mode = "MODE"
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "BOOTSTRAP_B6_4USERDATA"`

	kernelSettingsUserData = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"

[settings.network]
hostname = "hostname"
[settings.kernel.sysctl]
"foo" = "bar"
"abc" = "def"
`

	BootSettingsUserData = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"

[settings.network]
hostname = "hostname"
[settings.boot]
reboot-to-reconcile = true

[settings.boot.kernel-parameters]
"abc" = ["def","123"]
"foo" = ["bar"]
`

	userDataWithCertBundle = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"

[settings.network]
hostname = "hostname"

[settings.pki.bundle1]
data = "QUJDREVG"
trusted = true
[settings.pki.bundle2]
data = "MTIzNDU2"
trusted = true`

	registryMirrorMultipleMirrorsUserData = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"

[settings.network]
hostname = "hostname"

[[settings.container-registry.mirrors]]
registry = "docker.io"
endpoint = ["REGISTRY_ENDPOINT"]
[[settings.container-registry.mirrors]]
registry = "public.ecr.aws"
endpoint = ["REGISTRY_ENDPOINT"]
[settings.pki.registry-mirror-ca]
data = "UkVHSVNUUllfQ0E="
trusted=true`

	kubernetesSettingsUserDataCPU = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "ADMIN_REPO:ADMIN_TAG"
user-data = "CnsKCSJzc2giOiB7CgkJImF1dGhvcml6ZWQta2V5cyI6IFsic3NoLXJzYSBBQUEuLi4iXQoJfQp9"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "BOOTSTRAP_REPO:BOOTSTRAP_TAG"
user-data = "Qk9UVExFUk9DS0VUX0JPT1RTVFJBUF9VU0VSREFUQQ=="

[settings.kubernetes]
cluster-domain = "cluster.local2"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE_REPO:PAUSE_TAG"
provider-id = "PROVIDERID"
cpu-cfs-quota-enforced = false
container-log-max-files = 10
container-log-max-size = "5Mi"
cpu-manager-policy = "static"
cpu-manager-policy-options = ["full-pcpus-only"]
cpu-manager-reconcile-period = 10s
event-burst = 200
event-qps = 100
eviction-max-pod-grace-period = 10
image-gc-high-threshold-percent = 26
image-gc-low-threshold-percent = 19
kube-api-burst = 80
memory-manager-policy = "Static"
pod-pids-limit = 10
registry-burst = 11
registry-qps = 1
shutdown-grace-period = 15s
shutdown-grace-period-for-critical-pods = 20s
topology-manager-policy = "restricted"
topology-manager-scope = "pod"
[settings.kubernetes.eviction-hard]
"memory.available" = "15%"
[settings.kubernetes.eviction-soft]
"memory.available" = "12%"
[settings.kubernetes.eviction-soft-grace-period]
"memory.available" = "30s"
[settings.kubernetes.kube-reserved]
cpu = "20m"
[settings.kubernetes.system-reserved]
cpu = "10m"
ephemeral-storage = "1Gi"
memory = "100Mi"

[settings.network]
hostname = "hostname"`
)

var (
	brAdmin = bootstrapv1.BottlerocketAdmin{
		ImageMeta: bootstrapv1.ImageMeta{
			ImageRepository: "ADMIN_REPO",
			ImageTag:        "ADMIN_TAG",
		},
	}

	brBootstrap = bootstrapv1.BottlerocketBootstrap{
		ImageMeta: bootstrapv1.ImageMeta{
			ImageRepository: "BOOTSTRAP_REPO",
			ImageTag:        "BOOTSTRAP_TAG",
		},
	}

	users = []bootstrapv1.User{
		{
			Name:              "ec2-user",
			SSHAuthorizedKeys: []string{"ssh-rsa AAA..."},
		},
	}

	bootstrapContainers = []bootstrapv1.BottlerocketBootstrapContainer{
		{
			Name: "BOOTSTRAP",
			Mode: "MODE",
			ImageMeta: bootstrapv1.ImageMeta{
				ImageRepository: "BOOTSTRAP_REPO",
				ImageTag:        "BOOTSTRAP_TAG",
			},
			UserData: "BOOTSTRAP_B6_4USERDATA",
		},
	}

	pause = bootstrapv1.Pause{
		ImageMeta: bootstrapv1.ImageMeta{
			ImageRepository: "PAUSE_REPO",
			ImageTag:        "PAUSE_TAG",
		},
	}
)

func TestGetBottlerocketNodeUserData(t *testing.T) {
	g := NewWithT(t)
	hostname := "hostname"
	brBootstrapUserdata := []byte("BOTTLEROCKET_BOOTSTRAP_USERDATA")

	testcases := []struct {
		name   string
		config *BottlerocketConfig
		output string
	}{
		{
			name: "minimal settings",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
			},
			output: minimalUserData,
		},
		{
			name: "with node labels",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"node-labels": "KEY1=VAL1,KEY2=VAL2,KEY3=VAL3",
					"provider-id": "PROVIDERID",
				},
			},
			output: nodeLabelslUserData,
		},
		{
			name: "with taints",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
				Taints: []corev1.Taint{
					{
						Key:    "KEY1",
						Value:  "VAL1",
						Effect: corev1.TaintEffectNoSchedule,
					},
				},
			},
			output: taintsUserData,
		},
		{
			name: "with proxy",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
				ProxyConfiguration: bootstrapv1.ProxyConfiguration{
					HTTPSProxy: "HTTPS_PROXY",
					NoProxy:    []string{"no_proxy1", "no_proxy2", "no_proxy3"},
				},
			},
			output: proxyUserData,
		},
		{
			name: "with registry mirror",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
				RegistryMirrorConfiguration: bootstrapv1.RegistryMirrorConfiguration{
					Endpoint: "REGISTRY_ENDPOINT",
					CACert:   "REGISTRY_CA",
				},
			},
			output: registryMirrorUserData,
		},
		{
			name: "with registry mirror and auth",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
				RegistryMirrorConfiguration: bootstrapv1.RegistryMirrorConfiguration{
					Endpoint: "REGISTRY_ENDPOINT",
					CACert:   "REGISTRY_CA",
				},
				RegistryMirrorCredentials: RegistryMirrorCredentials{
					Username: "admin",
					Password: "pass",
				},
			},
			output: registryMirrorAndAuthUserData,
		},
		{
			name: "with ntp servers",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
				NTPServers: []string{
					"1.2.3.4",
					"time-a.capi.com",
					"time-b.capi.com",
				},
			},
			output: ntpUserData,
		},
		{
			name: "with kubernetes settings",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
				BottlerocketSettings: &bootstrapv1.BottlerocketSettings{
					Kubernetes: &bootstrapv1.BottlerocketKubernetesSettings{
						MaxPods: 100,
						ClusterDNSIPs: []string{
							"1.2.3.4",
							"4.3.2.1",
						},
						AllowedUnsafeSysctls: []string{
							"net.core.somaxconn",
							"net.ipv4.ip_local_port_range",
						},
					},
				},
			},
			output: kubernetesSettingsUserData,
		},
		{
			name: "with custom bootstrap containers",
			config: &BottlerocketConfig{
				Pause: pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
				BottlerocketCustomBootstrapContainers: bootstrapContainers,
				Hostname:                              hostname,
			},
			output: customBootstrapUserData,
		},
		{
			name: "with kernel settings",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
				BottlerocketSettings: &bootstrapv1.BottlerocketSettings{
					Kernel: &bootstrapv1.BottlerocketKernelSettings{
						SysctlSettings: map[string]string{
							"foo": "bar",
							"abc": "def",
						},
					},
				},
			},
			output: kernelSettingsUserData,
		},
		{
			name: "with boot settings",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
				BottlerocketSettings: &bootstrapv1.BottlerocketSettings{
					Boot: &bootstrapv1.BottlerocketBootSettings{
						BootKernelParameters: map[string][]string{
							"abc": {
								"def",
								"123",
							},
							"foo": {
								"bar",
							},
						},
					},
				},
			},
			output: BootSettingsUserData,
		},
		{
			name: "with custom cert bundle settings",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
				CertBundle: []bootstrapv1.CertBundle{
					{
						Name: "bundle1",
						Data: "ABCDEF",
					},
					{
						Name: "bundle2",
						Data: "123456",
					},
				},
			},
			output: userDataWithCertBundle,
		},
		{
			name: "with multiple registries to mirror",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
				RegistryMirrorConfiguration: bootstrapv1.RegistryMirrorConfiguration{
					CACert: "REGISTRY_CA",
					Mirrors: []bootstrapv1.Mirror{
						{
							Registry:  "docker.io",
							Endpoints: []string{"REGISTRY_ENDPOINT"},
						},
						{
							Registry:  "public.ecr.aws",
							Endpoints: []string{"REGISTRY_ENDPOINT"},
						},
					},
				},
			},
			output: registryMirrorMultipleMirrorsUserData,
		},
		{
			name: "with cpu manager policy options",
			config: &BottlerocketConfig{
				BottlerocketAdmin:     brAdmin,
				BottlerocketBootstrap: brBootstrap,
				Hostname:              hostname,
				Pause:                 pause,
				KubeletExtraArgs: map[string]string{
					"provider-id": "PROVIDERID",
				},
				BottlerocketSettings: &bootstrapv1.BottlerocketSettings{
					Kubernetes: &bootstrapv1.BottlerocketKubernetesSettings{
						ClusterDomain:        "cluster.local2",
						ContainerLogMaxFiles: 10,
						ContainerLogMaxSize:  "5Mi",
						CPUCFSQuota:          pointer.Bool(false),
						CPUManagerPolicy:     "static",
						CPUManagerPolicyOptions: map[string]string{
							"full-pcpus-only": "true",
						},
						CPUManagerReconcilePeriod: &v1.Duration{
							Duration: 10 * time.Second,
						},
						EventBurst:     200,
						EventRecordQPS: 100,
						EvictionHard: map[string]string{
							"memory.available": "15%",
						},
						EvictionMaxPodGracePeriod: 10,
						EvictionSoft: map[string]string{
							"memory.available": "12%",
						},
						EvictionSoftGracePeriod: map[string]string{
							"memory.available": "30s",
						},
						ImageGCHighThresholdPercent: 26,
						ImageGCLowThresholdPercent:  19,
						KubeAPIBurst:                80,
						KubeReserved: map[string]string{
							"cpu": "20m",
						},
						MemoryManagerPolicy: "Static",
						PodPidsLimit:        10,
						RegistryBurst:       11,
						RegistryPullQPS:     1,
						ShutdownGracePeriod: &v1.Duration{
							Duration: 15 * time.Second,
						},
						ShutdownGracePeriodCriticalPods: &v1.Duration{
							Duration: 20 * time.Second,
						},
						SystemReserved: map[string]string{
							"cpu":               "10m",
							"ephemeral-storage": "1Gi",
							"memory":            "100Mi",
						},
						TopologyManagerPolicy: "restricted",
						TopologyManagerScope:  "pod",
					},
				},
			},
			output: kubernetesSettingsUserDataCPU,
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			b, err := getBottlerocketNodeUserData(brBootstrapUserdata, users, testcase.config)

			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(string(b)).To(Equal(testcase.output))
		})
	}
}
