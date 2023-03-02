package bottlerocket

import (
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"

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
[settings.container-registry.mirrors]
"public.ecr.aws" = ["https://REGISTRY_ENDPOINT"]
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
[settings.container-registry.mirrors]
"public.ecr.aws" = ["https://REGISTRY_ENDPOINT"]
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
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			b, err := getBottlerocketNodeUserData(brBootstrapUserdata, users, testcase.config)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(string(b)).To(Equal(testcase.output))
		})
	}
}
