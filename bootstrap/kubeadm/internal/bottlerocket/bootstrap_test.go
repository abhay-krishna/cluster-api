package bottlerocket

import (
	"testing"

	. "github.com/onsi/gomega"

	bootstrapv1 "sigs.k8s.io/cluster-api/bootstrap/kubeadm/api/v1beta1"
)

const userDataFullSetting = `
[settings.host-containers.admin]
enabled = true
superpowered = true
source = "REPO:TAG"
user-data = "B64USERDATA"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "REPO:TAG"
user-data = "B64USERDATA"

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE"
provider-id = "PROVIDERID"

[settings.bootstrap-containers.BOOTSTRAP]
essential = false
mode = "MODE"
user-data = "B64USERDATA"
[settings.network]
https-proxy = "PROXY"
no-proxy = []
[settings.container-registry.mirrors]
"public.ecr.aws" = ["https://REGISTRYENDPOINT"]
[settings.pki.registry-mirror-ca]
data = "REGISTRYCA"
trusted=true
[settings.kubernetes.node-labels]
KEY=VAR
[settings.kubernetes.node-taints]
KEY=VAR`

const userDataNoAdminImage = `
[settings.host-containers.admin]
enabled = true
superpowered = true
user-data = "B64USERDATA"
[settings.host-containers.kubeadm-bootstrap]
enabled = true
superpowered = true
source = "REPO:TAG"
user-data = "B64USERDATA"

[settings.kubernetes]
cluster-domain = "cluster.local"
standalone-mode = true
authentication-mode = "tls"
server-tls-bootstrap = false
pod-infra-container-image = "PAUSE"
provider-id = "PROVIDERID"

[settings.bootstrap-containers.BOOTSTRAP]
essential = false
mode = "MODE"
user-data = "B64USERDATA"
[settings.network]
https-proxy = "PROXY"
no-proxy = []
[settings.container-registry.mirrors]
"public.ecr.aws" = ["https://REGISTRYENDPOINT"]
[settings.pki.registry-mirror-ca]
data = "REGISTRYCA"
trusted=true
[settings.kubernetes.node-labels]
KEY=VAR
[settings.kubernetes.node-taints]
KEY=VAR`

func TestGenerateUserData(t *testing.T) {
	g := NewWithT(t)

	testcases := []struct {
		name   string
		input  *BottlerocketSettingsInput
		output string
	}{
		{
			name: "full settings",
			input: &BottlerocketSettingsInput{
				PauseContainerSource:   "PAUSE",
				HTTPSProxyEndpoint:     "PROXY",
				RegistryMirrorEndpoint: "REGISTRYENDPOINT",
				RegistryMirrorCACert:   "REGISTRYCA",
				NodeLabels:             "KEY=VAR",
				Taints:                 "KEY=VAR",
				ProviderId:             "PROVIDERID",
				HostContainers: []bootstrapv1.BottlerocketHostContainer{
					{
						Name:         "admin",
						Superpowered: true,
						ImageMeta: bootstrapv1.ImageMeta{
							ImageRepository: "REPO",
							ImageTag:        "TAG",
						},
						UserData: "B64USERDATA",
					},
					{
						Name:         "kubeadm-bootstrap",
						Superpowered: true,
						ImageMeta: bootstrapv1.ImageMeta{
							ImageRepository: "REPO",
							ImageTag:        "TAG",
						},
						UserData: "B64USERDATA",
					},
				},
				BootstrapContainers: []bootstrapv1.BottlerocketBootstrapContainer{
					{
						Name:     "BOOTSTRAP",
						Mode:     "MODE",
						UserData: "B64USERDATA",
					},
				},
			},
			output: userDataFullSetting,
		},
		{
			name: "no admin image meta",
			input: &BottlerocketSettingsInput{
				PauseContainerSource:   "PAUSE",
				HTTPSProxyEndpoint:     "PROXY",
				RegistryMirrorEndpoint: "REGISTRYENDPOINT",
				RegistryMirrorCACert:   "REGISTRYCA",
				NodeLabels:             "KEY=VAR",
				Taints:                 "KEY=VAR",
				ProviderId:             "PROVIDERID",
				HostContainers: []bootstrapv1.BottlerocketHostContainer{
					{
						Name:         "admin",
						Superpowered: true,
						ImageMeta:    bootstrapv1.ImageMeta{},
						UserData:     "B64USERDATA",
					},
					{
						Name:         "kubeadm-bootstrap",
						Superpowered: true,
						ImageMeta: bootstrapv1.ImageMeta{
							ImageRepository: "REPO",
							ImageTag:        "TAG",
						},
						UserData: "B64USERDATA",
					},
				},
				BootstrapContainers: []bootstrapv1.BottlerocketBootstrapContainer{
					{
						Name:     "BOOTSTRAP",
						Mode:     "MODE",
						UserData: "B64USERDATA",
					},
				},
			},
			output: userDataNoAdminImage,
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			b, err := generateNodeUserData("TestBottlerocketInit", bottlerocketNodeInitSettingsTemplate, testcase.input)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(string(b)).To(Equal(testcase.output))
		})
	}
}
