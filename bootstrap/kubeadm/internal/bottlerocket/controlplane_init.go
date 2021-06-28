// TODO: make bottlerocket(init) more agnostic. In addition to other changes to make things
// less hacky, also move calling cloudinit from controller and passing it to
// bottlerocket bootstrap, to all control to bottlerocket bootstrap itself.
// That way, bottlerocket bootstrap will call cloudinit to generate that userdata
// which is much more cleaner.
package bottlerocket

import (
	"github.com/pkg/errors"
	"sigs.k8s.io/cluster-api/bootstrap/kubeadm/internal/cloudinit"
)

const (
	controlPlaneBootstrapContainerTemplate = `{{.Header}}
{{template "files" .WriteFiles}}
-   path: /tmp/kubeadm.yaml
    owner: root:root
    permissions: '0640'
    content: |
      ---
{{.ClusterConfiguration | Indent 6}}
      ---
{{.InitConfiguration | Indent 6}}
runcmd: "ControlPlaneInit"
`
)

// NewInitControlPlane will take the cloudinit's controlplane input as an argument
// and generate the bottlerocket toml formatted userdata for the host node, which
// has the settings for bootstrap container which has its own embedded base64 encoded userdata.
func NewInitControlPlane(input *cloudinit.ControlPlaneInput, config *BottlerocketConfig) ([]byte, error) {
	input.Header = cloudConfigHeader
	input.WriteFiles = input.Certificates.AsFiles()
	input.WriteFiles = append(input.WriteFiles, input.AdditionalFiles...)

	var err error
	input.WriteFiles, err = patchKubeVipFile(input.WriteFiles)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to patch kube-vip manifest file")
	}
	bootstrapContainerUserData, err := generateBootstrapContainerUserData("InitBootstrapContainer", controlPlaneBootstrapContainerTemplate, input)
	if err != nil {
		return nil, err
	}

	return getBottlerocketNodeUserData(bootstrapContainerUserData, input.Users, config)
}
