package bottlerocket

import (
	"github.com/pkg/errors"
	"sigs.k8s.io/cluster-api/bootstrap/kubeadm/internal/cloudinit"
)

const (
	controlPlaneJoinBottlerocketInit = `{{template "files" .WriteFiles}}
-   path: /tmp/kubeadm-join-config.yaml
    owner: root:root
    permissions: '0640'
    content: |
{{.JoinConfiguration | Indent 6}}
runcmd: "ControlPlaneJoin"
`
)

// NewJoinControlPlane returns the user data string to be used on a new control plane instance.
func NewJoinControlPlane(input *cloudinit.ControlPlaneJoinInput, config *BottlerocketConfig) ([]byte, error) {
	input.WriteFiles = input.Certificates.AsFiles()
	input.ControlPlane = true
	input.WriteFiles = append(input.WriteFiles, input.AdditionalFiles...)
	bootstrapContainerUserData, err := generateBootstrapContainerUserData("JoinControlplane", controlPlaneJoinBottlerocketInit, input)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate user data for machine joining control plane")
	}

	return getBottlerocketNodeUserData(bootstrapContainerUserData, input.Users, config)
}
