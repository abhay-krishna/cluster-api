package bottlerocket

import (
	"fmt"

	"sigs.k8s.io/cluster-api/bootstrap/kubeadm/internal/cloudinit"
)

const (
	nodeBottleRocketInit = `{{template "files" .WriteFiles}}
-   path: /tmp/kubeadm-join-config.yaml
    owner: root:root
    permissions: '0640'
    content: |
      ---
{{.JoinConfiguration | Indent 6}}
runcmd: "WorkerJoin"
`
)

// NewNode creates a toml formatted userdata including bootstrap host container settings that has
// a base64 encoded user data for the bootstrap container
func NewNode(input *cloudinit.NodeInput, config *BottlerocketConfig) ([]byte, error) {
	input.KubeadmCommand = fmt.Sprintf(standardJoinCommand, input.KubeadmVerbosity)
	input.WriteFiles = append(input.WriteFiles, input.AdditionalFiles...)
	bootstrapContainerUserData, err := generateBootstrapContainerUserData("Node", nodeBottleRocketInit, input)
	if err != nil {
		return nil, err
	}

	return getBottlerocketNodeUserData(bootstrapContainerUserData, input.Users, config)
}
