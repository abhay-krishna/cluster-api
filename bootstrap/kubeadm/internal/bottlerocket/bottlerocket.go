package bottlerocket

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"text/template"

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

type BottlerocketConfig struct {
	Pause                       bootstrapv1.Pause
	BottlerocketBootstrap       bootstrapv1.BottlerocketBootstrap
	ProxyConfiguration          bootstrapv1.ProxyConfiguration
	RegistryMirrorConfiguration bootstrapv1.RegistryMirrorConfiguration
}

type BottlerocketSettingsInput struct {
	BootstrapContainerUserData string
	AdminContainerUserData     string
	BootstrapContainerSource   string
	PauseContainerSource       string
	HTTPSProxyEndpoint         string
	NoProxyEndpoints           []string
	RegistryMirrorEndpoint     string
	RegistryMirrorCACert       string
}

type HostPath struct {
	Path string
	Type string
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

func generateNodeUserData(kind string, tpl string, data interface{}) ([]byte, error) {
	tm := template.New(kind)
	if _, err := tm.Parse(bootstrapHostContainerTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse hostContainer %s template", kind)
	}
	if _, err := tm.Parse(adminContainerInitTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse adminContainer %s template", kind)
	}
	if _, err := tm.Parse(kubernetesInitTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse kubernetes %s template", kind)
	}
	if _, err := tm.Parse(networkInitTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse networks %s template", kind)
	}
	if _, err := tm.Parse(registryMirrorTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse registry mirror %s template", kind)
	}
	if _, err := tm.Parse(registryMirrorCACertTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse registry mirror ca cert %s template", kind)
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

	bottlerocketInput := &BottlerocketSettingsInput{
		BootstrapContainerUserData: b64BootstrapContainerUserData,
		AdminContainerUserData:     b64AdminContainerUserData,
		BootstrapContainerSource:   fmt.Sprintf("%s:%s", config.BottlerocketBootstrap.ImageRepository, config.BottlerocketBootstrap.ImageTag),
		PauseContainerSource:       fmt.Sprintf("%s:%s", config.Pause.ImageRepository, config.Pause.ImageTag),
		HTTPSProxyEndpoint:         config.ProxyConfiguration.HTTPSProxy,
		NoProxyEndpoints:           config.ProxyConfiguration.NoProxy,
		RegistryMirrorEndpoint:     config.RegistryMirrorConfiguration.Endpoint,
	}
	if config.RegistryMirrorConfiguration.CACert != "" {
		bottlerocketInput.RegistryMirrorCACert = base64.StdEncoding.EncodeToString([]byte(config.RegistryMirrorConfiguration.CACert))
	}

	bottlerocketNodeUserData, err := generateNodeUserData("InitBottlerocketNode", bottlerocketNodeInitSettingsTemplate, bottlerocketInput)
	if err != nil {
		return nil, err
	}
	return bottlerocketNodeUserData, nil
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
