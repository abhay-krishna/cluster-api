package bottlerocket

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
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
	BottlerocketControl         bootstrapv1.BottlerocketControl
	ProxyConfiguration          bootstrapv1.ProxyConfiguration
	RegistryMirrorConfiguration bootstrapv1.RegistryMirrorConfiguration
	KubeletExtraArgs            map[string]string
	Taints                      []corev1.Taint
}

type BottlerocketSettingsInput struct {
	BootstrapContainerUserData string
	AdminContainerUserData     string
	BootstrapContainerSource   string
	ControlContainerSource     string
	PauseContainerSource       string
	HTTPSProxyEndpoint         string
	NoProxyEndpoints           []string
	RegistryMirrorEndpoint     string
	RegistryMirrorCACert       string
	NodeLabels                 string
	Taints                     string
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
	tm := template.New(kind).Funcs(template.FuncMap{"stringsJoin": strings.Join})
	if _, err := tm.Parse(bootstrapHostContainerTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse hostContainer %s template", kind)
	}
	if _, err := tm.Parse(adminContainerInitTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse adminContainer %s template", kind)
	}
	if _, err := tm.Parse(controlContainerTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse controlContainer %s template", kind)
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
	if _, err := tm.Parse(nodeLabelsTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse node labels %s template", kind)
	}
	if _, err := tm.Parse(taintsTemplate); err != nil {
		return nil, errors.Wrapf(err, "failed to parse taints %s template", kind)
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
		RegistryMirrorEndpoint:     config.RegistryMirrorConfiguration.Endpoint,
		NodeLabels:                 parseNodeLabels(config.KubeletExtraArgs["node-labels"]), // empty string if it does not exist
		Taints:                     parseTaints(config.Taints), //empty string if it does not exist
	}
	if config.BottlerocketControl.ImageRepository != "" && config.BottlerocketControl.ImageTag != "" {
		bottlerocketInput.ControlContainerSource = fmt.Sprintf("%s:%s", config.BottlerocketControl.ImageRepository, config.BottlerocketControl.ImageTag)
	}
	if len(config.ProxyConfiguration.NoProxy) > 0 {
		for _, noProxy := range config.ProxyConfiguration.NoProxy {
			bottlerocketInput.NoProxyEndpoints = append(bottlerocketInput.NoProxyEndpoints, strconv.Quote(noProxy))
		}
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
		taintsMap[taint.Key]= append(taintsMap[taint.Key], valueEffectString)
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
