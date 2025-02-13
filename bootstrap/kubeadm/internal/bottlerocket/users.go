package bottlerocket

const (
	usersTemplate = `{{- if . }}
{
	"ssh": {
		"authorized-keys": [{{.}}]
	}
}
{{- end -}}
`
)
