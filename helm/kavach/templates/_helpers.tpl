{{/*
SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
*/}}
{{- define "kavach.name" -}}kavach{{- end -}}

{{- define "kavach.labels" -}}
app.kubernetes.io/name: {{ include "kavach.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "kavach.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kavach.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kavach.authSecretName" -}}
{{- if .Values.auth.existingSecret -}}
{{ .Values.auth.existingSecret }}
{{- else -}}
kavach-auth
{{- end -}}
{{- end -}}

{{- define "kavach.scheme" -}}
{{- if .Values.tls.enabled -}}https{{- else -}}http{{- end -}}
{{- end -}}

{{- define "kavach.serverURL" -}}
{{- default (printf "%s://kavach.%s.svc:%v" (include "kavach.scheme" .) .Release.Namespace .Values.service.port) .Values.agent.server -}}
{{- end -}}

{{- define "kavach.mtlsMode" -}}
{{- $m := (.Values.mtls.mode | default "off" | toString | lower) -}}
{{- if not (has $m (list "off" "optional" "required")) -}}
{{- fail (printf "mtls.mode=%q: want off, optional or required" $m) -}}
{{- end -}}
{{- if and (ne $m "off") (not .Values.tls.enabled) -}}
{{- fail "mtls.mode needs tls.enabled=true (a client certificate cannot be requested over plain HTTP)" -}}
{{- end -}}
{{- if and (ne $m "off") (not .Values.mtls.secretName) -}}
{{- fail "mtls.mode needs mtls.secretName (a Secret with ca.crt; agents also need tls.crt and tls.key)" -}}
{{- end -}}
{{- $m -}}
{{- end -}}
