{{/*
templates/_helpers.tpl — shared name/label snippets (stock Helm convention).
*/}}

{{- define "network-api.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "network-api.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "network-api.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "network-api.labels" -}}
helm.sh/chart: {{ include "network-api.chart" . }}
{{ include "network-api.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: network-api
app.kubernetes.io/part-of: judicial-network
{{- end -}}

{{- define "network-api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "network-api.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "network-api.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "network-api.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Validate the required injected inputs at template time, so a misconfigured
release fails on `helm install` rather than CrashLooping on a missing cert/doc.
*/}}
{{- define "network-api.validate" -}}
{{- if not .Values.serverTLS.existingSecret -}}
{{- fail "network-api: serverTLS.existingSecret is required (a Secret with tls.crt, tls.key AND ca.crt for the mTLS listener, mounted at /etc/network-api/tls)" -}}
{{- end -}}
{{- if not .Values.bootstrap.existingSecret -}}
{{- fail "network-api: bootstrap.existingSecret is required (the network BootstrapDocument, mounted at /etc/network-api/bootstrap.json)" -}}
{{- end -}}
{{- end -}}
