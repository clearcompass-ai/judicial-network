{{/*
=============================================================================
templates/_helpers.tpl — shared name/label snippets (stock Helm convention).

The database-secret helpers resolve the existingSecret-vs-inline-url choice
once and feed the deployment.
=============================================================================
*/}}

{{- define "aggregator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aggregator.fullname" -}}
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

{{- define "aggregator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aggregator.labels" -}}
helm.sh/chart: {{ include "aggregator.chart" . }}
{{ include "aggregator.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: aggregator
app.kubernetes.io/part-of: judicial-network
{{- end -}}

{{- define "aggregator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aggregator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "aggregator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "aggregator.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Database Secret resolution.

database.existingSecret takes precedence; otherwise the chart writes its own
Secret "<fullname>-db" populated from database.url. Either way the deployment
reads key TOOLS_DATABASE_URL from the resolved Secret.
*/}}
{{- define "aggregator.dbSecretName" -}}
{{- if .Values.database.existingSecret -}}
{{- .Values.database.existingSecret -}}
{{- else -}}
{{- printf "%s-db" (include "aggregator.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Validate the database mode at template time. Exactly one of existingSecret or
url must be set, so a misconfigured release fails on `helm install` rather than
CrashLooping on a missing TOOLS_DATABASE_URL.
*/}}
{{- define "aggregator.validateDatabase" -}}
{{- if and (not .Values.database.existingSecret) (not .Values.database.url) -}}
{{- fail "aggregator: configure exactly one of database.existingSecret (key TOOLS_DATABASE_URL) or database.url" -}}
{{- end -}}
{{- end -}}
