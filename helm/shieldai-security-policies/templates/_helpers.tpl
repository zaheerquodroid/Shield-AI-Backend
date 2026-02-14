{{/*
Expand the name of the chart.
*/}}
{{- define "shieldai.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "shieldai.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "shieldai.labels" -}}
helm.sh/chart: {{ include "shieldai.chart" . }}
{{ include "shieldai.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "shieldai.selectorLabels" -}}
app.kubernetes.io/name: {{ include "shieldai.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Chart label
*/}}
{{- define "shieldai.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Namespace — use .Values.namespace if set, otherwise release namespace.
*/}}
{{- define "shieldai.namespace" -}}
{{- if .Values.namespace }}
{{- .Values.namespace }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
Validate a PodSecurity Standards level.
Usage: {{ include "shieldai.validatePSSLevel" (dict "level" "restricted" "field" "enforce") }}
*/}}
{{- define "shieldai.validatePSSLevel" -}}
{{- $valid := list "restricted" "baseline" "privileged" }}
{{- if not (has .level $valid) }}
{{- fail (printf "Invalid PodSecurity level '%s' for %s. Must be one of: restricted, baseline, privileged" .level .field) }}
{{- end }}
{{- end }}

{{/*
Pod Security Standards admission labels for namespace.
*/}}
{{- define "shieldai.podSecurityLabels" -}}
{{- if .Values.podSecurity.enabled }}
pod-security.kubernetes.io/enforce: {{ .Values.podSecurity.enforce | quote }}
pod-security.kubernetes.io/enforce-version: {{ .Values.podSecurity.version | quote }}
pod-security.kubernetes.io/audit: {{ .Values.podSecurity.audit | quote }}
pod-security.kubernetes.io/audit-version: {{ .Values.podSecurity.version | quote }}
pod-security.kubernetes.io/warn: {{ .Values.podSecurity.warn | quote }}
pod-security.kubernetes.io/warn-version: {{ .Values.podSecurity.version | quote }}
{{- end }}
{{- end }}
