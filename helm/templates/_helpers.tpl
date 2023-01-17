{{/*
Expand the name of the chart.
*/}}
{{- define "anchore-ui.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "anchore-ui.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "anchore-ui.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "anchore-ui.labels" -}}
helm.sh/chart: {{ include "anchore-ui.chart" . }}
{{ include "anchore-ui.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "anchore-ui.selectorLabels" -}}
app.kubernetes.io/name: {{ include "anchore-ui.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "anchore-ui.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "anchore-ui.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the secret with anchore-ui credentials
*/}}
{{- define "anchore-ui.uiSecretName" -}}
    {{- if .Values.auth.existingSecret -}}
        {{- printf "%s" (tpl .Values.auth.existingSecret $) -}}
    {{- else -}}
        {{- printf "%s" (include "anchore-ui.fullname" .) -}}
    {{- end -}}
{{- end -}}

{{/*
Return true if a secret object should be created for anchore-ui;
*/}}
{{- define "anchore-ui.uiCreateSecret" -}}
{{- if not .Values.auth.existingSecret }}
    {{- true -}}
{{- end -}}
{{- end -}}

{{/*
Password value
*/}}
{{- define "anchore-ui.uiPassword" -}}
{{- default (randAlphaNum 16) .Values.auth.password | b64enc | quote }}
{{- end }}


{{/*
Return the secret with anchore-engine credentials
*/}}
{{- define "anchore-ui.engineSecretName" -}}
    {{- if .Values.anchore.api.auth.existingSecret -}}
        {{- printf "%s" (tpl .Values.anchore.api.auth.existingSecret $) -}}
    {{- else -}}
        {{- printf "%s-engine" (include "anchore-ui.fullname" .) -}}
    {{- end -}}
{{- end -}}

{{/*
Return true if a secret object should be created for anchore-engine;
*/}}
{{- define "anchore-ui.engineCreateSecret" -}}
{{- if not .Values.anchore.api.auth.existingSecret }}
    {{- true -}}
{{- end -}}
{{- end -}}

{{/*
Engine secret Login key
*/}}
{{- define "anchore-ui.engineSecretLoginKey" -}}
{{- default "login" .Values.anchore.api.auth.existingSecretLoginKey | quote }}
{{- end -}}

{{/*
Engine secret Password key
*/}}
{{- define "anchore-ui.engineSecretPasswordKey" -}}
{{- default "password" .Values.anchore.api.auth.existingSecretPasswordKey | quote }}
{{- end -}}