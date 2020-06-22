# starboard-security-operator

![build](https://github.com/aquasecurity/starboard-security-operator/workflows/build/badge.svg)

## Getting Started

```
$ kubectl create secret generic starboard-security-operator \
  --namespace starboard \
  --from-literal OPERATOR_SCANNER_AQUA_CSP_USER=$AQUA_CONSOLE_USERNAME \
  --from-literal OPERATOR_SCANNER_AQUA_CSP_PASSWORD=$AQUA_CONSOLE_PASSWORD \
  --from-literal OPERATOR_SCANNER_AQUA_CSP_VERSION=$AQUA_VERSION \
  --from-literal OPERATOR_SCANNER_AQUA_CSP_HOST=http://csp-console-svc.aqua:8080
```

```
$ kubectl create secret docker-registry starboard-registry-credentials \
  --namespace starboard \
  --docker-server=$AQUA_REGISTRY_SERVER \
  --docker-username=$AQUA_REGISTRY_USERNAME \
  --docker-password=$AQUA_REGISTRY_PASSWORD
```

```
$ kubectl apply -f kube/starboard-security-operator.yaml
```
