# starboard-security-operator

![build](https://github.com/aquasecurity/starboard-security-operator/workflows/build/badge.svg)

## Getting Started

1. Define custom security resources used by Starboard:
   ```
   $ kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/master/kube/crd/vulnerabilities-crd.yaml \
     -f https://raw.githubusercontent.com/aquasecurity/starboard/master/kube/crd/configauditreports-crd.yaml \
     -f https://raw.githubusercontent.com/aquasecurity/starboard/master/kube/crd/ciskubebenchreports-crd.yaml \
     -f https://raw.githubusercontent.com/aquasecurity/starboard/master/kube/crd/kubehunterreports-crd.yaml
   ```
2. Create a Secret that holds configuration of the Aqua CSP scanner:
   ```
   $ kubectl create secret generic aqua-csp-vulnerability-scanner \
     --namespace starboard \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_USER=$AQUA_CONSOLE_USERNAME \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_PASSWORD=$AQUA_CONSOLE_PASSWORD \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_VERSION=$AQUA_VERSION \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_HOST=http://csp-console-svc.aqua:8080 \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_REGISTRY_SERVER=$AQUA_REGISTRY_SERVER
   ```
3. Create a Docker pull Secret to pull `scannercli` container image from the Aqua registry:
   ```
   $ kubectl create secret docker-registry aqua-csp-registry-credentials \
     --namespace starboard \
     --docker-server=$AQUA_REGISTRY_SERVER \
     --docker-username=$AQUA_REGISTRY_USERNAME \
     --docker-password=$AQUA_REGISTRY_PASSWORD
   ```
4. Create a Service Account used to run Aqua CSP scan Jobs:
   ```
   $ kubectl apply -f kube/aqua-csp-vulnerability-scanner.yaml
   ```
5. Create a Deployment for the Starboard Security Operator:
   ```
   $ kubectl apply -f kube/starboard-security-operator.yaml
   ```

## Configuration

| Name                                    | Default              | Description |
|-----------------------------------------|----------------------|-------------|
| `OPERATOR_STARBOARD_NAMESPACE`          | `starboard`          | The default namespace for Starboard |
| `OPERATOR_STARBOARD_DEFAULT_RESYNC`     | `10m`                | The default resync period for shared informers used by the operator |
| `OPERATOR_SCANNER_TRIVY_ENABLED`        | `true`               | The flag to enable Trivy vulnerability scanner |
| `OPERATOR_SCANNER_TRIVY_VERSION`        | `0.9.1`              | The version of Trivy to be used |
| `OPERATOR_SCANNER_AQUA_CSP_ENABLED`     | `false`              | The flag to enable Aqua CSP vulnerability scanner |
| `OPERATOR_SCANNER_AQUA_CSP_VERSION`     | `4.6`                | The version of Aqua CSP scannercli container image to be used |
| `OPERATOR_SCANNER_AQUA_REGISTRY_SERVER` | `aquasec.azurecr.io` | The name of Aqua registry server to pull the scannercli container image from |
