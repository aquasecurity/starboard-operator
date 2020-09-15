# starboard-operator

[![GitHub Release][release-img]][release]
[![GitHub Build Actions][build-action-img]][actions]
[![Coverage Status][cov-img]][cov]

This operator for Starboard automatically updates security report resources in response to workload and other changes on
a Kubernetes cluster - for example, initiating a vulnerability scan when a new pod is started. Please see the main
[Starboard](https://github.com/aquasecurity/starboard) repo for more info about the Starboard project.

## Getting started

1. Run `make` to build operator binaries into Docker containers:
   ```
   $ make docker-build
   ```
1. Define Custom Security Resources used by Starboard:
   ```
   $ kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/master/kube/crd/vulnerabilities-crd.yaml \
     -f https://raw.githubusercontent.com/aquasecurity/starboard/master/kube/crd/configauditreports-crd.yaml \
     -f https://raw.githubusercontent.com/aquasecurity/starboard/master/kube/crd/ciskubebenchreports-crd.yaml \
     -f https://raw.githubusercontent.com/aquasecurity/starboard/master/kube/crd/kubehunterreports-crd.yaml
   ```
2. Create the `starboard-operator` Namespace:
   ```
   $ kubectl create ns starboard-operator
   ```
3. Create a Secret that holds configuration of the Aqua CSP scanner:
   ```
   $ kubectl create secret generic starboard-operator \
     --namespace starboard-operator \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_USERNAME=$AQUA_CONSOLE_USERNAME \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_PASSWORD=$AQUA_CONSOLE_PASSWORD \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_VERSION=$AQUA_VERSION \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_HOST=http://csp-console-svc.aqua:8080
   ```
5. Create a Deployment for the Starboard Operator:
   ```
   $ kubectl apply -f deploy/starboard-operator.yaml
   ```

## Configuration

| Name                                    | Default              | Description |
|-----------------------------------------|----------------------|-------------|
| `OPERATOR_STARBOARD_NAMESPACE`          | `starboard-operator` | The default namespace for Starboard |
| `OPERATOR_SUPERVISED_NAMESPACE`         | `default`            | The namespace watched by the operator |
| `OPERATOR_SCAN_JOB_TIMEOUT`             | `5m`                 | The length of time to wait before giving up on a scan job |
| `OPERATOR_SCANNER_TRIVY_ENABLED`        | `true`               | The flag to enable Trivy vulnerability scanner |
| `OPERATOR_SCANNER_TRIVY_VERSION`        | `0.11.0`              | The version of Trivy to be used |
| `OPERATOR_SCANNER_AQUA_CSP_ENABLED`     | `false`              | The flag to enable Aqua CSP vulnerability scanner |
| `OPERATOR_SCANNER_AQUA_CSP_VERSION`     | `5.0`                | The version of Aqua CSP scannercli container image to be used |

## How does it work?

![](docs/starboard-operator.png)

[release-img]: https://img.shields.io/github/release/aquasecurity/starboard-operator.svg?logo=github
[release]: https://github.com/aquasecurity/starboard-operator/releases
[build-action-img]: https://github.com/aquasecurity/starboard-operator/workflows/build/badge.svg
[actions]: https://github.com/aquasecurity/starboard-operator/actions
[cov-img]: https://codecov.io/github/aquasecurity/starboard-operator/branch/master/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/starboard-operator
