# Contributing

These guidelines will help you get started with the Starboard Operator project.

## Prerequisites

1. Install Go

   The project requires [Go 1.14][go-download] or later. We also assume that you're familiar with
   Go's [GOPATH workspace][go-code] convention, and have the appropriate environment variables set.
2. Get the source code:

   ```
   $ git clone git@github.com:aquasecurity/starboard-operator.git
   $ cd starboard-operator
   ```
3. Access to a dev Kubernetes cluster. We assume that you're using a single-node [KIND][kind] cluster created with the
   following command:

   ```
   $ kind create cluster
   ```

## Deployment

You'll deploy the operator in the `starboard-operator` Namespace and configure it to watch the `starboard-operator`
Namespace. In OLM terms such install mode is called `OwnNamespace` and is suitable for end users who want to install
the operator in the same namespace as supervised workloads.

> The `OwnNamespace` mode is good to get started with a basic development workflow. For other install modes see
> [Operator Multitenancy with OperatorGroups][olm-operator-groups].

### Prerequisites

1. Build Docker images:

   ```
   $ make docker-build
   ```

   This will build the `docker.io/aquasec/starboard-operator:dev` as well as `docker.io/aquasec/starboard-scanner-aqua:dev`
   images. The second image is only used when you enable the Aqua CSP scanner. By default Trivy is used as vulnerability
   scanner by pulling its official image accessible from DockerHub (`docker.io/aquasec/trivy:$TRIVY_VERSION`).
2. Load Docker images into the cluster node:

   ```
   $ kind load docker-image aquasec/starboard-operator:dev
   $ kind load docker-image aquasec/starboard-scanner-aqua:dev
   ```
3. Send the definition of the VulnerabilityReport custom resource to the Kubernetes API:

   ```
   $ kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/master/kube/crd/vulnerabilityreports-crd.yaml
   ```
4. Send the following Kubernetes objects definitions to the Kubernetes API:

   ```
   $ kubectl apply -f deploy/kubectl/01-starboard-operator.ns.yaml \
       -f deploy/kubectl/02-starboard-operator.sa.yaml \
       -f deploy/kubectl/03-starboard-operator.role.yaml \
       -f deploy/kubectl/04-starboard-operator.rolebinding.yaml
   ```

   This will create the `starboard-operator` Namespace, and the `starboard-operator` ServiceAccount. Beyond that,
   it will create the `starboard-operator` Role and bind it to the `starboard-operator` ServiceAccount in the
   `starboard-operator` Namespace via the `starboard-operator` RoleBinding.

### In cluster

1. Create the `starboard-operator` Deployment in the `starboard-operator` namespace to run the operator's container:

   ```
   $ kubectl apply -f deploy/kubectl/05-starboard-operator.deployment.yaml
   ```

### Out of cluster

1. Run the main method of the operator program:

   ```
   $ go run cmd/operator/main.go
   ```

### Enable Aqua CSP scanner

1. Create the `starboard-operator` secret in the `starboard-operator` namespace that holds the scanner's configuration:

   ```
   $ kubectl create secret generic starboard-operator \
     --namespace starboard-operator \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_USERNAME=$AQUA_CONSOLE_USERNAME \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_PASSWORD=$AQUA_CONSOLE_PASSWORD \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_VERSION=$AQUA_VERSION \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_HOST=http://csp-console-svc.aqua:8080
   ```

## Operator Lifecycle Manager

### Prerequisites

1. Install [Operator Lifecycle Manager][olm] (OLM) and [Operator Marketplace][operator-marketplace]:

   ```
   $ ./deploy/olm/install.sh
   ```

2. Install [Operator Courier][operator-courier]:

   ```
   $ pip3 install operator-courier
   ```
3. [Sign up][quay] for a free Quay.io account if you're a new user.

### Build OLM bundle

1. Lint the OLM bundle:

   ```
   $ BUNDLE_SRC_DIR=deploy/olm/bundle
   $ operator-courier verify $BUNDLE_SRC_DIR
   ```
2. Retrieve a Quay.io token:
   ```
   $ QUAY_USERNAME=<your quay.io username>
   $ QUAY_PASSWORD=<your quay.io password>
   $ QUAY_URL=https://quay.io/cnr/api/v1/users/login

   $ QUAY_TOKEN=$(curl -s -H "Content-Type: application/json" -XPOST $QUAY_URL -d \
     '{"user":{"username":"'"${QUAY_USERNAME}"'","password": "'"${QUAY_PASSWORD}"'"}}' |
     jq -r .token)
   ```
3. Push the OLM bundle to Quay.io:
   ```
   $ QUAY_NAMESPACE=<quay.io namespace>
   $ PACKAGE_NAME=starboard-operator
   $ PACKAGE_VERSION=<next package version>

   $ operator-courier push "$BUNDLE_SRC_DIR" "$QUAY_NAMESPACE" \
     "$PACKAGE_NAME" "$PACKAGE_VERSION" "$QUAY_TOKEN"
   ```

### Create ClusterServiceVersion

1. Create the OperatorSource resource:

   ```
   QUAY_FULL_NAME=<your quay.io full name>
   $ cat << EOF | kubectl apply -f -
   apiVersion: operators.coreos.com/v1
   kind: OperatorSource
   metadata:
     name: $QUAY_USERNAME-operators
     namespace: marketplace
   spec:
     type: appregistry
     endpoint: https://quay.io/cnr
     displayName: "$QUAY_FULL_NAME Quay.io Applications"
     publisher: "$QUAY_FULL_NAME"
     registryNamespace: "$QUAY_USERNAME"
   EOF
   ```

   An OperatorSource resource defines the external data store used to host operator bundles. In this case, you will be
   defining an OperatorSource to point to your Quay.io account, which will provide access to its hosted OLM bundles.

2. Create the OperatorGroup resource:

   ```
   $ cat << EOF | kubectl apply -f -
   apiVersion: operators.coreos.com/v1alpha2
   kind: OperatorGroup
   metadata:
     name: workloads
     namespace: marketplace
   spec:
     targetNamespaces:
     - marketplace
   EOF
   ```

   You'll need an OperatorGroup to denote which namespaces the operator should watch. It must exist in the namespace
   where you want to deploy the operator.

3. Create the Subscription resource
   1. with Trivy scanner, which is enabled by default:

      ```
      $ cat << EOF | kubectl apply -f -
      apiVersion: operators.coreos.com/v1alpha1
      kind: Subscription
      metadata:
        name: starboard-operator
        namespace: marketplace
      spec:
        channel: alpha
        name: starboard-operator
        source: $QUAY_NAMESPACE-operators
        sourceNamespace: marketplace
      EOF
      ```
   2. with Aqua CSP scanner:

      ```
      $ kubectl create secret generic starboard-operator \
          --namespace marketplace \
          --from-literal OPERATOR_SCANNER_AQUA_CSP_USERNAME=$AQUA_CONSOLE_USERNAME \
          --from-literal OPERATOR_SCANNER_AQUA_CSP_PASSWORD=$AQUA_CONSOLE_PASSWORD \
          --from-literal OPERATOR_SCANNER_AQUA_CSP_VERSION=$AQUA_VERSION \
          --from-literal OPERATOR_SCANNER_AQUA_CSP_HOST=http://csp-console-svc.aqua:8080
      ```

      ```
      $ cat << EOF | kubectl apply -f -
      apiVersion: operators.coreos.com/v1alpha1
      kind: Subscription
      metadata:
        name: starboard-operator
        namespace: marketplace
      spec:
        channel: alpha
        name: starboard-operator
        source: $QUAY_NAMESPACE-operators
        sourceNamespace: marketplace
        config:
          env:
          - name: OPERATOR_SCANNER_TRIVY_ENABLED
            value: "false"
          - name: OPERATOR_SCANNER_AQUA_CSP_ENABLED
            value: "true"
          envFrom:
          - secretRef:
              name: starboard-operator
      EOF
      ```

   A Subscription links the previous steps together by selecting an operator and one of its channels. OLM uses this
   information to start the corresponding operator Pod. The example above creates a new Subscription to the `alpha`
   channel for the Starboard Operator.

[go-download]: https://golang.org/dl/
[go-code]: https://golang.org/doc/code.html
[kind]: https://github.com/kubernetes-sigs/kind
[olm]: https://github.com/operator-framework/operator-lifecycle-manager
[operator-marketplace]: https://github.com/operator-framework/operator-marketplace
[operator-courier]: https://github.com/operator-framework/operator-courier
[olm-operator-groups]: https://github.com/operator-framework/operator-lifecycle-manager/blob/master/doc/design/operatorgroups.md
[quay]: https://quay.io
