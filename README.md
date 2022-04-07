# Terraform Helm Scanning

Use this action to scan Docker image digests in a Terraform Helm repository using Trivy.

Use with the *Terraform Helm Digests* action.

## Requirements

This action scans an ```images.yaml``` file which contains image registries, names and digests for AMD64 and ARM64 images. This file is generated automatically by the *Terraform Helm Digests* action. This file is required to be in the following format:

```images.yaml```

```yaml
- registry: registry-x
  name: image-x
  digests:
    amd64: sha256:digest-x-amd64
    arm64: sha256:digest-x-arm64
- registry: registry-y
  name: image-y
  digests:
    amd64: sha256:digest-y-amd64
    arm64: sha256:digest-y-arm64
...
```

Furthermore, a file called ```security_rules.yaml``` defining scanning security rules can be defined in the Terraform module repository.

```security_rules.yaml```

```yaml
- name: image-x
  severityLevels: [medium, high, critical]
  acceptedSeverities:
  - cve: some-cve
    reason: "A reason for excluding this CVE"
  ...
  ignoreUnfixed: true
...
```

If this file does not exist, or entries for certain images do not exist, defaults will be used for the non-specified images, as below:

- Severity levels: Medium, High, Critical
- No accepted severities
- Unfixable CVEs will not be ignored

See Trivy documentation for more information.

## Usage

This action will run Trivy scans on every image in the ```images.yaml``` file against any settings in the ```security_rules.yaml``` file as described above, and output the results of each scan in JSON format in the ```results``` output.

Below is an example pull request workflow, which will scan the images on every pull request if the ```images.yaml``` changes in the pull request.

```yaml
name: Terraform Helm Scan
on:
  pull_request:
    paths: ## Only runs if the list of images or security rules have changed in the PR
    - 'images.yaml'
    - 'security_rules.yaml'
    types:
    - opened
    - synchronize
    - edited
    - reopened
    branches:
    - main

jobs:
  scan:
    name: Trivy scan Helm images
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3
      
      - name: Helm version update
        uses: clarkjohnd/terraform-helm-scanning@v0.0.1
```

If a vulnerability is found that is not defined in the accepted severities settings of ```security_rules.yaml``` (```acceptedSeverities```) or comes under unfixable severities that is enabled for that image (```ignoreUnfixed```), then the action will fail with error code 1. All images will continue to be scanned, and the full output of all images is available in JSON format, as well as the security rules provided to the action to explain why certain vulnerabilities are acceptable etc.
