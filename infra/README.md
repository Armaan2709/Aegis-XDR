# AegisAI XDR — Infrastructure as Code (IaC) & Deployment

This directory holds deployment infrastructure configurations for staging and production environments.

## Directory Contents

- `terraform/`: Cloud infrastructure modules (AWS / Azure / GCP) provisioning managed Postgres, Elastic Cloud, and Kubernetes clusters.
- `kubernetes/` (`k8s/`): Helm charts and Kubernetes manifests for production microservice deployment.
- `ansible/`: Configuration management playbooks for bare-metal SOC deployments.
