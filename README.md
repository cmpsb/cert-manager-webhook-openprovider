# 🪐🍌⚓ Openprovider cert-manager webhook

This webhook provides support for DNS01 ACME verification using the [Openprovider](https://www.openprovider.com/) API.

## Installation

### Helm

```shell
$ helm repo add cert-manager-webhook-openprovider-master https://git.wukl.net/api/v4/projects/149/packages/helm/master
$ helm upgrade --install -n cert-manager cert-manager-webhook-openprovider cert-manager-webhook-openprovider-master/openprovider-webhook
```


## Configuration

At a minimum, this webhook needs your Openprovider username and password. Both of these need to be stored in a secret.
