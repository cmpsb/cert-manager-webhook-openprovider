# 🪐🍌⚓ Openprovider cert-manager webhook

This webhook provides support for DNS01 ACME verification using the [Openprovider](https://www.openprovider.com/) API.

## Installation

### Helm

```shell
$ git clone https://git.wukl.net/wukl/cert-manager-webhook-openprovider
$ helm install cert-manager-webhook-openprovider --namespace=cert-manager ./deploy/openprovider-webhook
```


## Configuration

At a minimum, this webhook needs your Openprovider username and password. Both of these need to be stored in a secret.
