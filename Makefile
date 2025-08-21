GO ?= $(shell which go)
OS ?= $(shell $(GO) env GOOS)
ARCH ?= $(shell $(GO) env GOARCH)
SWAGGER ?= "$(GOPATH)/bin/swagger"

IMAGE_NAME := "webhook"
IMAGE_TAG := "latest"

OUT := $(shell pwd)/_out

KUBE_VERSION=1.30.0

$(shell mkdir -p "$(OUT)")
export TEST_ASSET_ETCD=_test/kubebuilder/etcd
export TEST_ASSET_KUBE_APISERVER=_test/kubebuilder/kube-apiserver
export TEST_ASSET_KUBECTL=_test/kubebuilder/kubectl

test: _test/kubebuilder
	$(GO) test -v .

_test/kubebuilder:
	curl -fsSL https://go.kubebuilder.io/test-tools/$(KUBE_VERSION)/$(OS)/$(ARCH) -o kubebuilder-tools.tar.gz
	mkdir -p _test/kubebuilder
	tar -xvf kubebuilder-tools.tar.gz
	mv kubebuilder/bin/* _test/kubebuilder/
	rm kubebuilder-tools.tar.gz
	rm -R kubebuilder

clean: clean-kubebuilder

clean-kubebuilder:
	rm -Rf _test/kubebuilder

build:
	docker build -t "$(IMAGE_NAME):$(IMAGE_TAG)" .

.PHONY: rendered-manifest.yaml api-client
rendered-manifest.yaml:
	helm template \
	    --name openprovider-webhook \
            --set image.repository=$(IMAGE_NAME) \
            --set image.tag=$(IMAGE_TAG) \
            deploy/openprovider-webhook > "$(OUT)/rendered-manifest.yaml"

api-client:
	$(SWAGGER) generate client -f https://docs.openprovider.com/swagger.json \
		--default-scheme=https \
		-c opapi/client -m opapi/models \
		--tags Auth --tags ZoneService \
		-M zoneRecord -M zoneRecordUpdates -M zoneUpdateZoneRequest -M authLoginRequest -M authLoginResponse \
		-M authLoginResponseData -M errorError -M zoneCreateZoneRequest -M zoneZoneBoolResponse -M zoneGetZoneResponse \
		-M zoneListZonesResponse -M errorWarning -M zoneDomain -M zoneZone -M zoneListZonesResponseData \
		-M zoneRecordWithOriginal -M zoneDomain -M zonePremiumDnsData -M zoneZoneBoolResponseData \
		-M historyZoneHistory -M recordRecordInfo -M zoneSectigoData
