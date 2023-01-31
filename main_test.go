package main

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"fmt"
	mathRand "math/rand"
	"os"
	"testing"

	"github.com/cert-manager/cert-manager/test/acme/dns"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
	nses = []string{
		"ns1.openprovider.nl",
		"ns2.openprovider.be",
		"ns3.openprovider.eu",
	}
)

func makeBase64String(length int) string {
	bytes := make([]byte, length)
	_, err := cryptoRand.Read(bytes)
	if err != nil {
		panic(fmt.Sprintf("Could not read %v random bytes", length))
	}

	return base64.URLEncoding.EncodeToString(bytes)
}

func TestRunsSuite(t *testing.T) {
	if zone == "" {
		panic("TEST_ZONE_NAME must be specified")
	}

	key := makeBase64String(36)
	name := makeBase64String(6) + "-cert-manager-dns01-tests." + zone

	fixture := dns.NewFixture(&openproviderDNSProviderSolver{},
		dns.SetResolvedZone(zone),
		dns.SetResolvedFQDN(name),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/openprovider"),
		dns.SetDNSChallengeKey(key),
		dns.SetStrict(true),
		dns.SetDNSName(nses[mathRand.Intn(len(nses))]),
	)

	fixture.RunConformance(t)
}
