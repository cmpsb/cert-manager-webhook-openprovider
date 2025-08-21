package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	certManV1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/runtime/logger"
	"golang.org/x/crypto/sha3"
	k8sV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"net/url"
	"os"
	"strings"
	"time"
	"wukl.net/projects/cert-manager-webhook-openprovider/opapi/client"
	"wukl.net/projects/cert-manager-webhook-openprovider/opapi/client/auth"
	"wukl.net/projects/cert-manager-webhook-openprovider/opapi/client/zone_service"
	"wukl.net/projects/cert-manager-webhook-openprovider/opapi/models"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

// reasonable upper bound for DNS discovery
const findZoneTimeout = 20 * time.Second

var (
	GroupName = os.Getenv("GROUP_NAME")
	CacheDir  = os.Getenv("CMWO_CACHE_DIR")
)

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&openproviderDNSProviderSolver{},
	)
}

// openproviderDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
type openproviderDNSProviderSolver struct {
	client *kubernetes.Clientset
	logger logger.Logger
}

type AuthSecretRef struct {
	certManV1.LocalObjectReference

	UsernameKey string `json:"usernameKey,omitempty"`
	PasswordKey string `json:"passwordKey,omitempty"`
}

type openproviderDNSProviderConfig struct {
	ApiUrl string `json:"apiUrl,omitempty"`

	Username string        `json:"username,omitempty"`
	Password string        `json:"password,omitempty"`
	Secret   AuthSecretRef `json:"secret,omitempty"`

	RestrictIp string `json:"restrictIp,omitempty"`

	Ttl int32 `json:"ttl,omitempty"`

	Nameservers []string `json:"nameservers,omitempty"`
}

type authTokenCache struct {
	Token    string `json:"token,omitempty"`
	Expires  int64  `json:"expires,omitempty"`
	CredHash string `json:"credHash,omitempty"`
}

func (c *openproviderDNSProviderConfig) GetNameservers() []string {
	if len(c.Nameservers) == 0 {
		return []string {
			"ns1.openprovider.nl:53",
			"ns2.openprovider.be:53",
			"ns3.openprovider.eu:53",
		}
	}

	return c.Nameservers
}

func (c *openproviderDNSProviderConfig) GetCredHash() string {
	credConcat := c.Username + ":" + c.Password

	hash := sha3.Sum512([]byte(credConcat))

	return base64.URLEncoding.EncodeToString(hash[:])
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
func (c *openproviderDNSProviderSolver) Name() string {
	return "openprovider"
}

func (c *openproviderDNSProviderSolver) authenticate(
	ch *v1alpha1.ChallengeRequest,
	cfg *openproviderDNSProviderConfig,
) (*client.RESTAPI, error) {
	c.logger.Printf("[auth] start (ns=%s, api=%s)", ch.ResourceNamespace, cfg.ApiUrl)
	tcfg := client.DefaultTransportConfig()
	if len(cfg.ApiUrl) > 0 {
		u, err := url.Parse(cfg.ApiUrl)
		if err != nil {
			return nil, err
		}

		tcfg = &client.TransportConfig{
			Schemes:  []string{u.Scheme},
			Host:     u.Host,
			BasePath: u.Path,
		}
	}

	username := cfg.Username
	password := cfg.Password
	if len(username) == 0 && len(password) == 0 {
		c.logger.Printf("[auth] loading credentials from secret in ns=%s", ch.ResourceNamespace)
		secretName := cfg.Secret.Name
		if len(secretName) == 0 {
			secretName = "openprovider-credentials"
		}

		secret, err := c.client.CoreV1().
			Secrets(ch.ResourceNamespace).
			Get(context.TODO(), secretName, k8sV1.GetOptions{})
		if err != nil {
			return nil, err
		}

		usernameKey := cfg.Secret.UsernameKey
		if len(usernameKey) == 0 {
			usernameKey = "username"
		}
		var exists bool
		usernameRaw, exists := secret.Data[usernameKey]
		if !exists {
			return nil, fmt.Errorf("no username under %v/%v.%v", ch.ResourceNamespace, secretName, usernameKey)
		}
		username = string(usernameRaw)

		passwordKey := cfg.Secret.PasswordKey
		if len(passwordKey) == 0 {
			passwordKey = "password"
		}
		passwordRaw, exists := secret.Data[passwordKey]
		if !exists {
			return nil, fmt.Errorf("no password under %v/%v.%v", ch.ResourceNamespace, secretName, passwordKey)
		}
		password = string(passwordRaw)
	}

	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)

	transport := httptransport.New(tcfg.Host, tcfg.BasePath, tcfg.Schemes)
	apiClient := client.New(transport, nil)

	credHash := cfg.GetCredHash()
	cachedToken := c.loadAuthTokenCache()
	now := time.Now().Unix()
	if now > cachedToken.Expires || cachedToken.CredHash != credHash {
		c.logger.Printf("[auth] no valid cached token (expired=%t, credMatch=%t), logging in", now > cachedToken.Expires, cachedToken.CredHash == credHash)
		restrictIp := cfg.RestrictIp
		if len(restrictIp) == 0 {
			restrictIp = "0.0.0.0"
		}

		r, err := apiClient.Auth.Login(auth.NewLoginParams().WithBody(&models.AuthLoginRequest{
			Username: username,
			Password: password,
			IP:       restrictIp,
		}),
			nil)
		if err != nil {
			return nil, err
		}

		cachedToken = &authTokenCache{
			Token:    r.Payload.Data.Token,
			Expires:  time.Now().Add(36 * time.Hour).Unix(),
			CredHash: credHash,
		}

		c.storeAuthTokenCache(cachedToken)
		c.logger.Printf("[auth] obtained token (exp=%d)", cachedToken.Expires)
	} else {
		c.logger.Printf("[auth] using cached token (exp=%d)", cachedToken.Expires)
	}

	token := httptransport.BearerToken(cachedToken.Token)
	transport.DefaultAuthentication = token

	return apiClient, nil
}

func (c *openproviderDNSProviderSolver) NewDnsEntryFromChallenge(
	ch *v1alpha1.ChallengeRequest,
	cfg *openproviderDNSProviderConfig,
	zone string,
) *models.ZoneRecord {
	return &models.ZoneRecord{
		Name:  strings.ToLower(extractRecordName(ch.ResolvedFQDN, zone)),
		TTL:   cfg.Ttl,
		Type:  "TXT",
		Value: ch.Key,
	}
}

func (c *openproviderDNSProviderSolver) getDnsZone(
	apiClient *client.RESTAPI,
	zoneName string,
) ([]*models.RecordRecordInfo, error) {
	c.logger.Printf("[zone] fetching zone records for %s", zoneName)

	trueConcrete := true
	res, err := apiClient.ZoneService.GetZone(
		zone_service.NewGetZoneParams().WithName(zoneName).WithWithRecords(&trueConcrete),
		nil,
	)
	if err != nil {
		c.logger.Printf("[zone] GetZone error for %s: %v", zoneName, err)
		return nil, err
	}

	if res != nil && res.Payload != nil && res.Payload.Data != nil {
		c.logger.Printf("[zone] %s: %d records", zoneName, len(res.Payload.Data.Records))
	}

	return res.Payload.Data.Records, nil
}

func recordInfoToZoneRecord(info *models.RecordRecordInfo, zoneName string) models.ZoneRecord {
	return models.ZoneRecord{
		Name:  extractRecordName(info.Name, zoneName),
		Prio:  info.Prio,
		TTL:   info.TTL,
		Type:  info.Type,
		Value: info.Value,
	}
}

func (c *openproviderDNSProviderSolver) findExistingRecord(
	apiClient *client.RESTAPI,
	zoneName string,
	record *models.ZoneRecord,
) (*models.RecordRecordInfo, error) {
	records, err := c.getDnsZone(apiClient, zoneName)
	if err != nil {
		return nil, err
	}

	fqdn := strings.ToLower(record.Name + "." + zoneName)
	quotedValue := "\"" + record.Value + "\""

	for _, v := range records {
		vName := strings.TrimSuffix(strings.ToLower(v.Name), ".")
		if vName == fqdn && strings.EqualFold(v.Type, record.Type) && (v.Value == record.Value || v.Value == quotedValue) {
			return v, nil
		}
	}

	return nil, nil
}

// Present is responsible for actually presenting the DNS record with the DNS provider.
func (c *openproviderDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	c.logger.Printf("[present] start resolvedFQDN=%s resolvedZone(from cm)=%s ttl=%d ns=%v",ch.ResolvedFQDN, ch.ResolvedZone, cfg.Ttl, cfg.GetNameservers())
	apiClient, err := c.authenticate(ch, cfg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), findZoneTimeout)
	defer cancel()

	zoneFqdn, err := util.FindZoneByFqdn(ctx, ch.ResolvedFQDN, cfg.GetNameservers())
	if err != nil {
		c.logger.Printf("[present] FindZoneByFqdn error: %v (resolvedFQDN=%s, ns=%v)", err, ch.ResolvedFQDN, cfg.GetNameservers())
		return err
	}

	zoneName := getZone(zoneFqdn)
	if !strings.Contains(zoneName, ".") { // likely a public suffix like "com"
		err := fmt.Errorf("discovered zone %q looks like a public suffix; refusing to update (fqdn=%s)", zoneName, ch.ResolvedFQDN)
		c.logger.Printf("[present] %v", err)
		return err
    }
	c.logger.Printf("[present] discovered zoneFqdn=%s zoneName=%s", zoneFqdn, zoneName)

	newRecord := c.NewDnsEntryFromChallenge(ch, cfg, zoneName)
	c.logger.Printf("[present] desired record: Name=%s Type=%s TTL=%d Value=%s", newRecord.Name, newRecord.Type, newRecord.TTL, newRecord.Value)

	existingRecord, err := c.findExistingRecord(apiClient, zoneName, newRecord)
	if err != nil {
		return err
	}

	var recordUpdates models.ZoneRecordUpdates
	if existingRecord != nil {
		c.logger.Printf("[present] existing record found; will UPDATE")
		originalRecord := recordInfoToZoneRecord(existingRecord, zoneName)
		recordUpdates = models.ZoneRecordUpdates{
			Update: []*models.ZoneRecordWithOriginal{
				{
					OriginalRecord: &originalRecord,
					Record:         newRecord,
				},
			},
		}
	} else {
		c.logger.Printf("[present] no existing record; will ADD")
		recordUpdates = models.ZoneRecordUpdates{
			Add: []*models.ZoneRecord{newRecord},
		}
	}

	res, err := apiClient.ZoneService.UpdateZone(zone_service.NewUpdateZoneParams().WithName(zoneName).WithBody(
		&models.ZoneUpdateZoneRequest{
			Name:    zoneName,
			Records: &recordUpdates,
		},
	), nil)

	if err != nil {
		c.logger.Printf("[present] UpdateZone error for %s: %v", zoneName, err)
		return err
	}

	if res != nil && res.Payload != nil && res.Payload.Data != nil {
		c.logger.Printf("[present] UpdateZone OK for %s", zoneName)
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
func (c *openproviderDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	c.logger.Printf("[cleanup] start resolvedFQDN=%s resolvedZone(from cm)=%s ttl=%d ns=%v", ch.ResolvedFQDN, ch.ResolvedZone, cfg.Ttl, cfg.GetNameservers())

	apiClient, err := c.authenticate(ch, cfg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), findZoneTimeout)
	defer cancel()

	zoneFqdn, err := util.FindZoneByFqdn(ctx, ch.ResolvedFQDN, cfg.GetNameservers())
	if err != nil {
		c.logger.Printf("[cleanup] FindZoneByFqdn error: %v (resolvedFQDN=%s, ns=%v)", err, ch.ResolvedFQDN, cfg.GetNameservers())
		return err
	}

	zoneName := getZone(zoneFqdn)
	if !strings.Contains(zoneName, ".") {
		err := fmt.Errorf("discovered zone %q looks like a public suffix; refusing to update (fqdn=%s)", zoneName, ch.ResolvedFQDN)
		c.logger.Printf("[cleanup] %v", err)
		return err
	}

	c.logger.Printf("[cleanup] discovered zoneFqdn=%s zoneName=%s", zoneFqdn, zoneName)

	refRecord := c.NewDnsEntryFromChallenge(ch, cfg, zoneName)
	c.logger.Printf("[cleanup] target record: Name=%s Type=%s TTL=%d Value=%s", refRecord.Name, refRecord.Type, refRecord.TTL, refRecord.Value)

	existingRecord, err := c.findExistingRecord(apiClient, zoneName, refRecord)
	if err != nil {
		return err
	}

	if existingRecord == nil {
		c.logger.Printf("WARNING [cleanup]: asked to delete record %+v, but could not find one", refRecord)
		return nil
	}
	existingRecordZoneRecord := recordInfoToZoneRecord(existingRecord, zoneName)

	res, err := apiClient.ZoneService.UpdateZone(zone_service.NewUpdateZoneParams().WithName(zoneName).WithBody(
		&models.ZoneUpdateZoneRequest{
			Name: zoneName,
			Records: &models.ZoneRecordUpdates{
				Remove: []*models.ZoneRecord{
					&existingRecordZoneRecord,
				},
			},
		},
	), nil)

	if err != nil {
		c.logger.Printf("[cleanup] UpdateZone error for %s: %v", zoneName, err)
		return err
	}

	if res != nil && res.Payload != nil && res.Payload.Data != nil {
		c.logger.Printf("[cleanup] UpdateZone OK for %s", zoneName)
	}

	return nil
}

// Initialize will be called when the webhook first starts.
func (c *openproviderDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	c.logger = logger.StandardLogger{}

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (*openproviderDNSProviderConfig, error) {
	var defaultTtl int32 = 900

	cfg := openproviderDNSProviderConfig{}
	cfg.Ttl = defaultTtl
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return &cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return &cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	if cfg.Ttl == 0 {
		cfg.Ttl = defaultTtl
	}

	var minTtl int32 = 600
	if cfg.Ttl < minTtl {
		fmt.Printf("WARNING: configured TTL %v is less than the Openprovider minimum of 600 seconds. "+
			"The TTL will be set to %v", cfg.Ttl, minTtl)
		cfg.Ttl = minTtl
	}

	return &cfg, nil
}

func ensureCacheDir() {
	if len(CacheDir) == 0 {
		CacheDir = "/var/cache/cert-manager-webhook-openprovider"
	}
}

func (c *openproviderDNSProviderSolver) loadAuthTokenCache() *authTokenCache {
	ensureCacheDir()

	nilAuthTokenCache := &authTokenCache{
		Token:   "",
		Expires: 0,
	}

	cachePath := CacheDir + "/auth-token"
	data, err := os.ReadFile(cachePath)

	tokenCache := new(authTokenCache)
	if err == nil {
		err = json.Unmarshal(data, tokenCache)
	}

	if err != nil {
		c.logger.Printf("WARNING: Could not read cached auth token at %v (%v), will need to authenticate",
			cachePath, err,
		)
		return nilAuthTokenCache
	}

	return tokenCache
}

func (c *openproviderDNSProviderSolver) storeAuthTokenCache(tokenCache *authTokenCache) {
	ensureCacheDir()

	bytes, err := json.Marshal(tokenCache)

	cachePath := CacheDir + "/auth-token"
	if err == nil {
		err = os.WriteFile(cachePath, bytes, 0600)
	}

	if err != nil {
		c.logger.Printf("WARNING: Could not store cached auth token at %v (%v)", cachePath, err)
		return
	}

	c.logger.Printf("Cached authentication token at %v", cachePath)
}

func extractRecordName(fqdn, domain string) string {
	if idx := strings.Index(fqdn, "."+domain); idx != -1 {
		return fqdn[:idx]
	}
	return util.UnFqdn(fqdn)
}

func getZone(resolvedZone string) string {
	return strings.ToLower(strings.Trim(resolvedZone, "."))
}
