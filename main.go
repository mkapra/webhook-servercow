package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"net/http"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&customDNSProviderSolver{},
	)
}

type customDNSProviderSolver struct {
	client *kubernetes.Clientset
}

type customDNSProviderConfig struct {
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.
	UserPasswordSecretRef string `json:"secretRef"`
	NamespaceRef          string `json:"secretNamespace"`
}

func (c *customDNSProviderSolver) Name() string {
	return "servercow"
}

func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	userName, userPassword, err := c.getConfig(&cfg, ch)
	if err != nil {
		return fmt.Errorf("Could not retrieve username and password from secret: %v", err)
	}

	rePattern := regexp.MustCompile(`^(.+)\.(([^\.]+)\.([^\.]+))\.$`)
	match := rePattern.FindStringSubmatch(ch.ResolvedFQDN)
	if match == nil {
		return fmt.Errorf("unable to parse host/domain out of resolved FQDN ('%s')", ch.ResolvedFQDN)
	}
	host := match[1]
	domain := match[2]

	url := fmt.Sprintf("https://api.servercow.de/dns/v1/domains/%s", domain)
	payload := map[string]interface{}{
		"type":    "TXT",
		"name":    host,
		"content": ch.Key,
		"ttl":     20,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		panic(err)
	}

	req.Header.Set("X-Auth-Username", userName)
	req.Header.Set("X-Auth-Password", userPassword)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	return nil
}

func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	userName, userPassword, err := c.getConfig(&cfg, ch)
	if err != nil {
		return fmt.Errorf("Could not retrieve username and password from secret: %v", err)
	}

	rePattern := regexp.MustCompile(`^(.+)\.(([^\.]+)\.([^\.]+))\.$`)
	match := rePattern.FindStringSubmatch(ch.ResolvedFQDN)
	if match == nil {
		return fmt.Errorf("unable to parse host/domain out of resolved FQDN ('%s')", ch.ResolvedFQDN)
	}
	host := match[1]
	domain := match[2]

	url := fmt.Sprintf("https://api.servercow.de/dns/v1/domains/%v", domain)
	payload := map[string]interface{}{
		"type": "TXT",
		"name": host,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("DELETE", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		panic(err)
	}

	req.Header.Set("X-Auth-Username", userName)
	req.Header.Set("X-Auth-Password", userPassword)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	return nil
}

// Initialize will be called when the webhook first starts.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func stringFromSecretData(secretData *map[string][]byte, key string) (string, error) {
	data, ok := (*secretData)[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret data", key)
	}
	return string(data), nil
}

func (n *customDNSProviderSolver) getConfig(cfg *customDNSProviderConfig, ch *v1alpha1.ChallengeRequest) (string, string, error) {
	var secretNs string
	if cfg.NamespaceRef != "" {
		secretNs = cfg.NamespaceRef
	} else {
		secretNs = ch.ResourceNamespace
	}

	secret, err := n.client.CoreV1().Secrets(secretNs).Get(context.TODO(), cfg.UserPasswordSecretRef, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("unable to get secret %s/%s': %v", secretNs, cfg.UserPasswordSecretRef, err)
	}

	userName, err := stringFromSecretData(&secret.Data, "username")
	if err != nil {
		return "", "", fmt.Errorf("unable to get username for user from secret: %v", err)
	}

	userPassword, err := stringFromSecretData(&secret.Data, "password")
	if err != nil {
		return "", "", fmt.Errorf("unable to get password for user from secret: %v", err)
	}

	return userName, userPassword, nil
}
