package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	groupToken     string
	groupTokenFile string
	nodeID         string
	nodeToken      *NodeToken  = &NodeToken{}
	sc             SecretCache = NewSecretCache()
)

var (
	rksBaseURL = "https://rks-server:8080"
	tr         = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // required in case the remote-key-server has a self signed certificate (Dev Env)
	}
	rksClient = &http.Client{Transport: tr}
)

// We redefine RKS structs here to avoid pulling all RKS dependencies by adding an import "github.com/Orange-OpenSource/remote-key-server/model"

// NodeToken Unique node specific token
type NodeToken struct {
	NodeToken string `json:"nodeToken,omitempty"`
	TTL       int    `json:"ttl,omitempty"`
}

// Secret represents a Certificate + Private Key pair + TTL
type Secret struct {
	Data SecretData `json:"data,omitempty" mapstructure:"data"`
}

// SecretData internal secret representation
type SecretData struct {
	Meta        SecretDataMeta `json:"meta,omitempty" mapstructure:"meta"`
	Certificate string         `json:"certificate,omitempty" mapstructure:"certificate"`
	PrivateKey  string         `json:"private_key,omitempty" mapstructure:"private_key"`
}

// SecretDataMeta internal secret metadata representation
type SecretDataMeta struct {
	TTL int32 `json:"ttl,omitempty" mapstructure:"ttl"`
}

// registerNode uses the register node endpoint on the RKS to get a node token
func registerNode() {
	req, err := http.NewRequest("POST", rksBaseURL+"/rks/v1/node", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("X-Vault-Token", groupToken)
	req.Header.Add("X-LCDN-nodeId", nodeID)

	resp, err := rksClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		log.Fatal(string(body), resp.StatusCode)
	}

	err = json.NewDecoder(resp.Body).Decode(nodeToken)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("registered node")
}

// renewNodeToken uses the renewNodeToken endpoint on the RKS to renew the node token
func renewNodeToken() error {
	req, err := http.NewRequest("POST", rksBaseURL+"/rks/v1/auth/token/renew-self", nil)
	if err != nil {
		return err
	}
	req.Header.Add("X-Vault-Token", nodeToken.NodeToken)

	resp, err := rksClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(nodeToken)
	if err != nil {
		return err
	}
	log.Println("renewed node token")

	return nil
}

// NodeTokenRenewer has to run in a goroutine
// it renews the node token periodically 10 seconds before it expires
func NodeTokenRenewer() {
	log.Println("start token renewer goroutine, renew node token every", nodeToken.TTL-10, "seconds")
	for {
		ticker := time.NewTicker(time.Duration(nodeToken.TTL-10) * time.Second)
		<-ticker.C
		err := renewNodeToken()
		if err != nil {
			log.Println(err)
		}
	}
}

// CachedSecret represents a local secret recovered from the remote key server
type CachedSecret struct {
	StoredTime time.Time
	TTL        time.Duration
	Secret     *tls.Certificate
}

// Expired indicates if a secret has been stored for longer than its TTL
func (c CachedSecret) Expired() bool {
	return time.Since(c.StoredTime) > c.TTL
}

// SecretCache stores secret associated with sni
type SecretCache struct {
	sync.Mutex
	Secrets map[string]CachedSecret
}

// NewSecretCache Initializes cache map
func NewSecretCache() SecretCache {
	return SecretCache{Secrets: make(map[string]CachedSecret, 100)}
}

// StaleEntriesRemover has to be started in a goroutine
// It removes expired secret entries from the cache every 10 seconds
func (sc *SecretCache) StaleEntriesRemover() {
	deletedEntries := 0
	log.Println("start stale cache entries remover")
	for {
		time.Sleep(time.Duration(10) * time.Second)
		sc.Lock()
		for key, secret := range sc.Secrets {
			if secret.Expired() {
				deletedEntries++
				delete(sc.Secrets, key)
			}
		}

		if deletedEntries != 0 {
			log.Println("stale entries remover: removed", deletedEntries, "expired secret entries")
		}
		deletedEntries = 0
		sc.Unlock()
	}
}

// fetchRKSSecret returns the secret corresponding to the given sni
// It first tries to get the secret from the cache
// If not found, it queries the RKS
func fetchRKSSecret(sni string) (*tls.Certificate, error) {
	sc.Lock()
	defer sc.Unlock()

	if cachedSecret, found := sc.Secrets[sni]; found {
		if cachedSecret.Expired() {
			log.Println("secret is in cache but expired, fetch from RKS")
		} else {
			log.Println(sni, "secret found in cache and still valid")
			return cachedSecret.Secret, nil
		}
	} else {
		log.Println("secret not found in cache, fetch from RKS")
	}

	r, err := http.NewRequest("GET", rksBaseURL+"/rks/v1/secret/"+sni, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Add("X-Vault-Token", nodeToken.NodeToken)

	resp, err := rksClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		// This can mean that the node has been revoked from the remote key server or that the node token expired
		// We should handle this error by trying again to registerNode
		return nil, errors.New("invalid node token")
	}

	// Fill RKS secret struct with RKS response body
	secret := Secret{}
	err = json.NewDecoder(resp.Body).Decode(&secret)
	if err != nil {
		return nil, err
	}

	// Create a tls.Certificate struct from cert and private key in PEM format
	certKeyPair, err := tls.X509KeyPair([]byte(secret.Data.Certificate), []byte(secret.Data.PrivateKey))
	if err != nil {
		return nil, err
	}
	log.Println("secret fetched from RKS and stored in cache for its TTL value of", secret.Data.Meta.TTL, "seconds")

	// Create secret entry in cache for further use
	sc.Secrets[sni] = CachedSecret{StoredTime: time.Now(), Secret: &certKeyPair, TTL: time.Second * time.Duration(secret.Data.Meta.TTL)}

	return &certKeyPair, nil
}

// GetCertificateCallback is the Standard go server callback function called on TLS Client Hello when SNI is sent by the client
// We use the sni to get the corresponding certificate/private key pair from the local cache or from the RKS
func GetCertificateCallback(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	log.Println("TLS client hello with sni:", clientHello.ServerName)
	return fetchRKSSecret(clientHello.ServerName)
}

// MyHandler answers Hello World to successful client requests
func MyHandler(w http.ResponseWriter, req *http.Request) {
	_, err := w.Write([]byte("Hello World"))
	if err != nil {
		log.Fatal(err)
	}
}

// start the client-node like this ./client-node <group_token> <node_id>
// Example: ./client-node s.JrZbFwDsd8Z5CESkF9f90uVV 1
func main() {
	flag.StringVar(&groupToken, "group-token", "", "group token for this node")
	flag.StringVar(&groupTokenFile, "group-token-file", "", "file containing group token for this node")
	flag.StringVar(&nodeID, "node-id", "1", "unique nodeID")

	flag.Parse()

	if groupToken == "" && groupTokenFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	if groupTokenFile != "" && groupToken == "" {
		if _, err := os.Stat(groupTokenFile); err == nil {
			// path/to/whatever exists
			groupTokenByte, err := ioutil.ReadFile(groupTokenFile)
			if err != nil {
				log.Fatal(err)
			}
			groupToken = string(groupTokenByte)
			groupToken = strings.TrimSuffix(groupToken, "\n")
		} else if os.IsNotExist(err) {
			log.Println("file not found")
			flag.Usage()
			os.Exit(1)
		} else {
			log.Fatal(err)
		}
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// We only get the node token at launch
	// A better implementation would try to register again in case of token expiration or revokation indicated by a 403 from the RKS
	registerNode()
	go NodeTokenRenewer()

	// Remove stale secret entries periodically
	go sc.StaleEntriesRemover()

	s := http.Server{Addr: ":8443"}
	s.TLSConfig = &tls.Config{}
	s.TLSConfig.GetCertificate = GetCertificateCallback
	s.Handler = http.HandlerFunc(MyHandler)
	// We need to load fake certificate / private key to start the TLS server
	if err := s.ListenAndServeTLS("./fake.com.crt", "./fake.com.key"); err != nil {
		log.Fatal(err)
	}
}
