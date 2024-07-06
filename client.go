package boringproxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
  "os/exec"
	"net/http"
	"sync"
  "strings"
	"time"
  "io"

	"github.com/caddyserver/certmagic"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	httpClient       *http.Client
	tunnels          map[string]Tunnel
	previousEtag     string
	server           string
	token            string
	clientName       string
	user             string
	cancelFuncs      map[string]context.CancelFunc
	cancelFuncsMutex *sync.Mutex
	certConfig       *certmagic.Config
	behindProxy      bool
	pollInterval     int
  proxyCommand     string
}

type ClientConfig struct {
	ServerAddr     string `json:"serverAddr,omitempty"`
	Token          string `json:"token,omitempty"`
	ClientName     string `json:"clientName,omitempty"`
	User           string `json:"user,omitempty"`
	CertDir        string `json:"certDir,omitempty"`
	AcmeEmail      string `json:"acmeEmail,omitempty"`
	AcmeUseStaging bool   `json:"acmeUseStaging,omitempty"`
	AcmeCa         string `json:"acmeCa,omitempty"`
	DnsServer      string `json:"dnsServer,omitempty"`
	BehindProxy    bool   `json:"behindProxy,omitempty"`
	PollInterval   int    `json:"pollInterval,omitempty"`
	ProxyCommand   string `json:"proxyComman,omitempty"`
}

func NewClient(config *ClientConfig) (*Client, error) {

	if config.DnsServer != "" {
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, "udp", fmt.Sprintf("%s:53", config.DnsServer))
			},
		}
	}

	// Use random unprivileged port for ACME challenges. This is necessary
	// because of the way certmagic works, in that if it fails to bind
	// HTTPSPort (443 by default) and doesn't detect anything else binding
	// it, it fails. Obviously the boringproxy client is likely to be
	// running on a machine where 443 isn't bound, so we need a different
	// port to hack around this. See here for more details:
	// https://github.com/caddyserver/certmagic/issues/111
	var err error
	certmagic.HTTPSPort, err = randomOpenPort()
	if err != nil {
		return nil, errors.New("Failed get random port for TLS challenges")
	}

	certmagic.DefaultACME.DisableHTTPChallenge = true

	if config.CertDir != "" {
		certmagic.Default.Storage = &certmagic.FileStorage{config.CertDir}
	}

	if config.AcmeEmail != "" {
		certmagic.DefaultACME.Email = config.AcmeEmail
	}

	if config.AcmeUseStaging {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	}

	if config.AcmeCa != "" {
		certmagic.DefaultACME.CA = config.AcmeCa
	}

	certConfig := certmagic.NewDefault()

	httpClient := &http.Client{
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	tunnels := make(map[string]Tunnel)
	cancelFuncs := make(map[string]context.CancelFunc)
	cancelFuncsMutex := &sync.Mutex{}

	return &Client{
		httpClient:       httpClient,
		tunnels:          tunnels,
		previousEtag:     "",
		server:           config.ServerAddr,
		token:            config.Token,
		clientName:       config.ClientName,
		user:             config.User,
		cancelFuncs:      cancelFuncs,
		cancelFuncsMutex: cancelFuncsMutex,
		certConfig:       certConfig,
		behindProxy:      config.BehindProxy,
		pollInterval:     config.PollInterval,
		proxyCommand:     config.ProxyCommand,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {

	url := fmt.Sprintf("https://%s/api/clients/?client-name=%s", c.server, c.clientName)
	if c.user != "" {
		url = url + "&user=" + c.user
	}

	clientReq, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("Failed to create request for URL %s", url)
	}
	if len(c.token) > 0 {
		clientReq.Header.Add("Authorization", "bearer "+c.token)
	}
	resp, err := c.httpClient.Do(clientReq)
	if err != nil {
		return fmt.Errorf("Failed to create client. Ensure the server is running. URL: %s", url)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("Failed to create client. HTTP Status code: %d. Failed to read body", resp.StatusCode)
		}

		msg := string(body)
		return fmt.Errorf("Failed to create client. Are the user ('%s') and token correct? HTTP Status code: %d. Message: %s", c.user, resp.StatusCode, msg)
	}

	pollChan := make(chan struct{})

	// A polling interval of 0 disables polling. Basically pollChan will
	// remain blocked and never trigger in the select below.
	if c.pollInterval > 0 {
		go func() {
			for {
				<-time.After(time.Duration(c.pollInterval) * time.Millisecond)
				pollChan <- struct{}{}
			}
		}()
	}

	for {
		err := c.PollTunnels(ctx)
		if err != nil {
			log.Print(err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-pollChan:
			// continue
		}
	}
}

func (c *Client) PollTunnels(ctx context.Context) error {

	//log.Println("PollTunnels")

	url := fmt.Sprintf("https://%s/api/tunnels?client-name=%s", c.server, c.clientName)

	listenReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	if len(c.token) > 0 {
		listenReq.Header.Add("Authorization", "bearer "+c.token)
	}

	resp, err := c.httpClient.Do(listenReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New("Failed to listen (not 200 status)")
	}

	etag := resp.Header["Etag"][0]

	if etag != c.previousEtag {

		body, err := ioutil.ReadAll(resp.Body)

		tunnels := make(map[string]Tunnel)

		err = json.Unmarshal(body, &tunnels)
		if err != nil {
			return err
		}

		c.SyncTunnels(ctx, tunnels)

		c.previousEtag = etag
	}

	return nil
}

func (c *Client) SyncTunnels(ctx context.Context, serverTunnels map[string]Tunnel) {
	log.Println("SyncTunnels")

	// update tunnels to match server
	for k, newTun := range serverTunnels {

		// assume tunnels exists and hasn't changed
		bore := false

		tun, exists := c.tunnels[k]
		if !exists {
			log.Println("New tunnel", k)
			c.tunnels[k] = newTun
			bore = true
		} else if newTun != tun {
			log.Println("Restart tunnel", k)
			c.cancelFuncsMutex.Lock()
			c.cancelFuncs[k]()
			c.cancelFuncsMutex.Unlock()
			bore = true
		}

		if bore {
			cancelCtx, cancel := context.WithCancel(ctx)

			c.cancelFuncsMutex.Lock()
			c.cancelFuncs[k] = cancel
			c.cancelFuncsMutex.Unlock()

			go func(closureCtx context.Context, tun Tunnel) {
				err := c.BoreTunnel(closureCtx, tun)
				if err != nil {
					log.Println("BoreTunnel error: ", err)
				}
			}(cancelCtx, newTun)
		}
	}

	// delete any tunnels that no longer exist on server
	for k, _ := range c.tunnels {
		_, exists := serverTunnels[k]
		if !exists {
			log.Println("Kill tunnel", k)
			c.cancelFuncsMutex.Lock()
			c.cancelFuncs[k]()
			c.cancelFuncsMutex.Unlock()

			delete(c.cancelFuncs, k)
			delete(c.tunnels, k)
		}
	}
}

func (c *Client) BoreTunnel(ctx context.Context, tunnel Tunnel) error {
    log.Println("BoreTunnel", tunnel.Domain)

    signer, err := ssh.ParsePrivateKey([]byte(tunnel.TunnelPrivateKey))
    if err != nil {
        return fmt.Errorf("Unable to parse private key: %v", err)
    }

    config := &ssh.ClientConfig{
        User: tunnel.Username,
        Auth: []ssh.AuthMethod{
            ssh.PublicKeys(signer),
        },
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    }

    sshHost := fmt.Sprintf("%s:%d", tunnel.ServerAddress, tunnel.ServerPort)

    var client *ssh.Client
    if c.proxyCommand == "" {
        // Use direct SSH connection
        client, err = ssh.Dial("tcp", sshHost, config)
        if err != nil {
            return fmt.Errorf("Failed to dial: %v", err)
        }
    } else {
      // Use SSH over proxy command
        tmpProxyCommand := strings.Replace(c.proxyCommand, "%h", tunnel.ServerAddress, -1)
        proxyCommand := strings.Replace(tmpProxyCommand, "%p", fmt.Sprintf("%d", tunnel.ServerPort), -1)

        cmd := exec.CommandContext(ctx, "sh", "-c", proxyCommand)
        stdin, err := cmd.StdinPipe()
        if err != nil {
            return fmt.Errorf("Failed to setup proxy command stdin: %v", err)
        }
        stdout, err := cmd.StdoutPipe()
        if err != nil {
            return fmt.Errorf("Failed to setup proxy command stdout: %v", err)
        }
        stderr, err := cmd.StderrPipe()
        if err != nil {
            return fmt.Errorf("Failed to setup proxy command stderr: %v", err)
        }
        err = cmd.Start()
        if err != nil {
            return fmt.Errorf("Failed to start proxy command: %v", err)
        }

        // Create a full-duplex pipe pair
        localConn, remoteConn := net.Pipe()
        defer localConn.Close()

        go func() {
            defer remoteConn.Close()
            io.Copy(remoteConn, stdout)
        }()
        go func() {
            defer remoteConn.Close()
            io.Copy(stdin, remoteConn)
        }()

        // Dial SSH over the proxy connection
        clientConn, chans, reqs, err := ssh.NewClientConn(localConn, sshHost, config)
        if err != nil {
            return fmt.Errorf("Failed to create SSH client connection: %v", err)
        }
        client = ssh.NewClient(clientConn, chans, reqs)

        // Reading stderr to check for errors
        go func() {
            errOutput, _ := ioutil.ReadAll(stderr)
            if len(errOutput) > 0 {
                log.Printf("Proxy command stderr: %s", errOutput)
            }
        }()
    }

    defer client.Close()

    bindAddr := "127.0.0.1"
    if tunnel.AllowExternalTcp {
        bindAddr = "0.0.0.0"
    }
    tunnelAddr := fmt.Sprintf("%s:%d", bindAddr, tunnel.TunnelPort)
    listener, err := client.Listen("tcp", tunnelAddr)
    if err != nil {
        return fmt.Errorf("Unable to register tcp forward for %s:%d %v", bindAddr, tunnel.TunnelPort, err)
    }
    defer listener.Close()

    if tunnel.TlsTermination == "client" {
        tlsConfig := &tls.Config{
            GetCertificate: c.certConfig.GetCertificate,
            NextProtos:     []string{"h2", "acme-tls/1"},
        }
        tlsListener := tls.NewListener(listener, tlsConfig)

        httpMux := http.NewServeMux()

        httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
            proxyRequest(w, r, tunnel, c.httpClient, tunnel.ClientAddress, tunnel.ClientPort, c.behindProxy)
        })

        httpServer := &http.Server{
            Handler: httpMux,
        }

        go httpServer.Serve(tlsListener)
    } else {
        go func() {
            for {
                conn, err := listener.Accept()
                if err != nil {
                    break
                }

                var useTls bool
                if tunnel.TlsTermination == "client-tls" {
                    useTls = true
                } else {
                    useTls = false
                }

                go ProxyTcp(conn, tunnel.ClientAddress, tunnel.ClientPort, useTls, c.certConfig)
            }
        }()
    }

    if tunnel.TlsTermination != "passthrough" {
        err = c.certConfig.ManageSync(ctx, []string{tunnel.Domain})
        if err != nil {
            log.Println("CertMagic error at startup")
            log.Println(err)
        }
    }

    <-ctx.Done()

    return nil
}

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}
