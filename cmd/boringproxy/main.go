package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/boringproxy/boringproxy"
)

const usage = `Usage: %s [command] [flags]

Commands:
    version      Prints version information.
    server       Start a new server.
    client       Connect to a server.
    tuntls       Tunnel a raw TLS connection.

Use "%[1]s command -h" for a list of flags for the command.
`

var Version string

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, os.Args[0]+": Need a command")
		fmt.Printf(usage, os.Args[0])
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "version":
		fmt.Println(Version)
	case "help", "-h", "--help", "-help":
		fmt.Printf(usage, os.Args[0])
	case "tuntls":
		// This command is a direct port of https://github.com/anderspitman/tuntls
		flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		server := flagSet.String("server", "", "boringproxy server")
		port := flagSet.Int("port", 0, "Local port to bind to")
		err := flagSet.Parse(os.Args[2:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: parsing flags: %s\n", os.Args[0], err)
			os.Exit(1)
		}

		if *server == "" {
			fmt.Fprintf(os.Stderr, "server argument is required\n")
			os.Exit(1)
		}

		if *port == 0 {
			// one-time tunnel over stdin/stdout
			doTlsTunnel(*server, os.Stdin, os.Stdout)
		} else {
			// listen on a port and create tunnels for each connection
			fmt.Fprintf(os.Stderr, "Listening on port %d\n", *port)
			listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
			if err != nil {
				fmt.Fprintf(os.Stderr, err.Error())
				os.Exit(1)
			}

			for {
				conn, err := listener.Accept()
				if err != nil {
					fmt.Fprintf(os.Stderr, err.Error())
					os.Exit(1)
				}

				go doTlsTunnel(*server, conn, conn)
			}
		}
	case "server":
		boringproxy.Listen()
	case "client":
		flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		server := flagSet.String("server", "", "boringproxy server")
		token := flagSet.String("token", "", "Access token")
		name := flagSet.String("client-name", "", "Client name")
		user := flagSet.String("user", "", "user")
		certDir := flagSet.String("cert-dir", "", "TLS cert directory")
		acmeEmail := flagSet.String("acme-email", "", "Email for ACME (ie Let's Encrypt)")
		acmeUseStaging := flagSet.Bool("acme-use-staging", false, "Use ACME (ie Let's Encrypt) staging servers")
		acmeCa := flagSet.String("acme-certificate-authority", "", "URI for ACME Certificate Authority")
		dnsServer := flagSet.String("dns-server", "", "Custom DNS server")
		behindProxy := flagSet.Bool("behind-proxy", false, "Whether we're running behind another reverse proxy")
		pollInterval := flagSet.Int("poll-interval-ms", 2000, "Interval in milliseconds to poll for tunnel changes")
		proxyCommand := flagSet.String("proxy-command", "", "ProxyCommand to use for outgoing connectin")

		err := flagSet.Parse(os.Args[2:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: parsing flags: %s\n", os.Args[0], err)
		}

		if *server == "" {
			fail("-server is required")
		}

		if *token == "" {
			fail("-token is required")
		}

		minPollInterval := 100
		if *pollInterval != 0 && *pollInterval < minPollInterval {
			fail(fmt.Sprintf("-poll-interval-ms must be at least %d, or 0 to disable polling", minPollInterval))
		}

		config := &boringproxy.ClientConfig{
			ServerAddr:     *server,
			Token:          *token,
			ClientName:     *name,
			User:           *user,
			CertDir:        *certDir,
			AcmeEmail:      *acmeEmail,
			AcmeUseStaging: *acmeUseStaging,
			AcmeCa:         *acmeCa,
			DnsServer:      *dnsServer,
			BehindProxy:    *behindProxy,
			PollInterval:   *pollInterval,
			ProxyCommand:   *proxyCommand,
		}

		ctx := context.Background()

		client, err := boringproxy.NewClient(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			os.Exit(1)
		}

		err = client.Run(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			os.Exit(1)
		}

	default:
		fail(os.Args[0] + ": Invalid command " + command)
	}
}

func doTlsTunnel(server string, in io.Reader, out io.Writer) {
	fmt.Fprintf(os.Stderr, "tuntls connecting to server: %s\n", server)

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", server), &tls.Config{
		//RootCAs: roots,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect: "+err.Error())
		os.Exit(1)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(conn, in)
		wg.Done()
	}()

	go func() {
		io.Copy(out, conn)
		wg.Done()
	}()

	wg.Wait()

	conn.Close()
}
