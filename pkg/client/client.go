package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/kayrus/gof5/pkg/config"
	"github.com/kayrus/gof5/pkg/cookie"
	"github.com/kayrus/gof5/pkg/link"
)

type Options struct {
	config.Config
	Server        string
	Username      string
	Password      string
	SessionID     string
	CACert        string
	Cert          string
	Key           string
	CloseSession  bool
	Debug         bool
	Sel           bool
	Version       bool
	ProfileIndex  int
	ProfileName   string
	Renegotiation tls.RenegotiationSupport
}

var errRetryConnection = errors.New("retryable connection error")

func UrlHandlerF5Vpn(opts *Options, s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}

	if u.Scheme != "f5-vpn" {
		return fmt.Errorf("invalid scheme %v expected f5-vpn", u.Scheme)
	}

	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return err
	}

	resourceTypes := m["resourcetype"]
	resourceNames := m["resourcename"]
	if len(resourceTypes) == len(resourceNames) {
		for i := range resourceTypes {
			if resourceTypes[i] == "network_access" {
				opts.ProfileName = resourceNames[i]
				break
			}
		}
	}

	opts.Server = m["server"][0]
	tokenUrl := fmt.Sprintf("%s://%s:%s/vdesk/get_sessid_for_token.php3", m["protocol"][0], opts.Server, m["port"][0])
	request, err := http.NewRequest(http.MethodGet, tokenUrl, nil)
	if err != nil {
		return err
	}
	otc := m["otc"]
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("X-Access-Session-Token", otc[len(otc)-1])

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}

	opts.SessionID = response.Header.Get("X-Access-Session-ID")
	return nil
}

func Connect(opts *Options) error {
	if opts.Server == "" {
		fmt.Print("Enter server address: ")
		fmt.Scanln(&opts.Server)
	}

	u, err := url.Parse(opts.Server)
	if err != nil {
		return fmt.Errorf("failed to parse server hostname: %s", err)
	}
	if u.Scheme != "https" {
		u, err = url.Parse(fmt.Sprintf("https://%s", u.Host))
		if err != nil {
			return fmt.Errorf("failed to parse server hostname: %s", err)
		}
	}
	if u.Host == "" {
		u, err = url.Parse(fmt.Sprintf("https://%s", opts.Server))
		if err != nil {
			return fmt.Errorf("failed to parse server hostname: %s", err)
		}
		if u.Host == "" {
			return fmt.Errorf("failed to parse server hostname: %s", err)
		}
	}
	opts.Server = u.Host

	// read config
	cfg, err := config.ReadConfig(opts.Debug)
	if err != nil {
		return err
	}
	opts.Config = *cfg

	switch cfg.Renegotiation {
	case "RenegotiateOnceAsClient":
		opts.Renegotiation = tls.RenegotiateOnceAsClient
	case "RenegotiateFreelyAsClient":
		opts.Renegotiation = tls.RenegotiateFreelyAsClient
	case "RenegotiateNever", "":
		opts.Renegotiation = tls.RenegotiateNever
	default:
		return fmt.Errorf("unknown renegotiation value: '%s'", cfg.Renegotiation)
	}

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to create cookie jar: %s", err)
	}

	client := &http.Client{Jar: cookieJar}
	client.CheckRedirect = checkRedirect(client)

	tlsConf, err := tlsConfig(opts, cfg.InsecureTLS)
	if err != nil {
		return fmt.Errorf("failed to build TLS config: %v", err)
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConf,
	}
	if opts.Debug {
		client.Transport = &RoundTripper{
			Rt:     transport,
			Logger: &logger{},
		}
	} else {
		client.Transport = transport
	}

	// when server select list has been chosen
	if opts.Sel {
		u, err = getServersList(client, opts.Server)
		if err != nil {
			return err
		}
		opts.Server = u.Host
	}

	// read cookies
	cookie.ReadCookies(client, u, cfg, opts.SessionID)

	if len(client.Jar.Cookies(u)) == 0 {
		// need to login
		if err := login(client, opts.Server, &opts.Username, &opts.Password); err != nil {
			return fmt.Errorf("failed to login: %s", err)
		}
	} else {
		log.Printf("Reusing saved HTTPS VPN session for %s", u.Host)
	}

	resp, err := getProfiles(client, opts.Server)
	if err != nil {
		return fmt.Errorf("failed to get VPN profiles: %s", err)
	}

	if resp.StatusCode == 302 {
		// need to relogin
		_, err = io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %s", err)
		}
		resp.Body.Close()

		if err := login(client, opts.Server, &opts.Username, &opts.Password); err != nil {
			return fmt.Errorf("failed to login: %s", err)
		}

		// new request
		resp, err = getProfiles(client, opts.Server)
		if err != nil {
			return fmt.Errorf("failed to get VPN profiles: %s", err)
		}
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("wrong response code on profiles get: %d", resp.StatusCode)
	}

	profile, err := parseProfile(resp.Body, opts.ProfileIndex, opts.ProfileName)
	if err != nil {
		return fmt.Errorf("failed to parse VPN profiles: %s", err)
	}

	// read config, returned by F5
	cfg.F5Config, err = getConnectionOptions(client, opts, profile)
	if err != nil {
		return fmt.Errorf("failed to get VPN connection options: %s", err)
	}

	// save cookies
	if err := cookie.SaveCookies(client, u, cfg); err != nil {
		return fmt.Errorf("failed to save cookies: %s", err)
	}

	// close HTTPS VPN session
	// next VPN connection will require credentials to auth
	if opts.CloseSession {
		defer closeVPNSession(client, opts.Server)
	}

	retryAttempt := 0
	lastAttempt := time.Now()
	for {
		err = createVPNTunnel(ctx, opts, cfg, tlsConf)
		if err != nil && !errors.Is(err, errRetryConnection) {
			return err
		}

		failureTime := time.Now()
		// Reset failure counter if the connection lasted at least 2 minutes
		if failureTime.Sub(lastAttempt).Abs() >= 2*time.Minute {
			retryAttempt = 0
		}

		retryAttempt++
		if cfg.MaxRetries >= 0 && retryAttempt > cfg.MaxRetries {
			return fmt.Errorf("exceeded maximum connection retry attempts (%d): %w", cfg.MaxRetries, err)
		}

		lastAttempt = failureTime

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
		}

		log.Print("Connection failure occurred, attempting to reconnect")
	}
}

func createVPNTunnel(ctx context.Context, opts *Options, cfg *config.Config, tlsConf *tls.Config) error {
	// TLS
	l, err := link.InitConnection(opts.Server, cfg, tlsConf)
	if err != nil {
		return err
	}
	defer l.HTTPConn.Close()

	cmd := link.Cmd(cfg)

	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGPIPE, syscall.SIGHUP)

	// set routes and DNS after the PPP/TUN is up
	go l.WaitAndConfig(cfg)

	// 1. stop ppp/pppd child at the very end
	defer l.StopPPPDChild(cmd)
	// 0. restore the config first
	defer l.RestoreConfig(cfg)

	if cfg.Driver == "pppd" {
		if runtime.GOOS == "freebsd" {
			// ppp log parser
			go l.PppLogParser()
		} else {
			/*
				// read file descriptor 3
				stderr, w, err := os.Pipe()
				cmd.ExtraFiles = []*os.File{w}
			*/
			stderr, err := cmd.StderrPipe()
			if err != nil {
				return fmt.Errorf("cannot allocate stderr pipe: %s", err)
			}
			// pppd log parser
			go l.PppdLogParser(stderr)
		}

		stdin, err := cmd.StdinPipe()
		if err != nil {
			return fmt.Errorf("cannot allocate stdin pipe: %s", err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("cannot allocate stdout pipe: %s", err)
		}

		err = cmd.Start()
		if err != nil {
			return fmt.Errorf("failed to start pppd: %s", err)
		}

		// catch ppp/pppd child termination
		go l.CatchPPPDTermination(cmd)

		// pppd http->tun go routine
		go l.PppdHTTPToTun(stdin)

		// pppd tun->http go routine
		go l.PppdTunToHTTP(stdout)
	} else {
		// http->tun go routine
		go l.HttpToTun()

		// tun->http go routine
		go l.TunToHTTP()

		// notify tun readers and writes to stop
		defer close(l.TunDown)
	}

	select {
	case sig := <-termChan:
		// Consider sigpipe to be a retryable error
		if sig == syscall.SIGPIPE {
			return fmt.Errorf("received broken pipe signal: %w", errRetryConnection)
		}
		return fmt.Errorf("received %s signal", sig)
		// Some os signal received
	case err = <-l.ErrChan:
		// error received
	case err = <-l.PppdErrChan:
	// ppp/pppd child error received
	case <-ctx.Done():
		err = ctx.Err()
	}

	return err
}
