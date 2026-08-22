package client

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"

	"github.com/kayrus/gof5/pkg/config"

	"github.com/howeyc/gopass"
	"github.com/manifoldco/promptui"
	"github.com/mitchellh/go-homedir"
)

const (
	userAgent        = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1a2pre) Gecko/2008073000 Shredder/3.0a2pre ThunderBrowse/3.2.1.8"
	androidUserAgent = "Mozilla/5.0 (Linux; Android 10; SM-G975F Build/QP1A.190711.020) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.138 Mobile Safari/537.36 EdgeClient/3.0.7 F5Access/3.0.7"
	edgeUserAgent    = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko EdgeClient/7262.2025.1203.0525"
	defaultHostname  = "test"
)

func tlsConfig(opts *Options, insecure bool) (*tls.Config, error) {
	config := &tls.Config{
		InsecureSkipVerify: insecure,
		Renegotiation:      opts.Renegotiation,
	}

	if opts.CACert != "" {
		caCert, err := readFile(opts.CACert)
		if err != nil {
			return nil, err
		}
		config.RootCAs = x509.NewCertPool()
		config.RootCAs.AppendCertsFromPEM(caCert)
	}

	if opts.Cert != "" && opts.Key != "" {
		crt, err := readFile(opts.Cert)
		if err != nil {
			return nil, err
		}
		key, err := readFile(opts.Key)
		if err != nil {
			return nil, err
		}

		cert, err := tls.X509KeyPair(crt, key)
		if err != nil {
			return nil, err
		}

		config.Certificates = []tls.Certificate{cert}
	}

	return config, nil
}

func readFile(path string) ([]byte, error) {
	if len(path) == 0 {
		return nil, nil
	}

	if path[0] == '~' {
		var err error
		path, err = homedir.Expand(path)
		if err != nil {
			return nil, err
		}
	}

	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return bytes.TrimSpace(content), nil
}

func checkRedirect(c *http.Client) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if req.URL.Path == "/my.logout.php3" || req.URL.Path == "/vdesk/hangup.php3" || req.URL.Query().Get("errorcode") != "" {
			// clear cookies
			var err error
			c.Jar, err = cookiejar.New(nil)
			if err != nil {
				return fmt.Errorf("failed to create cookie jar: %s", err)
			}
			return http.ErrUseLastResponse
		}
		return nil
	}
}

// 64-byte HMAC key
var hmacKey, _ = hex.DecodeString(
	"4342a2ee5e546d98bd24e014218c8b8d" +
		"c18531bd538c4694b720043435367edb" +
		"f5dd67a9f6da42b58d28b27710c39b1a" +
		"b4cb386acdae4e08bd328d8a45b0b082",
)

func generateClientDataFromInfo(info config.AgentInfo, sessionToken string) (string, error) {
	data, err := xml.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("failed to marshal agent info: %w", err)
	}
	values := &bytes.Buffer{}
	values.WriteString("session=&")
	values.WriteString("device_info=" + base64.StdEncoding.EncodeToString(data) + "&")
	values.WriteString("agent_result=&")
	values.WriteString("token=" + sessionToken)

	// HMAC-MD5 with the 64-byte key
	h := hmac.New(md5.New, hmacKey)
	_, err = h.Write(values.Bytes())
	if err != nil {
		return "", err
	}
	sig := base64.StdEncoding.EncodeToString(h.Sum(nil))

	values.WriteString("&signature=" + sig)

	return base64.StdEncoding.EncodeToString(values.Bytes()), nil
}

func generateClientData(cData config.ClientData) (string, error) {
	info := config.AgentInfo{
		Type:       "standalone",
		Version:    "2.0",
		Platform:   "Linux",
		CPU:        "x64",
		LandingURI: "/",
		Hostname:   defaultHostname,
	}

	return generateClientDataFromInfo(info, cData.Token)
}

func generateEdgeClientData(sessionToken string) (string, error) {
	info := config.AgentInfo{
		Type:       "standalone",
		Version:    "2.0",
		Platform:   "Win11",
		CPU:        "wow64",
		JavaScript: true,
		ActiveX:    true,
		Plugin:     false,
		LandingURI: "/",
		LockedMode: false,
		Hostname:   defaultHostname,
		AppID:      "edge",
	}
	return generateClientDataFromInfo(info, sessionToken)
}

func loginSignature(c *http.Client, server string, _, _ *string) error {
	log.Printf("Logging in...")
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/my.logon.php3?outform=xml&client_version=2.0&get_token=1", server), nil)
	if err != nil {
		return err
	}
	req.Proto = "HTTP/1.0"
	req.Header.Set("User-Agent", androidUserAgent)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	var cData config.ClientData
	dec := xml.NewDecoder(resp.Body)
	err = dec.Decode(&cData)
	resp.Body.Close()
	if err != nil {
		return err
	}

	clientData, err := generateClientData(cData)
	if err != nil {
		return err
	}

	req, err = http.NewRequest("POST", fmt.Sprintf("https://%s%s", server, cData.RedirectURL), strings.NewReader("client_data="+clientData))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", androidUserAgent)
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Origin", "null")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "com.f5.edge.client_ics")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US;q=0.9,en;q=0.8")

	resp, err = c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 {
		return fmt.Errorf("login failed")
	}

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func login(c *http.Client, server string, username, password *string) error {
	if *username == "" {
		fmt.Print("Enter VPN username: ")
		fmt.Scanln(username)
	}
	if *password == "" {
		fmt.Print("Enter VPN password: ")
		v, err := gopass.GetPasswd()
		if err != nil {
			return fmt.Errorf("failed to read password: %s", err)
		}
		*password = string(v)
	}

	log.Printf("Logging in...")
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s", server), nil)
	if err != nil {
		return err
	}
	req.Proto = "HTTP/1.0"
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	data := url.Values{}
	data.Set("username", *username)
	data.Add("password", *password)
	data.Add("vhost", "standard")
	req, err = http.NewRequest("POST", fmt.Sprintf("https://%s/my.policy?outform=xml", server), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Referer", fmt.Sprintf("https://%s/my.policy", server))
	req.Header.Set("User-Agent", userAgent)
	resp, err = c.Do(req)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	/*
		if resp.StatusCode == 302 && resp.Header.Get("Location") == "/my.policy" {
			return nil
		}
	*/

	// TODO: parse response 302 location and error code
	if resp.StatusCode == 302 || bytes.Contains(body, []byte("Session Expired/Timeout")) || bytes.Contains(body, []byte("The username or password is not correct")) {
		return fmt.Errorf("wrong credentials")
	}

	return nil
}

func parseProfile(reader io.ReadCloser, profileIndex int, profileName string) (string, error) {
	var profiles config.Profiles
	dec := xml.NewDecoder(reader)
	err := dec.Decode(&profiles)
	reader.Close()
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal a response: %s", err)
	}

	if profiles.Type == "VPN" {
		prfls := make([]string, len(profiles.Favorites))
		for i, p := range profiles.Favorites {
			if profileName != "" && profileName == p.Name {
				profileIndex = i
			}
			prfls[i] = fmt.Sprintf("%d:%s", i, p.Name)
		}
		log.Printf("Found F5 VPN profiles: %q", prfls)

		if profileIndex >= len(profiles.Favorites) {
			return "", fmt.Errorf("profile %q index is out of range", profileIndex)
		}
		log.Printf("Using %q F5 VPN profile", profiles.Favorites[profileIndex].Name)
		return profiles.Favorites[profileIndex].Params, nil
	}

	return "", fmt.Errorf("VPN profile was not found")
}

func getProfiles(c *http.Client, server string) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/vdesk/vpn/index.php3?outform=xml&client_version=2.0", server), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build a request: %s", err)
	}
	req.Header.Set("User-Agent", userAgent)
	return c.Do(req)
}

func getConnectionOptions(c *http.Client, opts *Options, profile string) (*config.Favorite, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/vdesk/vpn/connect.php3?%s&outform=xml&client_version=2.0", opts.Server, profile), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build a request: %s", err)
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("Failed to read a request: %s", err)
		log.Printf("Override link DNS values from config")
		return &config.Favorite{
			Object: config.Object{
				SessionID: opts.SessionID,
				DNS:       opts.Config.OverrideDNS,
				DNSSuffix: opts.Config.OverrideDNSSuffix,
			},
		}, nil
	}

	// parse profile
	var favorite config.Favorite
	dec := xml.NewDecoder(resp.Body)
	err = dec.Decode(&favorite)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal a response: %s", err)
	}

	// override link options
	if favorite.Object.SessionID == "" {
		favorite.Object.SessionID = opts.SessionID
	}
	if len(opts.Config.OverrideDNS) > 0 {
		favorite.Object.DNS = opts.Config.OverrideDNS
	}
	if len(opts.Config.OverrideDNSSuffix) > 0 {
		favorite.Object.DNSSuffix = opts.Config.OverrideDNSSuffix
	}

	return &favorite, nil
}

func closeVPNSession(c *http.Client, server string) {
	// close session
	r, err := http.NewRequest("GET", fmt.Sprintf("https://%s/vdesk/hangup.php3?hangup_error=1", server), nil)
	if err != nil {
		log.Printf("Failed to create a request to close the VPN session %s", err)
	}
	resp, err := c.Do(r)
	if err != nil {
		log.Printf("Failed to close the VPN session %s", err)
	}
	defer resp.Body.Close()
}

func getServersList(c *http.Client, server string) (*url.URL, error) {
	r, err := http.NewRequest("GET", fmt.Sprintf("https://%s/pre/config.php", server), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create a request to get servers list: %s", err)
	}
	resp, err := c.Do(r)
	if err != nil {
		return nil, fmt.Errorf("failed to request servers list: %s", err)
	}

	var s config.PreConfigProfile
	dec := xml.NewDecoder(resp.Body)
	err = dec.Decode(&s)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal servers list: %s", err)
	}

	prompt := promptui.Select{
		Label: "Select Server",
		Items: s.Servers,
	}

	i, _, err := prompt.Run()
	if err != nil {
		return nil, fmt.Errorf("prompt failed: %s", err)
	}

	u, err := url.Parse(s.Servers[i].Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server hostname: %s", err)
	}

	// if scheme is not set, assume https
	if u.Scheme == "" {
		u, err = url.Parse("https://" + s.Servers[i].Address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse server hostname: %s", err)
		}
	}

	return u, nil
}

func getOAuthRequestURL(c *http.Client, server string, redirectURI string) (*url.URL, *config.OAuth2, error) {
	r, err := http.NewRequest("GET", fmt.Sprintf("https://%s/pre/config.php?version=2.0", server), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create a request to get oauth configuration: %w", err)
	}
	resp, err := c.Do(r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to request oauth configuration: %w", err)
	}
	defer resp.Body.Close()

	var s config.PreConfigProfile
	dec := xml.NewDecoder(resp.Body)
	err = dec.Decode(&s)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal oauth configuration: %w", err)
	}

	u, err := url.Parse(s.OAuth2.AuthorizationEndpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse authorization endpoint: %w", err)
	}

	q := make(url.Values)
	q.Set("client_id", s.OAuth2.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", s.OAuth2.Scopes)
	u.RawQuery = q.Encode()

	return u, &s.OAuth2, nil
}

func exchangeOAuthCodeForToken(c *http.Client, oAuth2Config *config.OAuth2, redirectURI string, code string) (*config.OAuthTokenResponse, error) {
	form := make(url.Values)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", oAuth2Config.ClientID)

	req, err := http.NewRequest(http.MethodPost, oAuth2Config.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request oauth token endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var token config.OAuthTokenResponse
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to parse token response (parseTokenResponse): %w", err)
	}
	if token.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token (\"Failed to obtain authorization token\")")
	}
	return &token, nil
}

func exchangeBearerForF5Token(c *http.Client, server string, accessToken string) (*config.Session, error) {
	logonURL := fmt.Sprintf("https://%s/my.logon.php3?outform=xml&get_token=1&client_version=2.0", server)

	req, err := http.NewRequest(http.MethodGet, logonURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-AU")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("User-Agent", edgeUserAgent)
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange oauth access_token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var lr *config.Session
	decoder := xml.NewDecoder(resp.Body)
	if err := decoder.Decode(&lr); err != nil {
		return nil, fmt.Errorf("failed to parse logon response XML: %w", err)
	}

	if lr.Token == "" {
		return nil, fmt.Errorf("logon response missing <token>: %v", *lr)
	}

	return lr, nil
}

func submitOAuthPolicy(c *http.Client, server string, session *config.Session) error {
	edgeClientData, err := generateEdgeClientData(session.Token)
	if err != nil {
		return fmt.Errorf("failed to generate client_data: %w", err)
	}

	form := make(url.Values)
	form.Set("client_data", edgeClientData)

	loginRedirectURL := session.RedirectURL
	if loginRedirectURL == "" {
		log.Printf("WARNING: logon response missing <redirect_url>, defaulting to /my.policy\n")
		loginRedirectURL = "my.policy"
	}

	policyURL := fmt.Sprintf("https://%s/%s", server, strings.TrimLeft(loginRedirectURL, "/"))
	req, err := http.NewRequest(http.MethodPost, policyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-AU")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("User-Agent", edgeUserAgent)
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to submit oauth policy: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func validateOAuthSession(c *http.Client, server string) error {
	sessionURL := fmt.Sprintf("https://%s/vdesk/sessioninfo?outform=xml", server)

	req, err := http.NewRequest(http.MethodGet, sessionURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-AU")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("User-Agent", edgeUserAgent)

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request oauth session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("validateOAuthSession: status %d", resp.StatusCode)
	}

	// TODO: Read the body out at some point, has inactiveTimeout, and maxSessionTimeout, etc
	return nil
}
