package oauth

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"
)

func createLocalAuthListener(ctx context.Context, listenAddress string, chanAuthorizationCode chan<- string, chanError chan<- error) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing authorization_code", http.StatusBadRequest)
			return
		}
		_, err := fmt.Fprintln(w, "Authentication complete. You may close this window.")
		if err != nil {
			return
		}
		chanAuthorizationCode <- code
	})

	srv := &http.Server{
		Addr:    listenAddress,
		Handler: mux,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, err
	}
	log.Printf("OAuth response http server listening on: %s\n", listenAddress)

	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			chanError <- err
		}
	}()

	return srv, nil
}

func StartOAuthFlow(ctx context.Context, listenAddress string, authURL string, autoOpenBrowser bool) (string, error) {
	chanAuthorizationCode := make(chan string, 1)
	defer close(chanAuthorizationCode)
	chanError := make(chan error, 1)
	defer close(chanError)

	server, err := createLocalAuthListener(ctx, listenAddress, chanAuthorizationCode, chanError)
	if err != nil {
		return "", err
	}
	defer server.Shutdown(ctx)

	log.Printf("Use the following oauth url to proceed: %s", authURL)
	if autoOpenBrowser {
		err := openBrowser(authURL)
		if err != nil {
			log.Printf("Failed to open browser for auth flow (Non-Fatal): %v\n", err)
		}
	}

	var code string
	select {
	case code = <-chanAuthorizationCode:
		log.Println("Received authorization_code via local callback")
	case err := <-chanError:
		return "", err
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(5 * time.Minute):
		return "", fmt.Errorf("timed out waiting for oauth2 redirect callback")
	}

	return code, nil
}

func openBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	case "darwin":
		cmd = exec.Command("open", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}
