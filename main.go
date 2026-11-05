// Email Test Tools: a local web app for testing SMTP settings and
// debugging email-related network problems.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"email-test-tools/internal/server"
	"email-test-tools/web"
)

// Set at build time: -ldflags "-X main.version=v1.2.3"
var version = "dev"

const defaultAddr = "127.0.0.1:8587"

func main() {
	addr := flag.String("addr", defaultAddr, "address to listen on (use 0.0.0.0:8587 to allow other computers, not recommended)")
	noBrowser := flag.Bool("no-browser", false, "don't open the web browser automatically")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("email-test-tools", version)
		return
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil && *addr == defaultAddr {
		// Default port busy (maybe another copy is running): pick any free port.
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot listen:", err)
		os.Exit(1)
	}

	tcp := ln.Addr().(*net.TCPAddr)
	remote := !tcp.IP.IsLoopback()
	if remote {
		slog.Warn("listening on a non-loopback address: anyone who can reach this port can use the tools to probe networks from this machine")
	}
	url := fmt.Sprintf("http://127.0.0.1:%d", tcp.Port)
	if remote {
		url = fmt.Sprintf("http://%s", ln.Addr())
	}

	srv := &http.Server{
		Handler:           server.New(server.Options{Static: web.Static(), Version: version, AllowRemote: remote}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("\n  Email Test Tools %s\n  ➜ Open %s in your browser\n  Press Ctrl+C to stop.\n\n", version, url)
	if !*noBrowser {
		go openBrowser(url)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func openBrowser(url string) {
	time.Sleep(300 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Stdout, cmd.Stderr = nil, nil
	_ = cmd.Start()
}
