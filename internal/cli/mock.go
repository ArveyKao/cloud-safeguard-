package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// runMock implements the demo helper `csg mock request`.
func (a *App) runMock(args []string) error {
	if len(args) == 0 {
		return usagef("mock requires a subcommand: request")
	}
	switch args[0] {
	case "request":
		return a.runMockRequest(args[1:])
	default:
		return usagef("unknown mock subcommand %q (request)", args[0])
	}
}

// runMockRequest calls the built-in mock cloud with the mock STS token from
// $ALIBABA_CLOUD_SECURITY_TOKEN. The token is never printed or echoed.
func (a *App) runMockRequest(args []string) error {
	fs := a.newFlagSet("mock request", `Usage: csg mock request METHOD /v1/PATH [JSON_BODY] [--json] [--server URL]

Calls the built-in mock cloud using the short-lived token in
$ALIBABA_CLOUD_SECURITY_TOKEN (fetch one with: eval "$(csg credential --lease ID --export)").
Prints the response body; exits 1 on HTTP >= 400.
`)
	serverFlag := fs.String("server", "", "control plane URL (default: $CSG_SERVER or saved config)")
	jsonOut := fs.Bool("json", false, "print request/response metadata without the token")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) < 2 || len(positionals) > 3 {
		return usagef("mock request requires METHOD and /v1/PATH (and an optional JSON body)")
	}
	method := strings.ToUpper(strings.TrimSpace(positionals[0]))
	if method == "" {
		return usagef("mock request requires an HTTP method")
	}
	requestPath := strings.TrimSpace(positionals[1])
	if requestPath == "" {
		return usagef("mock request requires a path such as /v1/ecs/instances")
	}
	bodyJSON := ""
	if len(positionals) == 3 {
		bodyJSON = positionals[2]
		if !json.Valid([]byte(bodyJSON)) {
			return usagef("mock request body is not valid JSON")
		}
	}

	server, err := a.resolveServer(&clientFlags{server: *serverFlag})
	if err != nil {
		return err
	}
	mockToken := strings.TrimSpace(a.Getenv("ALIBABA_CLOUD_SECURITY_TOKEN"))
	if mockToken == "" {
		return usagef("ALIBABA_CLOUD_SECURITY_TOKEN is not set: fetch a lease credential first (csg credential --lease ID --export)")
	}

	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	fullPath := requestPath
	if !strings.HasPrefix(fullPath, "/mock-cloud") {
		fullPath = "/mock-cloud" + fullPath
	}
	target := server + fullPath

	var reader io.Reader
	if bodyJSON != "" {
		reader = bytes.NewReader([]byte(bodyJSON))
	}
	req, err := http.NewRequestWithContext(context.Background(), method, target, reader)
	if err != nil {
		return fmt.Errorf("cannot build mock-cloud request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+mockToken)
	req.Header.Set("Accept", "application/json")
	if bodyJSON != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach mock cloud at %s: %v", server, unwrapHTTPError(err))
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("cannot read mock-cloud response: %v", err)
	}

	if *jsonOut {
		var parsed any
		if jsonErr := json.Unmarshal(respBody, &parsed); jsonErr != nil {
			parsed = string(respBody)
		}
		payload := map[string]any{
			"method":   method,
			"path":     fullPath,
			"status":   resp.StatusCode,
			"response": parsed,
		}
		if err := a.printJSON(payload); err != nil {
			return err
		}
	} else {
		_, _ = a.Stdout.Write(respBody)
		if len(respBody) == 0 || respBody[len(respBody)-1] != '\n' {
			fmt.Fprintln(a.Stdout)
		}
	}

	if resp.StatusCode >= 400 {
		var cloudError struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		}
		if jsonErr := json.Unmarshal(respBody, &cloudError); jsonErr == nil && cloudError.Code != "" {
			fmt.Fprintf(a.Stderr, "error: %s: %s\n", cloudError.Code, cloudError.Message)
		} else {
			fmt.Fprintf(a.Stderr, "error: mock-cloud request failed with HTTP %d\n", resp.StatusCode)
		}
		return silentExit(ExitOperationErr)
	}
	return nil
}
