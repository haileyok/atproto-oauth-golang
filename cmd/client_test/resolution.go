package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

func resolveHandle(ctx context.Context, handle string) (string, error) {
	var did string

	_, err := syntax.ParseHandle(handle)
	if err != nil {
		return "", err
	}

	recs, err := net.LookupTXT(fmt.Sprintf("_atproto.%s", handle))
	if err == nil {
		for _, rec := range recs {
			if strings.HasPrefix(rec, "did=") {
				did = strings.Split(rec, "did=")[1]
				break
			}
		}
	}

	if did == "" {
		req, err := http.NewRequestWithContext(
			ctx,
			"GET",
			fmt.Sprintf("https://%s/.well-known/atproto-did", handle),
			nil,
		)
		if err != nil {
			return "", err
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, resp.Body)
			return "", fmt.Errorf("unable to resolve handle")
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		maybeDid := string(b)

		if _, err := syntax.ParseDID(maybeDid); err != nil {
			return "", fmt.Errorf("unable to resolve handle")
		}

		did = maybeDid
	}

	return did, nil
}

func resolveService(ctx context.Context, did string) (string, error) {
	type Identity struct {
		Service []struct {
			ID              string `json:"id"`
			Type            string `json:"type"`
			ServiceEndpoint string `json:"serviceEndpoint"`
		} `json:"service"`
	}

	var ustr string
	if strings.HasPrefix(did, "did:plc:") {
		ustr = fmt.Sprintf("https://plc.directory/%s", did)
	} else if strings.HasPrefix(did, "did:web:") {
		ustr = fmt.Sprintf("https://%s/.well-known/did.json", strings.TrimPrefix(did, "did:web:"))
	} else {
		return "", fmt.Errorf("did was not a supported did type")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", ustr, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("could not find identity in plc registry")
	}

	var identity Identity
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		return "", err
	}

	var service string
	for _, svc := range identity.Service {
		if svc.ID == "#atproto_pds" {
			service = svc.ServiceEndpoint
		}
	}

	if service == "" {
		return "", fmt.Errorf("could not find atproto_pds service in identity services")
	}

	return service, nil
}
