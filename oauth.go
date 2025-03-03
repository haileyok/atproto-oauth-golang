package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Client struct {
	h                *http.Client
	clientPrivateKey *ecdsa.PrivateKey
	clientKid        string
	clientId         string
	redirectUri      string
}

type ClientArgs struct {
	H           *http.Client
	ClientJwk   jwk.Key
	ClientId    string
	RedirectUri string
}

func NewClient(args ClientArgs) (*Client, error) {
	if args.ClientId == "" {
		return nil, fmt.Errorf("no client id provided")
	}

	if args.RedirectUri == "" {
		return nil, fmt.Errorf("no redirect uri provided")
	}

	if args.H == nil {
		args.H = &http.Client{
			Timeout: 5 * time.Second,
		}
	}

	clientPkey, err := getPrivateKey(args.ClientJwk)
	if err != nil {
		return nil, fmt.Errorf("could not load private key from provided client jwk: %w", err)
	}

	kid := args.ClientJwk.KeyID()

	return &Client{
		h:                args.H,
		clientKid:        kid,
		clientPrivateKey: clientPkey,
		clientId:         args.ClientId,
		redirectUri:      args.RedirectUri,
	}, nil
}

func (c *Client) ResolvePDSAuthServer(ctx context.Context, ustr string) (string, error) {
	u, err := isSafeAndParsed(ustr)
	if err != nil {
		return "", err
	}

	u.Path = "/.well-known/oauth-protected-resource"

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("error creating request for oauth protected resource: %w", err)
	}

	resp, err := c.h.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not get response from server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("received non-200 response from pds. code was %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("could not read body: %w", err)
	}

	var resource OauthProtectedResource
	if err := resource.UnmarshalJSON(b); err != nil {
		return "", fmt.Errorf("could not unmarshal json: %w", err)
	}

	if len(resource.AuthorizationServers) == 0 {
		return "", fmt.Errorf("oauth protected resource contained no authorization servers")
	}

	return resource.AuthorizationServers[0], nil
}

func (c *Client) FetchAuthServerMetadata(ctx context.Context, ustr string) (*OauthAuthorizationMetadata, error) {
	u, err := isSafeAndParsed(ustr)
	if err != nil {
		return nil, err
	}

	u.Path = "/.well-known/oauth-authorization-server"

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request to fetch auth metadata: %w", err)
	}

	resp, err := c.h.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting response for auth metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf(
			"received non-200 response from pds. status code was %d",
			resp.StatusCode,
		)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read body for metadata response: %w", err)
	}

	var metadata OauthAuthorizationMetadata
	if err := metadata.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("could not unmarshal metadata: %w", err)
	}

	if err := metadata.Validate(u); err != nil {
		return nil, fmt.Errorf("could not validate metadata: %w", err)
	}

	return &metadata, nil
}

func (c *Client) ClientAssertionJwt(authServerUrl string) (string, error) {
	claims := jwt.MapClaims{
		"iss": c.clientId,
		"sub": c.clientId,
		"aud": authServerUrl,
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = c.clientKid

	tokenString, err := token.SignedString(c.clientPrivateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (c *Client) AuthServerDpopJwt(method, url, nonce string, privateJwk jwk.Key) (string, error) {
	pubJwk, err := privateJwk.PublicKey()
	if err != nil {
		return "", err
	}

	b, err := json.Marshal(pubJwk)
	if err != nil {
		return "", err
	}

	var pubMap map[string]any
	if err := json.Unmarshal(b, &pubMap); err != nil {
		return "", err
	}

	now := time.Now().Unix()

	claims := jwt.MapClaims{
		"jti": uuid.NewString(),
		"htm": method,
		"htu": url,
		"iat": now,
		"exp": now + 30,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["alg"] = "ES256"
	token.Header["jwk"] = pubMap

	var rawKey any
	if err := privateJwk.Raw(&rawKey); err != nil {
		return "", err
	}

	tokenString, err := token.SignedString(rawKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func (c *Client) SendParAuthRequest(ctx context.Context, authServerUrl string, authServerMeta *OauthAuthorizationMetadata, loginHint, scope string, dpopPrivateKey jwk.Key) (*SendParAuthResponse, error) {
	if authServerMeta == nil {
		return nil, fmt.Errorf("nil metadata provided")
	}

	parUrl := authServerMeta.PushedAuthorizationRequestEndpoint

	state, err := generateToken(10)
	if err != nil {
		return nil, fmt.Errorf("could not generate state token: %w", err)
	}

	pkceVerifier, err := generateToken(48)
	if err != nil {
		return nil, fmt.Errorf("could not generate pkce verifier: %w", err)
	}

	codeChallenge := generateCodeChallenge(pkceVerifier)
	codeChallengeMethod := "S256"

	clientAssertion, err := c.ClientAssertionJwt(authServerUrl)
	if err != nil {
		return nil, err
	}

	dpopAuthserverNonce := ""
	dpopProof, err := c.AuthServerDpopJwt("POST", parUrl, dpopAuthserverNonce, dpopPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error getting dpop proof: %w", err)
	}

	params := url.Values{
		"response_type":         {"code"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {codeChallengeMethod},
		"client_id":             {c.clientId},
		"state":                 {state},
		"redirect_uri":          {c.redirectUri},
		"scope":                 {scope},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {clientAssertion},
	}

	if loginHint != "" {
		params.Set("login_hint", loginHint)
	}

	_, err = isSafeAndParsed(parUrl)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", parUrl, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpopProof)

	resp, err := c.h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rmap map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rmap); err != nil {
		return nil, err
	}

	if resp.StatusCode == 400 && rmap["error"] == "use_dpop_nonce" {
		dpopAuthserverNonce = resp.Header.Get("DPoP-Nonce")
		dpopProof, err := c.AuthServerDpopJwt("POST", parUrl, dpopAuthserverNonce, dpopPrivateKey)
		if err != nil {
			return nil, err
		}

		req2, err := http.NewRequestWithContext(
			ctx,
			"POST",
			parUrl,
			strings.NewReader(params.Encode()),
		)
		if err != nil {
			return nil, err
		}

		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req2.Header.Set("DPoP", dpopProof)

		resp2, err := c.h.Do(req2)
		if err != nil {
			return nil, err
		}
		defer resp2.Body.Close()

		rmap = map[string]any{}
		if err := json.NewDecoder(resp2.Body).Decode(&rmap); err != nil {
			return nil, err
		}
	}

	return &SendParAuthResponse{
		PkceVerifier:        pkceVerifier,
		State:               state,
		DpopAuthserverNonce: dpopAuthserverNonce,
		Resp:                rmap,
	}, nil
}

func (c *Client) InitialTokenRequest(
	ctx context.Context,
	code,
	authserverIss,
	pkceVerifier,
	dpopAuthserverNonce string,
	dpopPrivateJwk jwk.Key,
) (*TokenResponse, error) {
	authserverMeta, err := c.FetchAuthServerMetadata(ctx, authserverIss)
	if err != nil {
		return nil, err
	}

	clientAssertion, err := c.ClientAssertionJwt(authserverIss)
	if err != nil {
		return nil, err
	}

	params := url.Values{
		"client_id":             {c.clientId},
		"redirect_uri":          {c.redirectUri},
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"code_verifier":         {pkceVerifier},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {clientAssertion},
	}

	dpopProof, err := c.AuthServerDpopJwt("POST", authserverMeta.TokenEndpoint, dpopAuthserverNonce, dpopPrivateJwk)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", authserverMeta.TokenEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpopProof)

	resp, err := c.h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	tokenResponse.DpopAuthserverNonce = dpopAuthserverNonce

	return &tokenResponse, nil
}

func (c *Client) RefreshTokenRequest(
	ctx context.Context,
	refreshToken,
	authserverIss,
	dpopAuthserverNonce string,
	dpopPrivateJwk jwk.Key,
) (*TokenResponse, error) {
	// we may need to update the dpop nonce
	for range 2 {
		authserverMeta, err := c.FetchAuthServerMetadata(ctx, authserverIss)
		if err != nil {
			return nil, err
		}

		clientAssertion, err := c.ClientAssertionJwt(authserverIss)
		if err != nil {
			return nil, err
		}

		params := url.Values{
			"client_id":             {c.clientId},
			"grant_type":            {"refresh_token"},
			"refresh_token":         {refreshToken},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {clientAssertion},
		}

		dpopProof, err := c.AuthServerDpopJwt("POST", authserverMeta.TokenEndpoint, dpopAuthserverNonce, dpopPrivateJwk)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, "POST", authserverMeta.TokenEndpoint, strings.NewReader(params.Encode()))
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", dpopProof)

		resp, err := c.h.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			var respMap map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&respMap); err != nil {
				return nil, err
			}

			if resp.StatusCode == 400 && respMap["error"] == "use_dpop_nonce" {
				dpopAuthserverNonce = resp.Header.Get("DPoP-Nonce")
				continue
			}

			return nil, fmt.Errorf("token refresh error: %s", respMap["error"])
		}

		var tokenResponse TokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
			return nil, err
		}

		// set the nonce so that updates are reflected in response
		tokenResponse.DpopAuthserverNonce = dpopAuthserverNonce

		return &tokenResponse, nil
	}

	return nil, nil
}

func generateToken(len int) (string, error) {
	b := make([]byte, len)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func generateCodeChallenge(pkceVerifier string) string {
	h := sha256.New()
	h.Write([]byte(pkceVerifier))
	hash := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hash)
}

func parsePrivateJwkFromString(str string) (jwk.Key, error) {
	return jwk.ParseKey([]byte(str))
}
