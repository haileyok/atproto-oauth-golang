package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/gorilla/sessions"
	oauth_helpers "github.com/haileyok/atproto-oauth-golang/helpers"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm/clause"
)

func (s *TestServer) handleLoginSubmit(e echo.Context) error {
	authInput := strings.ToLower(e.FormValue("auth-input"))
	if authInput == "" {
		return e.Redirect(302, "/login?e=auth-input-empty")
	}

	var service string
	var did string
	var loginHint string

	if strings.HasPrefix("https://", authInput) {
		u, err := url.Parse(authInput)
		if err == nil {
			u.Path = ""
			u.RawQuery = ""
			u.User = nil
			service = u.String()
		}
	} else {
		_, herr := syntax.ParseHandle(authInput)
		_, derr := syntax.ParseDID(authInput)

		if herr != nil && derr != nil {
			return e.Redirect(302, "/login?e=handle-invalid")
		}

		if derr == nil {
			did = authInput
		} else {
			maybeDid, err := resolveHandle(e.Request().Context(), authInput)
			if err != nil {
				return err
			}

			did = maybeDid
		}

		maybeService, err := resolveService(ctx, did)
		if err != nil {
			return err
		}

		service = maybeService
		loginHint = authInput
	}

	authserver, err := s.oauthClient.ResolvePdsAuthServer(ctx, service)
	if err != nil {
		return err
	}

	meta, err := s.oauthClient.FetchAuthServerMetadata(ctx, authserver)
	if err != nil {
		return err
	}

	dpopPrivateKey, err := oauth_helpers.GenerateKey(nil)
	if err != nil {
		return err
	}

	dpopPrivateKeyJson, err := json.Marshal(dpopPrivateKey)
	if err != nil {
		return err
	}

	parResp, err := s.oauthClient.SendParAuthRequest(ctx, authserver, meta, loginHint, scope, dpopPrivateKey)
	if err != nil {
		return err
	}

	oauthRequest := &OauthRequest{
		State:               parResp.State,
		AuthserverIss:       meta.Issuer,
		Did:                 did,
		PdsUrl:              service,
		PkceVerifier:        parResp.PkceVerifier,
		DpopAuthserverNonce: parResp.DpopAuthserverNonce,
		DpopPrivateJwk:      string(dpopPrivateKeyJson),
	}

	if err := s.db.Create(oauthRequest).Error; err != nil {
		return err
	}

	params := url.Values{
		"client_id":   {s.args.UrlRoot + serverMetadataPath},
		"request_uri": {parResp.RequestUri},
	}

	u, _ := url.Parse(meta.AuthorizationEndpoint)
	u.RawQuery = params.Encode()

	sess, err := session.Get("session", e)
	if err != nil {
		return err
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   300, // save for five minutes
		HttpOnly: true,
	}

	// make sure the session is empty
	sess.Values = map[any]any{}
	sess.Values["oauth_state"] = parResp.State
	sess.Values["oauth_did"] = did

	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}

	return e.Redirect(302, u.String())
}

func (s *TestServer) handleCallback(e echo.Context) error {
	params := e.QueryParams()
	state := params.Get("state")
	iss := params.Get("iss")
	code := params.Get("code")

	sess, err := session.Get("session", e)
	if err != nil {
		return err
	}

	sessState := sess.Values["oauth_state"]

	if state == "" || iss == "" || code == "" {
		return fmt.Errorf("request missing needed parameters")
	}

	if state != sessState {
		return fmt.Errorf("session state does not match response state")
	}

	var oauthRequest OauthRequest
	if err := s.db.Raw("SELECT * FROM oauth_requests WHERE state = ?", sessState).Scan(&oauthRequest).Error; err != nil {
		return err
	}

	if err := s.db.Exec("DELETE FROM oauth_requests WHERE state = ?", sessState).Error; err != nil {
		return err
	}

	if iss != oauthRequest.AuthserverIss {
		return fmt.Errorf("incoming iss did not match authserver iss")
	}

	jwk, err := oauth_helpers.ParseJWKFromBytes([]byte(oauthRequest.DpopPrivateJwk))
	if err != nil {
		return err
	}

	initialTokenResp, err := s.oauthClient.InitialTokenRequest(e.Request().Context(), code, iss, oauthRequest.PkceVerifier, oauthRequest.DpopAuthserverNonce, jwk)
	if err != nil {
		return err
	}

	if initialTokenResp.Scope != scope {
		return fmt.Errorf("did not receive correct scopes from token request")
	}

	// if we didn't start with a did, we can get it from the response
	if oauthRequest.Did == "" {
		oauthRequest.Did = initialTokenResp.Sub
	}

	oauthSession := &OauthSession{
		Did:                 oauthRequest.Did,
		PdsUrl:              oauthRequest.PdsUrl,
		AuthserverIss:       oauthRequest.AuthserverIss,
		AccessToken:         initialTokenResp.AccessToken,
		RefreshToken:        initialTokenResp.RefreshToken,
		DpopAuthserverNonce: initialTokenResp.DpopAuthserverNonce,
		DpopPrivateJwk:      oauthRequest.DpopPrivateJwk,
		Expiration:          time.Now().Add(time.Duration(int(time.Second) * int(initialTokenResp.ExpiresIn))),
	}

	if err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "did"}},
		UpdateAll: true,
	}).Create(oauthSession).Error; err != nil {
		return err
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}

	// make sure the session is empty
	sess.Values = map[any]any{}
	sess.Values["did"] = oauthRequest.Did

	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}

	slog.Default().Info("handled callback", "params", params)

	return e.Redirect(302, "/")
}

func (s *TestServer) handleLogout(e echo.Context) error {
	sess, err := session.Get("session", e)
	if err != nil {
		return err
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}

	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}

	return e.Redirect(302, "/")
}
