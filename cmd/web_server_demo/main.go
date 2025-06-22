package main

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	oauth "github.com/haileyok/atproto-oauth-golang"
	oauth_helpers "github.com/haileyok/atproto-oauth-golang/helpers"
	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	slogecho "github.com/samber/slog-echo"
	"github.com/urfave/cli/v2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	ctx                = context.Background()
	serverMetadataPath = "/oauth/client-metadata.json"
	serverCallbackPath = "/callback"
	scope              = "atproto transition:generic"
)

func main() {
	app := &cli.App{
		Name:   "atproto-goauth-demo-webserver",
		Action: run,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "addr",
				Value:   ":8080",
				EnvVars: []string{"OAUTH_TEST_SERVER_ADDR"},
			},
			&cli.StringFlag{
				Name:     "url-root",
				Required: true,
				EnvVars:  []string{"OAUTH_TEST_SERVER_URL_ROOT"},
			},
			&cli.StringFlag{
				Name:    "static-file-path",
				Value:   "./cmd/web_server_demo/html",
				EnvVars: []string{"OAUTH_TEST_SERVER_STATIC_PATH"},
			},
			&cli.StringFlag{
				Name:    "session-secret",
				Value:   "session-secret",
				EnvVars: []string{"OAUTH_TEST_SERVER_SESSION_SECRET"},
			},
		},
	}

	app.Run(os.Args)
}

type TestServer struct {
	httpd        *http.Server
	e            *echo.Echo
	db           *gorm.DB
	oauthClient  *oauth.Client
	xrpcCli      *oauth.XrpcClient
	jwksResponse *oauth_helpers.JwksResponseObject
	args         ServerArgs
}

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	if viewContext, isMap := data.(map[string]any); isMap {
		viewContext["reverse"] = c.Echo().Reverse
	}

	return t.templates.ExecuteTemplate(w, name, data)
}

func run(cmd *cli.Context) error {
	s, err := NewServer(ServerArgs{
		Addr:           cmd.String("addr"),
		UrlRoot:        cmd.String("url-root"),
		StaticFilePath: cmd.String("static-file-path"),
		SessionSecret:  cmd.String("session-secret"),
	})
	if err != nil {
		panic(err)
	}

	s.run()

	return nil
}

type ServerArgs struct {
	Addr           string
	UrlRoot        string
	StaticFilePath string
	SessionSecret  string
}

func NewServer(args ServerArgs) (*TestServer, error) {
	e := echo.New()

	e.Use(slogecho.New(slog.Default()))
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(args.SessionSecret))))

	fmt.Println("atproto goauth demo webserver")

	b, err := os.ReadFile("./jwks.json")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(
				"could not find jwks.json. does it exist? hint: run `go run ./cmd/cmd generate-jwks --prefix demo` to create one.",
			)
		}
		return nil, err
	}

	k, err := oauth_helpers.ParseJWKFromBytes(b)
	if err != nil {
		return nil, err
	}

	pubKey, err := k.PublicKey()
	if err != nil {
		return nil, err
	}

	c, err := oauth.NewClient(oauth.ClientArgs{
		ClientJwk:   k,
		ClientId:    args.UrlRoot + serverMetadataPath,
		RedirectUri: args.UrlRoot + serverCallbackPath,
	})
	if err != nil {
		return nil, err
	}

	httpd := &http.Server{
		Addr:    args.Addr,
		Handler: e,
	}

	db, err := gorm.Open(sqlite.Open("oauth.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(&OauthRequest{}, &OauthSession{})

	xrpcCli := &oauth.XrpcClient{
		OnDpopPdsNonceChanged: func(did, newNonce string) {
			if err := db.Exec("UPDATE oauth_sessions SET dpop_pds_nonce = ? WHERE did = ?", newNonce, did).Error; err != nil {
				slog.Default().Error("error updating pds nonce", "err", err)
			}
		},
	}

	s := &TestServer{
		httpd:        httpd,
		e:            e,
		db:           db,
		oauthClient:  c,
		xrpcCli:      xrpcCli,
		jwksResponse: oauth_helpers.CreateJwksResponseObject(pubKey),
		args:         args,
	}

	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob(s.getFilePath("*.html"))),
	}
	e.Renderer = renderer

	return s, nil
}

func (s *TestServer) run() error {
	s.e.GET("/", s.handleHome)
	s.e.File("/login", s.getFilePath("login.html"))
	s.e.POST("/login", s.handleLoginSubmit)
	s.e.GET("/logout", s.handleLogout)
	s.e.GET("/profile", s.handleProfile)
	s.e.GET("/make-post", s.handleMakePost)
	s.e.GET("/callback", s.handleCallback)
	s.e.GET("/oauth/client-metadata.json", s.handleClientMetadata)
	s.e.GET("/oauth/jwks.json", s.handleJwks)

	slog.Default().Info("starting http server", "addr", s.args.Addr)

	if err := s.httpd.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

func (s *TestServer) handleHome(e echo.Context) error {
	sess, err := session.Get("session", e)
	if err != nil {
		return err
	}

	return e.Render(200, "index.html", map[string]any{
		"Did": sess.Values["did"],
	})
}

func (s *TestServer) handleClientMetadata(e echo.Context) error {
	metadata := map[string]any{
		"client_id":                       s.args.UrlRoot + serverMetadataPath,
		"client_name":                     "Atproto GoAuth Demo Webserver",
		"client_uri":                      s.args.UrlRoot,
		"logo_uri":                        fmt.Sprintf("%s/logo.png", s.args.UrlRoot),
		"tos_uri":                         fmt.Sprintf("%s/tos", s.args.UrlRoot),
		"policy_url":                      fmt.Sprintf("%s/policy", s.args.UrlRoot),
		"redirect_uris":                   []string{s.args.UrlRoot + serverCallbackPath},
		"grant_types":                     []string{"authorization_code", "refresh_token"},
		"response_types":                  []string{"code"},
		"application_type":                "web",
		"dpop_bound_access_tokens":        true,
		"jwks_uri":                        fmt.Sprintf("%s/oauth/jwks.json", s.args.UrlRoot),
		"scope":                           "atproto transition:generic",
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
	}

	return e.JSON(200, metadata)
}

func (s *TestServer) handleJwks(e echo.Context) error {
	return e.JSON(200, s.jwksResponse)
}

func (s *TestServer) getFilePath(file string) string {
	return fmt.Sprintf("%s/%s", s.args.StaticFilePath, file)
}
