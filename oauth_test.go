package oauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	_ "github.com/joho/godotenv/autoload"
	"github.com/stretchr/testify/assert"
)

var (
	ctx               = context.Background()
	oauthClient       = newTestOauthClient()
	serverUrlRoot     = os.Getenv("OAUTH_TEST_SERVER_URL_ROOT")
	serverMetadataUrl = fmt.Sprintf("%s/oauth/client-metadata.json", serverUrlRoot)
	serverCallbackUrl = fmt.Sprintf("%s/callback", serverUrlRoot)
	pdsUrl            = os.Getenv("OAUTH_TEST_PDS_URL")
)

func newTestOauthClient() *OauthClient {
	b, err := os.ReadFile("./jwks.json")
	if err != nil {
		panic(err)
	}

	k, err := ParseKeyFromBytes(b)
	if err != nil {
		panic(err)
	}

	c, err := NewOauthClient(OauthClientArgs{
		ClientJwk:   k,
		ClientId:    serverMetadataUrl,
		RedirectUri: serverCallbackUrl,
	})
	if err != nil {
		panic(err)
	}

	// make sure the server is running

	req, err := http.NewRequest("GET", serverMetadataUrl, nil)
	if err != nil {
		panic(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(fmt.Errorf("could not connect to test server. are you sure you started it?"))
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)

	return c
}

func TestResolvePDSAuthServer(t *testing.T) {
	assert := assert.New(t)

	authServer, err := oauthClient.ResolvePDSAuthServer(ctx, pdsUrl)

	assert.NoError(err)
	assert.NotEmpty(authServer)
	assert.Equal(pdsUrl, authServer)
}

func TestFetchAuthServerMetadata(t *testing.T) {
	assert := assert.New(t)

	meta, err := oauthClient.FetchAuthServerMetadata(ctx, pdsUrl)

	assert.NoError(err)
	assert.IsType(&OauthAuthorizationMetadata{}, meta)
}

func TestGenerateKey(t *testing.T) {
	assert := assert.New(t)

	prefix := "testing"
	_, err := GenerateKey(&prefix)
	assert.NoError(err)
}

func TestSendParAuthRequest(t *testing.T) {
	assert := assert.New(t)

	authserverUrl, err := oauthClient.ResolvePDSAuthServer(ctx, pdsUrl)
	meta, err := oauthClient.FetchAuthServerMetadata(ctx, pdsUrl)
	if err != nil {
		panic(err)
	}

	prefix := "testing"
	dpopPriv, err := GenerateKey(&prefix)
	if err != nil {
		panic(err)
	}

	parResp, err := oauthClient.SendParAuthRequest(ctx, authserverUrl, meta, "transition:generic", "atproto", dpopPriv)
	if err != nil {
		panic(err)
	}

	assert.NoError(err)
	assert.Equal(float64(299), parResp.Resp["expires_in"])
	assert.NotEmpty(parResp.Resp["request_uri"])
}
