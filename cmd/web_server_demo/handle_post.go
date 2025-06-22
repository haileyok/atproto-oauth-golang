package main

import (
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/lex/util"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/labstack/echo/v4"
)

func (s *TestServer) handleMakePost(e echo.Context) error {
	authArgs, authed, err := s.getOauthSessionAuthArgs(e)
	if err != nil {
		return err
	}

	if !authed {
		return e.Redirect(302, "/login")
	}

	post := bsky.FeedPost{
		Text:      "hello from atproto golang oauth client",
		CreatedAt: syntax.DatetimeNow().String(),
	}

	input := atproto.RepoCreateRecord_Input{
		Collection: "app.bsky.feed.post",
		Repo:       authArgs.Did,
		Record:     &util.LexiconTypeDecoder{Val: &post},
	}

	var out atproto.RepoCreateRecord_Output
	if err := s.xrpcCli.Do(e.Request().Context(), authArgs, xrpc.Procedure, "application/json", "com.atproto.repo.createRecord", nil, input, &out); err != nil {
		return err
	}

	return e.File(s.getFilePath("make-post.html"))
}
