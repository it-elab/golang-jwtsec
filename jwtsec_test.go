package jwtsec_test

import (
	"testing"
	"time"

	jwtsec "github.com/it-elab/golang-jwtsec"
)

func TestJwtManager(t *testing.T) {
	m := jwtsec.NewJwtManager(
		"Random string secret",
		time.Second*10,
		time.Second*20,
		jwtsec.Sha256,
	)

	sub := "user1"
	ip := "127.0.0.1"
	user_agent := "GoTest-UA"
	accept := "text/html"
	accept_encoding := "gzip"
	accept_language := "ru"
	cache_control := "no-cache"

	t.Run("Create and verify access token", func(t *testing.T) {
		token, err := m.CreateToken(sub, ip, user_agent, jwtsec.Access, accept, accept_encoding, accept_language, cache_control)
		if err != nil {
			t.Fatalf("CreateToken error: %v", err)
		}

		claims, err := m.VerifyToken(token, ip, user_agent, accept, accept_encoding, accept_language, cache_control)
		if err != nil {
			t.Fatalf("VerifyToken error: %v", err)
		}

		if claims.Sub != "user1" {
			t.Errorf("expected subject %s, got %s", sub, claims.Sub)
		}

		if claims.TokenType != jwtsec.Access {
			t.Errorf("expected access token, got %s", claims.TokenType)
		}
	})

	t.Run("Refresh access token", func(t *testing.T) {
		token, err := m.CreateToken(sub, ip, user_agent, jwtsec.Refresh, accept, accept_encoding, accept_language, cache_control)
		if err != nil {
			t.Fatalf("CreateToken error: %v", err)
		}

		claims, err := m.VerifyToken(token, ip, user_agent, accept, accept_encoding, accept_language, cache_control)
		if err != nil {
			t.Fatalf("VerifyToken error: %v", err)
		}

		if claims.Sub != sub {
			t.Errorf("expected subject %s, got %s", sub, claims.Sub)
		}

		if claims.TokenType != jwtsec.Refresh {
			t.Errorf("expected access token, got %s", claims.TokenType)
		}

		accessToken, err := m.RefreshAccessToken(token, ip, user_agent, accept, accept_encoding, accept_language, cache_control)
		if err != nil {
			t.Fatalf("RefreshAccessToken error: %v", err)
		}

		claims, err = m.VerifyToken(accessToken, ip, user_agent, accept, accept_encoding, accept_language, cache_control)
		if err != nil {
			t.Fatalf("VerifyToken error: %v", err)
		}

		if claims.Sub != sub {
			t.Errorf("expected subject %s, got %s", sub, claims.Sub)
		}

		if claims.TokenType != jwtsec.Access {
			t.Errorf("expected access token, got %s", claims.TokenType)
		}
	})

	t.Run("Access token expires", func(t *testing.T) {
		m2 := jwtsec.NewJwtManager(
			"11111",
			time.Millisecond*10, // очень короткое TTL,
			time.Second*20,
			jwtsec.Sha256,
		)

		token, err := m2.CreateToken(sub, ip, user_agent, jwtsec.Access, accept, accept_encoding, accept_language, cache_control)
		if err != nil {
			t.Fatalf("CreateToken error: %v", err)
		}

		time.Sleep(time.Millisecond * 50)

		_, err = m2.VerifyToken(token, ip, user_agent, accept, accept_encoding, accept_language, cache_control)
		if err == nil {
			t.Fatalf("expected expiration error, got nil")
		}
	})
}
