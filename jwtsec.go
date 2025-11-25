package jwtsec

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

const (
	Access  TokenType = "access"
	Refresh TokenType = "refresh"
)

type CryptAlgo string

const (
	Sha224 CryptAlgo = "sha224"
	Sha256 CryptAlgo = "sha256"
	Sha384 CryptAlgo = "sha384"
	Sha512 CryptAlgo = "sha512"
)

type JwtManager struct {
	baseSecret []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	cryptAlgo  CryptAlgo
}

type Claims struct {
	Sub       string    `json:"sub"`
	Exp       int64     `json:"exp"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	TokenType TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

func NewJwtManager(
	baseSecret string,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	algo CryptAlgo,
) *JwtManager {
	return &JwtManager{
		baseSecret: []byte(baseSecret),
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		cryptAlgo:  algo,
	}
}

// ======================
//   internal utilities
// ======================

func (m *JwtManager) hash(data ...[]byte) []byte {
	switch m.cryptAlgo {
	case Sha224:
		h := sha256.New224()
		for _, d := range data {
			h.Write(d)
		}
		return h.Sum(nil)
	case Sha256:
		h := sha256.New()
		for _, d := range data {
			h.Write(d)
		}
		return h.Sum(nil)
	case Sha384:
		h := sha512.New384()
		for _, d := range data {
			h.Write(d)
		}
		return h.Sum(nil)
	case Sha512:
		h := sha512.New()
		for _, d := range data {
			h.Write(d)
		}
		return h.Sum(nil)
	default:
		panic("unknown algorithm")
	}
}

// derive 32-byte key
func (m *JwtManager) deriveKey(ip, user_agent, accept, accept_encoding, accept_language, cache_control string) []byte {
	sum := m.hash(
		[]byte(ip),
		[]byte(user_agent),
		[]byte(accept),
		[]byte(accept_encoding),
		[]byte(accept_language),
		[]byte(cache_control),
		m.baseSecret,
	)

	key := make([]byte, 32)
	copy(key, sum)
	return key
}

func now() int64 {
	return time.Now().Unix()
}

// ======================
//   token creation
// ======================

func (m *JwtManager) CreateToken(
	subject, ip, user_agent string,
	tokenType TokenType,
	accept, accept_encoding, accept_language, cache_control string,
) (string, error) {

	ttl := m.accessTTL
	if tokenType == Refresh {
		ttl = m.refreshTTL
	}

	exp := now() + int64(ttl.Seconds())

	claims := Claims{
		Sub:       subject,
		Exp:       exp,
		IP:        ip,
		UserAgent: user_agent,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(exp, 0)),
			Subject:   subject,
		},
	}

	key := m.deriveKey(ip, user_agent, accept, accept_encoding, accept_language, cache_control)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

// ======================
//   token verification
// ======================

func (m *JwtManager) VerifyToken(
	tokenStr, ip, user_agent, accept, accept_encoding, accept_language, cache_control string,
) (*Claims, error) {

	key := m.deriveKey(ip, user_agent, accept, accept_encoding, accept_language, cache_control)

	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid_token")
	}

	if claims.Exp < now() {
		return nil, errors.New("expired_token")
	}

	return claims, nil
}

// ======================
//   refresh access token
// ======================

func (m *JwtManager) RefreshAccessToken(
	refresh, ip, user_agent, accept, accept_encoding, accept_language, cache_control string,
) (string, error) {

	claims, err := m.VerifyToken(refresh, ip, user_agent, accept, accept_encoding, accept_language, cache_control)
	if err != nil {
		return "", err
	}

	if claims.TokenType != Refresh {
		return "", errors.New("not_refresh_token")
	}

	return m.CreateToken(
		claims.Sub,
		ip,
		user_agent,
		Access,
		accept,
		accept_encoding,
		accept_language,
		cache_control,
	)
}
