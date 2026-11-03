// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package yggdrasil

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/achetronic/minecrauth/internal/accounts"
	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/config"
	"github.com/achetronic/minecrauth/internal/fallback"
	"github.com/achetronic/minecrauth/internal/signing"
	"github.com/achetronic/minecrauth/internal/store/sqlite"
)

// newTestKeyManager generates a 2048-bit RSA key, writes it to a temp file, and loads
// it via signing.New. Using a pre-written file makes signing.New load rather than
// generate, keeping tests fast while exercising the full KeyManager code path.
func newTestKeyManager(t *testing.T) *signing.KeyManager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling test RSA key to PKCS#8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	keyPath := filepath.Join(t.TempDir(), "test.key")
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		t.Fatalf("writing test RSA key to disk: %v", err)
	}
	km, err := signing.New(keyPath)
	if err != nil {
		t.Fatalf("loading test KeyManager: %v", err)
	}
	return km
}

// testEnv wires a complete, isolated Yggdrasil stack backed by a real SQLite database.
type testEnv struct {
	handler  http.Handler
	accounts *accounts.Service
	tokens   *auth.TokenService
}

// newTestEnv constructs a full testEnv with a fresh in-memory SQLite store.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	st, err := sqlite.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("creating test store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrating test store: %v", err)
	}

	policy := accounts.Policy{
		MinPasswordLength: 8,
		MaxPlayersPerUser: -1,
		PlayerNameRegex:   regexp.MustCompile(`^[a-zA-Z0-9_]{2,16}$`),
		UUIDGeneration:    "random",
		RequireInvite:     false,
	}

	svc := accounts.NewService(st, policy)
	authn := auth.NewPasswordAuthenticator(st)
	tokens := auth.NewTokenService(st, 0, nil) // TTL 0 = never expires
	km := newTestKeyManager(t)

	h := NewHandler(tokens, authn, svc, km, "TestServer", "example.com", "http://example.com", nil, false, false, true, true, "0.0.0-test")
	return &testEnv{handler: h.Routes(), accounts: svc, tokens: tokens}
}

// do fires an HTTP request against the in-process handler and returns the recorder.
func (e *testEnv) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshaling request body: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

// decodeBody is a helper that JSON-decodes the recorder body into v.
func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decoding response body: %v\nbody was: %s", err, rec.Body.String())
	}
}

// createUserAndPlayer is a test helper that registers a user and adds one player via
// the accounts service, returning (userID, playerUUID dashed, playerName).
func createUserAndPlayer(t *testing.T, e *testEnv, email, password, playerName string) (userID, playerUUID, name string) {
	t.Helper()
	ctx := context.Background()
	user, err := e.accounts.AdminCreateUser(ctx, email, password, false)
	if err != nil {
		t.Fatalf("creating test user %q: %v", email, err)
	}
	player, err := e.accounts.CreatePlayer(ctx, user.ID, playerName, "")
	if err != nil {
		t.Fatalf("creating test player %q: %v", playerName, err)
	}
	return user.ID, player.UUID, player.Name
}

// TestUUIDRoundTrip verifies that undash(redash(x)) == x and redash(undash(y)) == y for
// representative UUID values. This is a canary for the wire-format conversion logic.
func TestUUIDRoundTrip(t *testing.T) {
	cases := []struct {
		dashed   string
		undashed string
	}{
		{
			dashed:   "550e8400-e29b-41d4-a716-446655440000",
			undashed: "550e8400e29b41d4a716446655440000",
		},
		{
			dashed:   "00000000-0000-0000-0000-000000000000",
			undashed: "00000000000000000000000000000000",
		},
		{
			dashed:   "ffffffff-ffff-ffff-ffff-ffffffffffff",
			undashed: "ffffffffffffffffffffffffffffffff",
		},
	}

	for _, tc := range cases {
		got := undash(tc.dashed)
		if got != tc.undashed {
			t.Errorf("undash(%q) = %q; want %q", tc.dashed, got, tc.undashed)
		}
		got = redash(tc.undashed)
		if got != tc.dashed {
			t.Errorf("redash(%q) = %q; want %q", tc.undashed, got, tc.dashed)
		}
		if redash(undash(tc.dashed)) != tc.dashed {
			t.Errorf("redash(undash(%q)) round-trip failed", tc.dashed)
		}
		if undash(redash(tc.undashed)) != tc.undashed {
			t.Errorf("undash(redash(%q)) round-trip failed", tc.undashed)
		}
	}
}

// TestRedashBadInput confirms that redash is a no-op when the input is not 32 characters.
func TestRedashBadInput(t *testing.T) {
	in := "not-a-hex-uuid"
	if got := redash(in); got != in {
		t.Errorf("redash(%q) = %q; want unchanged input", in, got)
	}
}

// TestMetadata verifies the GET / metadata document shape and that signaturePublickey is
// a parseable PKIX PEM block, which authlib-injector uses to verify texture signatures.
func TestMetadata(t *testing.T) {
	e := newTestEnv(t)
	rec := e.do(t, http.MethodGet, "/", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d; want 200", rec.Code)
	}

	var meta MetadataResponse
	decodeBody(t, rec, &meta)

	if meta.Meta.ImplementationName != "minecrauth" {
		t.Errorf("implementationName = %q; want %q", meta.Meta.ImplementationName, "minecrauth")
	}
	if meta.Meta.ServerName != "TestServer" {
		t.Errorf("serverName = %q; want %q", meta.Meta.ServerName, "TestServer")
	}
	if meta.Meta.ImplementationVersion != "0.0.0-test" {
		t.Errorf("implementationVersion = %q; want %q (must be build-stamped, not hardcoded)", meta.Meta.ImplementationVersion, "0.0.0-test")
	}
	if meta.Meta.Links == nil {
		t.Fatal("meta.links is nil; want homepage and register URLs")
	}
	if meta.Meta.Links.Homepage != "http://example.com" {
		t.Errorf("links.homepage = %q; want %q", meta.Meta.Links.Homepage, "http://example.com")
	}
	if meta.Meta.Links.Register != "http://example.com/login" {
		t.Errorf("links.register = %q; want %q", meta.Meta.Links.Register, "http://example.com/login")
	}
	if len(meta.SkinDomains) == 0 || meta.SkinDomains[0] != "example.com" {
		t.Errorf("skinDomains = %v; want [example.com]", meta.SkinDomains)
	}
	if meta.SignaturePublickey == "" {
		t.Fatal("signaturePublickey is empty")
	}

	block, _ := pem.Decode([]byte(meta.SignaturePublickey))
	if block == nil {
		t.Fatal("signaturePublickey is not a valid PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM block type = %q; want PUBLIC KEY", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKIXPublicKey: %v", err)
	}
	if _, ok := parsed.(*rsa.PublicKey); !ok {
		t.Fatalf("parsed key type = %T; want *rsa.PublicKey", parsed)
	}

	if !meta.Meta.EnableProfileKey {
		t.Error("expected feature.enable_profile_key to be true")
	}
}

// TestAuthenticateHappyPath is the end-to-end canary:
//
//  1. Register a user with one player.
//  2. POST /authserver/authenticate -> get accessToken + selectedProfile.
//  3. POST /authserver/validate -> 204.
//  4. POST /sessionserver/session/minecraft/join -> 204.
//  5. GET /sessionserver/session/minecraft/hasJoined -> 200 with full profile.
//  6. Verify the texture signature against the public key from the metadata endpoint.
//     This is the critical canary: it would fail if the wrong hash, key, or base64
//     encoding were used anywhere in the signing pipeline.
func TestAuthenticateHappyPath(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	_ = ctx

	email := "player@example.com"
	password := "securepass1"
	playerName := "HeroPlayer"

	_, _, _ = createUserAndPlayer(t, e, email, password, playerName)

	// Step 1: authenticate.
	authRec := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": email,
		"password": password,
	})
	if authRec.Code != http.StatusOK {
		t.Fatalf("authenticate status = %d; want 200\nbody: %s", authRec.Code, authRec.Body.String())
	}

	var authResp AuthenticateResponse
	decodeBody(t, authRec, &authResp)

	if authResp.AccessToken == "" {
		t.Fatal("accessToken is empty")
	}
	if authResp.ClientToken == "" {
		t.Fatal("clientToken is empty")
	}
	if authResp.SelectedProfile == nil {
		t.Fatal("selectedProfile is nil; expected auto-selection for a single-player account")
	}
	if authResp.SelectedProfile.Name != playerName {
		t.Errorf("selectedProfile.name = %q; want %q", authResp.SelectedProfile.Name, playerName)
	}

	selectedUndashed := authResp.SelectedProfile.ID
	if len(selectedUndashed) != 32 {
		t.Errorf("selectedProfile.id length = %d; want 32 (undashed UUID)", len(selectedUndashed))
	}

	// The availableProfiles list should include the player.
	if len(authResp.AvailableProfiles) != 1 {
		t.Fatalf("availableProfiles len = %d; want 1", len(authResp.AvailableProfiles))
	}

	// Step 2: validate the token.
	valRec := e.do(t, http.MethodPost, "/authserver/validate", map[string]any{
		"accessToken": authResp.AccessToken,
		"clientToken": authResp.ClientToken,
	})
	if valRec.Code != http.StatusNoContent {
		t.Fatalf("validate status = %d; want 204\nbody: %s", valRec.Code, valRec.Body.String())
	}

	// Step 3: join.
	serverID := "unique-server-id-for-canary"
	joinRec := e.do(t, http.MethodPost, "/sessionserver/session/minecraft/join", map[string]any{
		"accessToken":     authResp.AccessToken,
		"selectedProfile": selectedUndashed,
		"serverId":        serverID,
	})
	if joinRec.Code != http.StatusNoContent {
		t.Fatalf("join status = %d; want 204\nbody: %s", joinRec.Code, joinRec.Body.String())
	}

	// Step 4: hasJoined.
	hasJoinedPath := "/sessionserver/session/minecraft/hasJoined?username=" + playerName + "&serverId=" + serverID
	hjRec := e.do(t, http.MethodGet, hasJoinedPath, nil)
	if hjRec.Code != http.StatusOK {
		t.Fatalf("hasJoined status = %d; want 200\nbody: %s", hjRec.Code, hjRec.Body.String())
	}

	var profile FullProfile
	decodeBody(t, hjRec, &profile)

	if profile.ID != selectedUndashed {
		t.Errorf("hasJoined profile id = %q; want %q", profile.ID, selectedUndashed)
	}
	if profile.Name != playerName {
		t.Errorf("hasJoined profile name = %q; want %q", profile.Name, playerName)
	}
	if len(profile.Properties) == 0 {
		t.Fatal("hasJoined profile has no properties")
	}
	texProp := profile.Properties[0]
	if texProp.Name != "textures" {
		t.Errorf("properties[0].name = %q; want textures", texProp.Name)
	}
	if texProp.Value == "" {
		t.Fatal("properties[0].value is empty")
	}
	if texProp.Signature == "" {
		t.Fatal("properties[0].signature is empty; canary requires a signed profile")
	}

	// Step 5: signature canary.
	// Obtain the public key from the live metadata endpoint (not from an internal handle)
	// to make this a fully external-facing verification of the signing pipeline.
	metaRec := e.do(t, http.MethodGet, "/", nil)
	var meta MetadataResponse
	decodeBody(t, metaRec, &meta)

	pemBlock, _ := pem.Decode([]byte(meta.SignaturePublickey))
	if pemBlock == nil {
		t.Fatal("signaturePublickey from metadata is not valid PEM")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing public key from metadata: %v", err)
	}
	pubKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("metadata public key type = %T; want *rsa.PublicKey", parsedKey)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(texProp.Signature)
	if err != nil {
		t.Fatalf("base64-decoding texture signature: %v", err)
	}

	// The signature is over sha1(value) where value is the base64 string itself.
	// This must match signing.KeyManager.SignProperty which uses crypto.SHA1 + PKCS1v15.
	digest := sha1.Sum([]byte(texProp.Value))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, digest[:], sigBytes); err != nil {
		t.Fatalf("texture signature verification failed (SHA1withRSA/PKCS1v15): %v", err)
	}
}

// TestAuthenticateBadPassword verifies that an incorrect password returns 403 with the
// canonical Yggdrasil ForbiddenOperationException error shape.
func TestAuthenticateBadPassword(t *testing.T) {
	e := newTestEnv(t)
	createUserAndPlayer(t, e, "user@example.com", "correctpass", "SomePlayer")

	rec := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": "user@example.com",
		"password": "wrongpassword",
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", rec.Code)
	}

	var errBody YggError
	decodeBody(t, rec, &errBody)

	if errBody.Error != "ForbiddenOperationException" {
		t.Errorf("error = %q; want ForbiddenOperationException", errBody.Error)
	}
	if errBody.ErrorMessage == "" {
		t.Error("errorMessage is empty")
	}
}

// TestAuthenticateUnknownUser verifies that an unknown email also returns 403 (no user
// enumeration via different error codes or messages).
func TestAuthenticateUnknownUser(t *testing.T) {
	e := newTestEnv(t)

	rec := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": "nobody@example.com",
		"password": "doesnotmatter",
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", rec.Code)
	}
}

// TestRefreshRotates verifies that after a successful refresh:
//   - a new, different access token is returned, and
//   - the old access token is no longer valid (validate returns 403).
func TestRefreshRotates(t *testing.T) {
	e := newTestEnv(t)
	createUserAndPlayer(t, e, "refresh@example.com", "strongpass", "RefreshMe")

	// Authenticate to get a token pair.
	authRec := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": "refresh@example.com",
		"password": "strongpass",
	})
	if authRec.Code != http.StatusOK {
		t.Fatalf("authenticate status = %d", authRec.Code)
	}
	var authResp AuthenticateResponse
	decodeBody(t, authRec, &authResp)

	oldAccess := authResp.AccessToken
	clientToken := authResp.ClientToken

	// Refresh the token pair.
	refreshRec := e.do(t, http.MethodPost, "/authserver/refresh", map[string]any{
		"accessToken": oldAccess,
		"clientToken": clientToken,
	})
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d\nbody: %s", refreshRec.Code, refreshRec.Body.String())
	}
	var refreshResp RefreshResponse
	decodeBody(t, refreshRec, &refreshResp)

	if refreshResp.AccessToken == oldAccess {
		t.Error("refreshed access token is identical to the original; rotation did not occur")
	}
	if refreshResp.ClientToken != clientToken {
		t.Errorf("client token changed after refresh: got %q, want %q", refreshResp.ClientToken, clientToken)
	}

	// The old access token must now be invalid.
	valRec := e.do(t, http.MethodPost, "/authserver/validate", map[string]any{
		"accessToken": oldAccess,
	})
	if valRec.Code != http.StatusForbidden {
		t.Errorf("validate with old token after refresh: status = %d; want 403", valRec.Code)
	}

	// The new access token must be valid.
	valRec2 := e.do(t, http.MethodPost, "/authserver/validate", map[string]any{
		"accessToken": refreshResp.AccessToken,
		"clientToken": clientToken,
	})
	if valRec2.Code != http.StatusNoContent {
		t.Errorf("validate with new token after refresh: status = %d; want 204", valRec2.Code)
	}
}

// TestRefreshSelectedProfile verifies that the refreshed token response includes
// selectedProfile when the underlying token carries a playerID.
func TestRefreshSelectedProfile(t *testing.T) {
	e := newTestEnv(t)
	createUserAndPlayer(t, e, "sp@example.com", "strongpass", "ProfiledPlayer")

	authRec := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": "sp@example.com",
		"password": "strongpass",
	})
	var authResp AuthenticateResponse
	decodeBody(t, authRec, &authResp)

	refreshRec := e.do(t, http.MethodPost, "/authserver/refresh", map[string]any{
		"accessToken": authResp.AccessToken,
		"clientToken": authResp.ClientToken,
	})
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d", refreshRec.Code)
	}
	var refreshResp RefreshResponse
	decodeBody(t, refreshRec, &refreshResp)

	if refreshResp.SelectedProfile == nil {
		t.Error("selectedProfile is nil after refresh; want the player profile")
	}
}

// TestRefreshSelectsProfileMultiPlayer reproduces the real launcher flow for an
// account that owns several players: authenticate returns availableProfiles with no
// selection, then the launcher re-sends refresh carrying the chosen profile, and the
// server must bind it and echo it back (otherwise the client reports "No profile
// selected"). It also checks that selecting a profile owned by ANOTHER user is rejected.
func TestRefreshSelectsProfileMultiPlayer(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()

	// One user with two players.
	user, err := e.accounts.AdminCreateUser(ctx, "multi@example.com", "strongpass", false)
	if err != nil {
		t.Fatalf("AdminCreateUser: %v", err)
	}
	if _, err := e.accounts.CreatePlayer(ctx, user.ID, "Alpha", ""); err != nil {
		t.Fatalf("CreatePlayer Alpha: %v", err)
	}
	chosen, err := e.accounts.CreatePlayer(ctx, user.ID, "Bravo", "")
	if err != nil {
		t.Fatalf("CreatePlayer Bravo: %v", err)
	}

	// A second, unrelated user with their own player (to test ownership enforcement).
	other, err := e.accounts.AdminCreateUser(ctx, "other@example.com", "strongpass", false)
	if err != nil {
		t.Fatalf("AdminCreateUser other: %v", err)
	}
	foreign, err := e.accounts.CreatePlayer(ctx, other.ID, "Foreign", "")
	if err != nil {
		t.Fatalf("CreatePlayer Foreign: %v", err)
	}

	// authenticate: multiple players -> no auto-selection.
	authRec := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": "multi@example.com",
		"password": "strongpass",
	})
	var authResp AuthenticateResponse
	decodeBody(t, authRec, &authResp)
	if authResp.SelectedProfile != nil {
		t.Fatalf("selectedProfile should be nil for a multi-player account, got %+v", authResp.SelectedProfile)
	}
	if len(authResp.AvailableProfiles) != 2 {
		t.Fatalf("expected 2 available profiles, got %d", len(authResp.AvailableProfiles))
	}

	// refresh selecting "Bravo" -> the response must carry that profile.
	refreshRec := e.do(t, http.MethodPost, "/authserver/refresh", map[string]any{
		"accessToken": authResp.AccessToken,
		"clientToken": authResp.ClientToken,
		"selectedProfile": map[string]any{
			"id":   undash(chosen.UUID),
			"name": chosen.Name,
		},
	})
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d", refreshRec.Code)
	}
	var refreshResp RefreshResponse
	decodeBody(t, refreshRec, &refreshResp)
	if refreshResp.SelectedProfile == nil {
		t.Fatal("selectedProfile is nil after selecting a profile; the launcher would report 'No profile selected'")
	}
	if refreshResp.SelectedProfile.Name != "Bravo" {
		t.Errorf("selectedProfile.name = %q; want Bravo", refreshResp.SelectedProfile.Name)
	}

	// The selected profile must now work for the join handshake.
	joinRec := e.do(t, http.MethodPost, "/sessionserver/session/minecraft/join", map[string]any{
		"accessToken":     refreshResp.AccessToken,
		"selectedProfile": undash(chosen.UUID),
		"serverId":        "multi-server",
	})
	if joinRec.Code != http.StatusNoContent {
		t.Errorf("join after profile selection: status = %d; want 204", joinRec.Code)
	}

	// Selecting a profile owned by ANOTHER user must be rejected.
	authRec2 := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": "multi@example.com",
		"password": "strongpass",
	})
	var authResp2 AuthenticateResponse
	decodeBody(t, authRec2, &authResp2)
	foreignRec := e.do(t, http.MethodPost, "/authserver/refresh", map[string]any{
		"accessToken": authResp2.AccessToken,
		"clientToken": authResp2.ClientToken,
		"selectedProfile": map[string]any{
			"id":   undash(foreign.UUID),
			"name": foreign.Name,
		},
	})
	if foreignRec.Code != http.StatusForbidden {
		t.Errorf("refresh selecting another user's profile: status = %d; want 403", foreignRec.Code)
	}
}

// TestInvalidate verifies that after invalidation the token is no longer valid, and a
// second invalidation of the same token still returns 204 (idempotency).
func TestInvalidate(t *testing.T) {
	e := newTestEnv(t)
	createUserAndPlayer(t, e, "inv@example.com", "strongpass", "InvPlayer")

	authRec := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": "inv@example.com",
		"password": "strongpass",
	})
	var authResp AuthenticateResponse
	decodeBody(t, authRec, &authResp)

	// Invalidate.
	invRec := e.do(t, http.MethodPost, "/authserver/invalidate", map[string]any{
		"accessToken": authResp.AccessToken,
		"clientToken": authResp.ClientToken,
	})
	if invRec.Code != http.StatusNoContent {
		t.Fatalf("invalidate status = %d; want 204", invRec.Code)
	}

	// Token should now be invalid.
	valRec := e.do(t, http.MethodPost, "/authserver/validate", map[string]any{
		"accessToken": authResp.AccessToken,
	})
	if valRec.Code != http.StatusForbidden {
		t.Errorf("validate after invalidate: status = %d; want 403", valRec.Code)
	}

	// Second invalidation is still 204 (idempotent).
	invRec2 := e.do(t, http.MethodPost, "/authserver/invalidate", map[string]any{
		"accessToken": authResp.AccessToken,
		"clientToken": authResp.ClientToken,
	})
	if invRec2.Code != http.StatusNoContent {
		t.Fatalf("second invalidate status = %d; want 204", invRec2.Code)
	}
}

// TestSignout verifies that signout invalidates all tokens for a user and that the
// invalidated tokens no longer validate.
func TestSignout(t *testing.T) {
	e := newTestEnv(t)
	createUserAndPlayer(t, e, "signout@example.com", "strongpass", "SignoutPlayer")

	// Issue two tokens for the same user.
	authRec1 := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": "signout@example.com",
		"password": "strongpass",
	})
	var a1 AuthenticateResponse
	decodeBody(t, authRec1, &a1)

	authRec2 := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": "signout@example.com",
		"password": "strongpass",
	})
	var a2 AuthenticateResponse
	decodeBody(t, authRec2, &a2)

	// Signout.
	soRec := e.do(t, http.MethodPost, "/authserver/signout", map[string]any{
		"username": "signout@example.com",
		"password": "strongpass",
	})
	if soRec.Code != http.StatusNoContent {
		t.Fatalf("signout status = %d; want 204\nbody: %s", soRec.Code, soRec.Body.String())
	}

	// Both tokens must be invalid now.
	for _, tok := range []string{a1.AccessToken, a2.AccessToken} {
		valRec := e.do(t, http.MethodPost, "/authserver/validate", map[string]any{
			"accessToken": tok,
		})
		if valRec.Code != http.StatusForbidden {
			t.Errorf("validate after signout: status = %d; want 403", valRec.Code)
		}
	}
}

// TestSignoutBadPassword verifies that signout with wrong credentials returns 403.
func TestSignoutBadPassword(t *testing.T) {
	e := newTestEnv(t)
	createUserAndPlayer(t, e, "so2@example.com", "strongpass", "So2Player")

	rec := e.do(t, http.MethodPost, "/authserver/signout", map[string]any{
		"username": "so2@example.com",
		"password": "wrongpassword",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", rec.Code)
	}
}

// TestHasJoinedUnknownServerID verifies that hasJoined with a serverId that has no
// pending join returns 204 with an empty body, which is how vanilla signals "not joined".
func TestHasJoinedUnknownServerID(t *testing.T) {
	e := newTestEnv(t)

	rec := e.do(t, http.MethodGet, "/sessionserver/session/minecraft/hasJoined?username=Ghost&serverId=no-such-server", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "" {
		t.Errorf("body = %q; want empty", body)
	}
}

// TestHasJoinedUsernameMismatch verifies that hasJoined returns 204 when the cached
// profile name does not match the requested username.
func TestHasJoinedUsernameMismatch(t *testing.T) {
	e := newTestEnv(t)
	createUserAndPlayer(t, e, "mismatch@example.com", "strongpass", "RealPlayer")

	authRec := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": "mismatch@example.com",
		"password": "strongpass",
	})
	var authResp AuthenticateResponse
	decodeBody(t, authRec, &authResp)

	e.do(t, http.MethodPost, "/sessionserver/session/minecraft/join", map[string]any{
		"accessToken":     authResp.AccessToken,
		"selectedProfile": authResp.SelectedProfile.ID,
		"serverId":        "mismatch-server",
	})

	// Ask for a different username than what was registered in the cache.
	rec := e.do(t, http.MethodGet, "/sessionserver/session/minecraft/hasJoined?username=WrongName&serverId=mismatch-server", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204 for username mismatch", rec.Code)
	}
}

// TestProfileEndpoint verifies the GET /sessionserver/session/minecraft/profile/{id}
// endpoint returns a full signed profile for a known UUID and 204 for an unknown one.
func TestProfileEndpoint(t *testing.T) {
	e := newTestEnv(t)
	_, playerUUID, playerName := createUserAndPlayer(t, e, "prof@example.com", "strongpass", "ProfPlayer")

	undashed := undash(playerUUID)

	// Known UUID: expect 200 with signed profile.
	rec := e.do(t, http.MethodGet, "/sessionserver/session/minecraft/profile/"+undashed, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("profile status = %d; want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	var profile FullProfile
	decodeBody(t, rec, &profile)
	if profile.ID != undashed {
		t.Errorf("profile.id = %q; want %q", profile.ID, undashed)
	}
	if profile.Name != playerName {
		t.Errorf("profile.name = %q; want %q", profile.Name, playerName)
	}
	if len(profile.Properties) == 0 || profile.Properties[0].Signature == "" {
		t.Error("expected signed profile; signature is empty")
	}

	// Same UUID with unsigned=true: signature must be absent.
	recU := e.do(t, http.MethodGet, "/sessionserver/session/minecraft/profile/"+undashed+"?unsigned=true", nil)
	if recU.Code != http.StatusOK {
		t.Fatalf("unsigned profile status = %d; want 200", recU.Code)
	}
	var unsignedProfile FullProfile
	decodeBody(t, recU, &unsignedProfile)
	if len(unsignedProfile.Properties) == 0 {
		t.Fatal("unsigned profile has no properties")
	}
	if unsignedProfile.Properties[0].Signature != "" {
		t.Error("unsigned profile still carries a signature; want empty")
	}

	// Unknown UUID: expect 204.
	fakeUndashed := "00000000000000000000000000000000"
	recMissing := e.do(t, http.MethodGet, "/sessionserver/session/minecraft/profile/"+fakeUndashed, nil)
	if recMissing.Code != http.StatusNoContent {
		t.Errorf("unknown profile status = %d; want 204", recMissing.Code)
	}
}

// TestProfilesBulk verifies POST /api/profiles/minecraft returns undashed IDs for known
// player names and silently skips unknown ones.
func TestProfilesBulk(t *testing.T) {
	e := newTestEnv(t)

	_, uuid1, _ := createUserAndPlayer(t, e, "bulk1@example.com", "strongpass", "BulkAlpha")
	_, uuid2, _ := createUserAndPlayer(t, e, "bulk2@example.com", "strongpass", "BulkBeta")

	rec := e.do(t, http.MethodPost, "/api/profiles/minecraft", []string{
		"BulkAlpha",
		"BulkBeta",
		"UnknownGhost",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200\nbody: %s", rec.Code, rec.Body.String())
	}

	var stubs []ProfileStub
	decodeBody(t, rec, &stubs)

	if len(stubs) != 2 {
		t.Fatalf("got %d profiles; want 2 (unknown name must be skipped)", len(stubs))
	}

	// Collect returned IDs for assertion without relying on order.
	returned := make(map[string]string) // name -> undashed id
	for _, s := range stubs {
		returned[s.Name] = s.ID
	}

	if got, ok := returned["BulkAlpha"]; !ok {
		t.Error("BulkAlpha missing from bulk response")
	} else if want := undash(uuid1); got != want {
		t.Errorf("BulkAlpha id = %q; want %q", got, want)
	}

	if got, ok := returned["BulkBeta"]; !ok {
		t.Error("BulkBeta missing from bulk response")
	} else if want := undash(uuid2); got != want {
		t.Errorf("BulkBeta id = %q; want %q", got, want)
	}

	if _, found := returned["UnknownGhost"]; found {
		t.Error("UnknownGhost should have been skipped but appeared in the response")
	}
}

// TestProfilesBulkEmpty verifies that an empty name list returns an empty JSON array,
// not null, which is the correct JSON encoding for an empty collection.
func TestProfilesBulkEmpty(t *testing.T) {
	e := newTestEnv(t)

	rec := e.do(t, http.MethodPost, "/api/profiles/minecraft", []string{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}
	body := strings.TrimSpace(rec.Body.String())
	if !strings.HasPrefix(body, "[") {
		t.Errorf("body = %q; want a JSON array (starting with [)", body)
	}
}

// TestProfilesBulkCaseInsensitive verifies that name-to-UUID lookup matches regardless
// of ASCII casing. This is the canary for player discovery by username: an admin running
// a command (e.g. /whitelist add) with a different casing than the stored profile must
// still resolve the player instead of getting a "player does not exist" error.
func TestProfilesBulkCaseInsensitive(t *testing.T) {
	e := newTestEnv(t)

	_, playerUUID, _ := createUserAndPlayer(t, e, "case@example.com", "strongpass", "CaseSensitive")

	rec := e.do(t, http.MethodPost, "/api/profiles/minecraft", []string{"casesensitive"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200\nbody: %s", rec.Code, rec.Body.String())
	}

	var stubs []ProfileStub
	decodeBody(t, rec, &stubs)

	if len(stubs) != 1 {
		t.Fatalf("got %d profiles; want 1 (case-insensitive match)", len(stubs))
	}
	if stubs[0].Name != "CaseSensitive" {
		t.Errorf("resolved name = %q; want %q (canonical casing)", stubs[0].Name, "CaseSensitive")
	}
	if stubs[0].ID != undash(playerUUID) {
		t.Errorf("resolved id = %q; want %q", stubs[0].ID, undash(playerUUID))
	}
}

// TestJoinInvalidToken verifies that join with a non-existent access token returns 403.
func TestJoinInvalidToken(t *testing.T) {
	e := newTestEnv(t)
	createUserAndPlayer(t, e, "joinbad@example.com", "strongpass", "JoinBadPlayer")

	rec := e.do(t, http.MethodPost, "/sessionserver/session/minecraft/join", map[string]any{
		"accessToken":     "this-token-does-not-exist",
		"selectedProfile": "00000000000000000000000000000000",
		"serverId":        "s1",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("join with bad token: status = %d; want 403", rec.Code)
	}
}

// TestValidateInvalidToken verifies that validate with a made-up token returns 403.
func TestValidateInvalidToken(t *testing.T) {
	e := newTestEnv(t)

	rec := e.do(t, http.MethodPost, "/authserver/validate", map[string]any{
		"accessToken": "made-up-token",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("validate with bad token: status = %d; want 403", rec.Code)
	}
}

// TestRequestUser verifies that the requestUser flag in authenticate returns the user
// object in the response.
func TestRequestUser(t *testing.T) {
	e := newTestEnv(t)
	createUserAndPlayer(t, e, "requser@example.com", "strongpass", "ReqUserPlayer")

	rec := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username":    "requser@example.com",
		"password":    "strongpass",
		"requestUser": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticate status = %d", rec.Code)
	}
	var authResp AuthenticateResponse
	decodeBody(t, rec, &authResp)

	if authResp.User == nil {
		t.Fatal("user field is nil; want a user object when requestUser is true")
	}
	if authResp.User.ID == "" {
		t.Error("user.id is empty")
	}
	if authResp.User.Properties == nil {
		t.Error("user.properties is nil; want an empty array at minimum")
	}
}

// ============================================================================
// Interop / fallback tests (Block 4 + Block 3 ForwardSkins/OfflineSkins)
// ============================================================================

// fallbackKnownProfile is the profile the fake fallback server returns for its known player.
var fallbackKnownProfile = FullProfile{
	ID:   "aaaabbbbccccddddaaaabbbbccccdddd",
	Name: "FallbackOnly",
	Properties: []TextureProperty{
		{Name: "textures", Value: "dGVzdA==", Signature: "fakesig"},
	},
}

// newFakeYggdrasilServer starts an httptest.Server that responds like a real Yggdrasil
// session + account server for fallbackKnownProfile. It counts inbound requests via
// the returned atomic counter so callers can assert cache behaviour.
func newFakeYggdrasilServer(t *testing.T) (server *httptest.Server, hits *int64) {
	t.Helper()
	var counter int64
	mux := http.NewServeMux()

	mux.HandleFunc("/session/minecraft/hasJoined", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&counter, 1)
		if r.URL.Query().Get("username") == fallbackKnownProfile.Name {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(fallbackKnownProfile)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/session/minecraft/profile/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&counter, 1)
		id := r.URL.Path[len("/session/minecraft/profile/"):]
		if id == fallbackKnownProfile.ID {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(fallbackKnownProfile)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/users/profiles/minecraft/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&counter, 1)
		name := r.URL.Path[len("/users/profiles/minecraft/"):]
		if name == fallbackKnownProfile.Name {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id":   fallbackKnownProfile.ID,
				"name": fallbackKnownProfile.Name,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &counter
}

// newTestEnvWithFallback builds a testEnv configured with a fallback server.
func newTestEnvWithFallback(t *testing.T, srv *httptest.Server, denyUnknownUsers bool) *testEnv {
	t.Helper()

	st, err := sqlite.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("creating test store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrating test store: %v", err)
	}

	policy := accounts.Policy{
		MinPasswordLength: 8,
		MaxPlayersPerUser: -1,
		PlayerNameRegex:   regexp.MustCompile(`^[a-zA-Z0-9_]{2,16}$`),
		UUIDGeneration:    "random",
		RequireInvite:     false,
	}

	svc := accounts.NewService(st, policy)
	authn := auth.NewPasswordAuthenticator(st)
	tokens := auth.NewTokenService(st, 0, nil)
	km := newTestKeyManager(t)

	enableAuth := true
	fb := fallback.NewClient([]config.FallbackAPIServer{
		{
			Nickname:             "fake",
			AccountURL:           srv.URL,
			SessionURL:           srv.URL,
			CacheTTLSeconds:      0, // no caching in most tests so we can count hits
			DenyUnknownUsers:     denyUnknownUsers,
			EnableAuthentication: &enableAuth,
		},
	})

	h := NewHandler(tokens, authn, svc, km, "TestServer", "example.com", "http://example.com",
		fb, false, false, true, true, "0.0.0-test")
	return &testEnv{handler: h.Routes(), accounts: svc, tokens: tokens}
}

// TestHasJoinedFallbackUnknownLocally verifies that hasJoined returns the fallback
// profile for a player authenticated against the fallback but unknown locally.
func TestHasJoinedFallbackUnknownLocally(t *testing.T) {
	fakeSrv, _ := newFakeYggdrasilServer(t)
	e := newTestEnvWithFallback(t, fakeSrv, false /* denyUnknownUsers=false */)

	// No local player with fallbackKnownProfile.Name exists. The fallback should serve it.
	path := "/sessionserver/session/minecraft/hasJoined?username=" +
		fallbackKnownProfile.Name + "&serverId=any-server"
	rec := e.do(t, http.MethodGet, path, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("hasJoined fallback: status = %d; want 200\nbody: %s", rec.Code, rec.Body.String())
	}

	var profile FullProfile
	decodeBody(t, rec, &profile)
	if profile.ID != fallbackKnownProfile.ID {
		t.Errorf("profile.ID = %q; want %q", profile.ID, fallbackKnownProfile.ID)
	}
	if profile.Name != fallbackKnownProfile.Name {
		t.Errorf("profile.Name = %q; want %q", profile.Name, fallbackKnownProfile.Name)
	}
}

// TestHasJoinedFallbackDenyUnknownUsersNoLocalPlayer verifies that with DenyUnknownUsers=true
// and no local player, the fallback authentication is blocked (204).
func TestHasJoinedFallbackDenyUnknownUsersNoLocalPlayer(t *testing.T) {
	fakeSrv, _ := newFakeYggdrasilServer(t)
	e := newTestEnvWithFallback(t, fakeSrv, true /* denyUnknownUsers=true */)

	path := "/sessionserver/session/minecraft/hasJoined?username=" +
		fallbackKnownProfile.Name + "&serverId=any-server"
	rec := e.do(t, http.MethodGet, path, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("hasJoined DenyUnknownUsers no local player: status = %d; want 204\nbody: %s",
			rec.Code, rec.Body.String())
	}
}

// TestHasJoinedFallbackDenyUnknownUsersWithLocalPlayer verifies that with DenyUnknownUsers=true
// and a matching local player, the fallback authentication is allowed (200).
func TestHasJoinedFallbackDenyUnknownUsersWithLocalPlayer(t *testing.T) {
	fakeSrv, _ := newFakeYggdrasilServer(t)
	e := newTestEnvWithFallback(t, fakeSrv, true /* denyUnknownUsers=true */)

	// Create a local player with the same name as the fallback's known player.
	createUserAndPlayer(t, e, "whitelist@example.com", "strongpass", fallbackKnownProfile.Name)

	path := "/sessionserver/session/minecraft/hasJoined?username=" +
		fallbackKnownProfile.Name + "&serverId=any-server"
	rec := e.do(t, http.MethodGet, path, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("hasJoined DenyUnknownUsers with local player: status = %d; want 200\nbody: %s",
			rec.Code, rec.Body.String())
	}
}

// TestProfileFallbackUnknownUUID verifies that profile/{id} for a UUID unknown locally
// returns the fallback profile when a fallback is configured.
func TestProfileFallbackUnknownUUID(t *testing.T) {
	fakeSrv, _ := newFakeYggdrasilServer(t)
	e := newTestEnvWithFallback(t, fakeSrv, false)

	rec := e.do(t, http.MethodGet,
		"/sessionserver/session/minecraft/profile/"+fallbackKnownProfile.ID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("profile fallback: status = %d; want 200\nbody: %s", rec.Code, rec.Body.String())
	}

	var profile FullProfile
	decodeBody(t, rec, &profile)
	if profile.ID != fallbackKnownProfile.ID {
		t.Errorf("profile.ID = %q; want %q", profile.ID, fallbackKnownProfile.ID)
	}
}

// TestProfileFallbackNoFallbackConfigured verifies that without a fallback, an unknown
// UUID still returns 204 (behavior unchanged from default).
func TestProfileFallbackNoFallbackConfigured(t *testing.T) {
	e := newTestEnv(t)
	rec := e.do(t, http.MethodGet,
		"/sessionserver/session/minecraft/profile/"+fallbackKnownProfile.ID, nil)
	if rec.Code != http.StatusNoContent {
		t.Errorf("profile no fallback: status = %d; want 204", rec.Code)
	}
}

// TestProfilesBulkFallbackResolves verifies that /api/profiles/minecraft resolves an
// unknown name via the fallback when configured.
func TestProfilesBulkFallbackResolves(t *testing.T) {
	fakeSrv, _ := newFakeYggdrasilServer(t)
	e := newTestEnvWithFallback(t, fakeSrv, false)

	rec := e.do(t, http.MethodPost, "/api/profiles/minecraft",
		[]string{fallbackKnownProfile.Name, "TotallyUnknown"})
	if rec.Code != http.StatusOK {
		t.Fatalf("profilesBulk fallback: status = %d; want 200\nbody: %s", rec.Code, rec.Body.String())
	}

	var stubs []ProfileStub
	decodeBody(t, rec, &stubs)

	found := false
	for _, s := range stubs {
		if s.Name == fallbackKnownProfile.Name {
			found = true
			if s.ID != fallbackKnownProfile.ID {
				t.Errorf("fallback resolved ID = %q; want %q", s.ID, fallbackKnownProfile.ID)
			}
		}
		if s.Name == "TotallyUnknown" {
			t.Error("TotallyUnknown should not appear in the result")
		}
	}
	if !found {
		t.Errorf("fallback player %q not found in bulk result", fallbackKnownProfile.Name)
	}
}

// TestProfilesBulkNoFallback verifies that without a fallback, unknown names are simply
// skipped (behavior unchanged from default).
func TestProfilesBulkNoFallback(t *testing.T) {
	e := newTestEnv(t)
	rec := e.do(t, http.MethodPost, "/api/profiles/minecraft", []string{fallbackKnownProfile.Name})
	if rec.Code != http.StatusOK {
		t.Fatalf("profilesBulk no fallback: status = %d", rec.Code)
	}
	var stubs []ProfileStub
	decodeBody(t, rec, &stubs)
	if len(stubs) != 0 {
		t.Errorf("expected empty result without fallback, got %v", stubs)
	}
}

// TestOfflineSkinsByUUID verifies that a profile/{uuid} request using the offline UUID
// of a local player returns that player's profile when OfflineSkins=true.
func TestOfflineSkinsByUUID(t *testing.T) {
	st, err := sqlite.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("creating test store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrating test store: %v", err)
	}

	policy := accounts.Policy{
		MinPasswordLength: 8,
		MaxPlayersPerUser: -1,
		PlayerNameRegex:   regexp.MustCompile(`^[a-zA-Z0-9_]{2,16}$`),
		UUIDGeneration:    "random", // player gets a RANDOM uuid, not offline uuid
		RequireInvite:     false,
	}

	svc := accounts.NewService(st, policy)
	authn := auth.NewPasswordAuthenticator(st)
	tokens := auth.NewTokenService(st, 0, nil)
	km := newTestKeyManager(t)

	// offlineSkins=true, no fallback.
	h := NewHandler(tokens, authn, svc, km, "TestServer", "example.com", "http://example.com",
		nil, false, true, true, true, "0.0.0-test")
	env := &testEnv{handler: h.Routes(), accounts: svc, tokens: tokens}

	const playerName = "OfflinePlyr"

	// Create player with a random UUID.
	ctx := context.Background()
	user, err := svc.AdminCreateUser(ctx, "offline@example.com", "strongpass", false)
	if err != nil {
		t.Fatalf("AdminCreateUser: %v", err)
	}
	player, err := svc.CreatePlayer(ctx, user.ID, playerName, "")
	if err != nil {
		t.Fatalf("CreatePlayer: %v", err)
	}

	// The player's stored UUID is random; compute the offline UUID independently.
	offlineUUID := accounts.OfflineUUID(playerName)
	offlineUndashed := undash(offlineUUID)

	// Requesting by the player's actual random UUID should work (normal path).
	recDirect := env.do(t, http.MethodGet,
		"/sessionserver/session/minecraft/profile/"+undash(player.UUID), nil)
	if recDirect.Code != http.StatusOK {
		t.Fatalf("direct UUID lookup: status = %d; want 200", recDirect.Code)
	}

	// Requesting by the offline UUID should also work when OfflineSkins=true.
	recOffline := env.do(t, http.MethodGet,
		"/sessionserver/session/minecraft/profile/"+offlineUndashed, nil)
	if recOffline.Code != http.StatusOK {
		t.Fatalf("offline UUID lookup: status = %d; want 200\nbody: %s",
			recOffline.Code, recOffline.Body.String())
	}

	var profile FullProfile
	decodeBody(t, recOffline, &profile)
	if profile.Name != playerName {
		t.Errorf("offline profile.Name = %q; want %q", profile.Name, playerName)
	}
}

// TestOfflineSkinsDisabled verifies that without OfflineSkins, requesting the offline
// UUID of a local player returns 204.
func TestOfflineSkinsDisabled(t *testing.T) {
	e := newTestEnv(t) // OfflineSkins=false by default

	const playerName = "OffDisabled"
	ctx := context.Background()
	user, err := e.accounts.AdminCreateUser(ctx, "offdis@example.com", "strongpass", false)
	if err != nil {
		t.Fatalf("AdminCreateUser: %v", err)
	}
	if _, err := e.accounts.CreatePlayer(ctx, user.ID, playerName, ""); err != nil {
		t.Fatalf("CreatePlayer: %v", err)
	}

	offlineUUID := accounts.OfflineUUID(playerName)
	offlineUndashed := undash(offlineUUID)

	rec := e.do(t, http.MethodGet,
		"/sessionserver/session/minecraft/profile/"+offlineUndashed, nil)
	if rec.Code != http.StatusNoContent {
		t.Errorf("offline UUID without OfflineSkins: status = %d; want 204", rec.Code)
	}
}

// TestForwardSkinsInjectsProperties verifies that when ForwardSkins=true and a local
// player has no skin, the fallback's properties are injected into the response.
func TestForwardSkinsInjectsProperties(t *testing.T) {
	fakeSrv, _ := newFakeYggdrasilServer(t)

	st, err := sqlite.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("creating test store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrating test store: %v", err)
	}

	policy := accounts.Policy{
		MinPasswordLength: 8,
		MaxPlayersPerUser: -1,
		PlayerNameRegex:   regexp.MustCompile(`^[a-zA-Z0-9_]{2,16}$`),
		UUIDGeneration:    "random",
	}
	svc := accounts.NewService(st, policy)
	authn := auth.NewPasswordAuthenticator(st)
	tokens := auth.NewTokenService(st, 0, nil)
	km := newTestKeyManager(t)

	enableAuth := true
	fb := fallback.NewClient([]config.FallbackAPIServer{
		{
			Nickname:             "fake",
			AccountURL:           fakeSrv.URL,
			SessionURL:           fakeSrv.URL,
			CacheTTLSeconds:      0,
			EnableAuthentication: &enableAuth,
		},
	})

	// forwardSkins=true, the local player's UUID must match what the fake server knows.
	// We use a chosen UUID matching fallbackKnownProfile.ID so the fake server returns it.
	chosenDashed := redash(fallbackKnownProfile.ID)
	h := NewHandler(tokens, authn, svc, km, "TestServer", "example.com", "http://example.com",
		fb, true /* forwardSkins */, false, true, true, "0.0.0-test")
	env := &testEnv{handler: h.Routes(), accounts: svc, tokens: tokens}

	ctx := context.Background()
	user, _ := svc.AdminCreateUser(ctx, "fwdskin@example.com", "strongpass", false)
	// Create local player with UUID matching the fake server's known profile.
	_, createErr := svc.CreatePlayer(ctx, user.ID, "LocalNoSkin", chosenDashed)
	if createErr != nil {
		t.Fatalf("creating player with chosen UUID: %v", createErr)
	}

	// Profile request: local player has no skin, ForwardSkins should inject fallback properties.
	rec := env.do(t, http.MethodGet,
		"/sessionserver/session/minecraft/profile/"+fallbackKnownProfile.ID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("forwardSkins profile: status = %d; want 200\nbody: %s", rec.Code, rec.Body.String())
	}

	// The response should carry the fallback's signature value, not our own.
	var raw struct {
		ID         string            `json:"id"`
		Name       string            `json:"name"`
		Properties []json.RawMessage `json:"properties"`
	}
	decodeBody(t, rec, &raw)
	if len(raw.Properties) == 0 {
		t.Fatal("ForwardSkins: response has no properties; want fallback properties")
	}
	// Verify the fallback's textures signature value is present (it's the marker from the fake server).
	propStr := string(raw.Properties[0])
	if !strings.Contains(propStr, "fakesig") {
		t.Errorf("ForwardSkins: expected fallback signature in properties; got: %s", propStr)
	}
}

// TestNoFallbackBehaviourUnchanged verifies that with no fallback configured, all
// lookups of unknown names/UUIDs return 204 or empty, matching the pre-interop baseline.
func TestNoFallbackBehaviourUnchanged(t *testing.T) {
	e := newTestEnv(t)

	// Unknown UUID -> 204
	rec := e.do(t, http.MethodGet,
		"/sessionserver/session/minecraft/profile/00000000000000000000000000000000", nil)
	if rec.Code != http.StatusNoContent {
		t.Errorf("unknown UUID no fallback: status = %d; want 204", rec.Code)
	}

	// Unknown hasJoined -> 204
	rec2 := e.do(t, http.MethodGet,
		"/sessionserver/session/minecraft/hasJoined?username=Ghost&serverId=nosuchserver", nil)
	if rec2.Code != http.StatusNoContent {
		t.Errorf("unknown hasJoined no fallback: status = %d; want 204", rec2.Code)
	}

	// Bulk with unknown name -> empty array
	rec3 := e.do(t, http.MethodPost, "/api/profiles/minecraft", []string{"TotallyUnknown"})
	if rec3.Code != http.StatusOK {
		t.Fatalf("bulk no fallback: status = %d", rec3.Code)
	}
	var stubs []ProfileStub
	decodeBody(t, rec3, &stubs)
	if len(stubs) != 0 {
		t.Errorf("bulk no fallback: expected empty, got %v", stubs)
	}
}

// TestPlayerCertificates is the Phase 4 canary. It verifies that:
//  1. The endpoint requires a Bearer token (401 without one).
//  2. A valid token bound to a player returns a 200 certificate bundle.
//  3. The returned PEM blocks carry the expected headers.
//  4. The v2 signature over the binary buffer (uuid ++ expiresAtMilli ++ pubDER)
//     verifies correctly against the server public key from the metadata endpoint.
func TestPlayerCertificates(t *testing.T) {
	e := newTestEnv(t)

	createUserAndPlayer(t, e, "certs@example.com", "strongpass1", "CertPlayer")

	// Authenticate to get a token with a bound profile.
	authRec := e.do(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": "certs@example.com",
		"password": "strongpass1",
	})
	if authRec.Code != http.StatusOK {
		t.Fatalf("authenticate status = %d; want 200\nbody: %s", authRec.Code, authRec.Body.String())
	}
	var authResp AuthenticateResponse
	decodeBody(t, authRec, &authResp)
	if authResp.AccessToken == "" {
		t.Fatal("accessToken is empty")
	}
	if authResp.SelectedProfile == nil {
		t.Fatal("selectedProfile is nil; need a bound profile for the certificates endpoint")
	}

	// 1. Request without any Bearer header -> expect 401.
	rec401 := httptest.NewRecorder()
	req401 := httptest.NewRequest(http.MethodPost, "/minecraftservices/player/certificates", nil)
	e.handler.ServeHTTP(rec401, req401)
	if rec401.Code != http.StatusUnauthorized {
		t.Errorf("no Bearer header: status = %d; want 401", rec401.Code)
	}

	// 2. Request with a valid Bearer token -> expect 200.
	req := httptest.NewRequest(http.MethodPost, "/minecraftservices/player/certificates", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.AccessToken)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("certificates status = %d; want 200\nbody: %s", rec.Code, rec.Body.String())
	}

	var certResp certificatesResponse
	decodeBody(t, rec, &certResp)

	// 3. Assert key material headers and non-empty signatures.
	if !strings.Contains(certResp.KeyPair.PrivateKey, "BEGIN RSA PRIVATE KEY") {
		t.Errorf("privateKey missing expected PEM header")
	}
	if !strings.Contains(certResp.KeyPair.PublicKey, "BEGIN RSA PUBLIC KEY") {
		t.Errorf("publicKey missing expected PEM header")
	}
	if certResp.PublicKeySignature == "" {
		t.Error("publicKeySignature is empty")
	}
	if certResp.PublicKeySignatureV2 == "" {
		t.Error("publicKeySignatureV2 is empty")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, certResp.ExpiresAt)
	if err != nil {
		t.Fatalf("parsing expiresAt %q: %v", certResp.ExpiresAt, err)
	}
	if _, err := time.Parse(time.RFC3339Nano, certResp.RefreshedAfter); err != nil {
		t.Fatalf("parsing refreshedAfter %q: %v", certResp.RefreshedAfter, err)
	}

	// 4. Crypto canary: reconstruct the v2 signed buffer and verify against the server
	// public key fetched from the live metadata endpoint.

	// Fetch server public key from the metadata endpoint.
	metaRec := e.do(t, http.MethodGet, "/", nil)
	var meta MetadataResponse
	decodeBody(t, metaRec, &meta)
	pemBlock, _ := pem.Decode([]byte(meta.SignaturePublickey))
	if pemBlock == nil {
		t.Fatal("signaturePublickey from metadata is not valid PEM")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing server public key from metadata: %v", err)
	}
	serverPub, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("server public key type = %T; want *rsa.PublicKey", parsedKey)
	}

	// Decode the returned ephemeral public key PEM; block.Bytes is pubDER (SPKI/PKIX).
	pubBlock, _ := pem.Decode([]byte(certResp.KeyPair.PublicKey))
	if pubBlock == nil {
		t.Fatal("keyPair.publicKey is not a valid PEM block")
	}
	pubDER := pubBlock.Bytes

	// authResp.SelectedProfile.ID is already the undashed 32-hex UUID.
	uuidBytes, err := hex.DecodeString(authResp.SelectedProfile.ID)
	if err != nil {
		t.Fatalf("hex-decoding player UUID %q: %v", authResp.SelectedProfile.ID, err)
	}
	if len(uuidBytes) != 16 {
		t.Fatalf("expected 16 UUID bytes; got %d", len(uuidBytes))
	}

	// Build the v2 buffer: uuid(16) ++ expiresAtMilli(8, big-endian) ++ pubDER.
	expiresAtMilli := expiresAt.UnixMilli()
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(expiresAtMilli))

	v2buf := make([]byte, 0, 24+len(pubDER))
	v2buf = append(v2buf, uuidBytes...)
	v2buf = append(v2buf, ts...)
	v2buf = append(v2buf, pubDER...)

	digest := sha1.Sum(v2buf)

	sigV2, err := base64.StdEncoding.DecodeString(certResp.PublicKeySignatureV2)
	if err != nil {
		t.Fatalf("base64-decoding publicKeySignatureV2: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(serverPub, crypto.SHA1, digest[:], sigV2); err != nil {
		t.Fatalf("v2 signature verification failed (SHA1withRSA/PKCS1v15): %v", err)
	}
}
