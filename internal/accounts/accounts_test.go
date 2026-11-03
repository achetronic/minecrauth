// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/store"
	"github.com/achetronic/minecrauth/internal/store/sqlite"
	"github.com/pquerna/otp/totp"
)

// setupTestService creates a temporary SQLite store, migrates it, and returns a new Service.
func setupTestService(t *testing.T, p Policy) (*Service, store.Store) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	st, err := sqlite.New(dbPath)
	if err != nil {
		t.Fatalf("failed to initialize sqlite store: %v", err)
	}

	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		_ = st.Close()
		t.Fatalf("failed to migrate store: %v", err)
	}

	t.Cleanup(func() {
		_ = st.Close()
	})

	svc := NewService(st, p)
	return svc, st
}

func TestRegister(t *testing.T) {
	policy := Policy{
		MinPasswordLength: 8,
		MaxPlayersPerUser: -1,
		PlayerNameRegex:   regexp.MustCompile(`^[a-zA-Z0-9_]{3,16}$`),
		UUIDGeneration:    "random",
		RequireInvite:     false,
	}

	t.Run("successful self-service registration", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)
		ctx := context.Background()

		u, err := svc.Register(ctx, "user@example.com", "password123", "")
		if err != nil {
			t.Fatalf("expected successful registration, got: %v", err)
		}

		if u.Email != "user@example.com" {
			t.Errorf("expected email %q, got %q", "user@example.com", u.Email)
		}
		if u.PasswordHash == "password123" {
			t.Errorf("expected hashed password, but got plaintext")
		}

		// Check hash
		err = auth.CheckPassword(u.PasswordHash, "password123")
		if err != nil {
			t.Errorf("expected stored hash to be valid, got: %v", err)
		}

		// Check retrieve
		retrieved, err := svc.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("getting user failed: %v", err)
		}
		if retrieved.Email != "user@example.com" {
			t.Errorf("retrieved user mismatch")
		}
	})

	t.Run("too short password", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)
		ctx := context.Background()

		_, err := svc.Register(ctx, "user@example.com", "short", "")
		if !errors.Is(err, ErrWeakPassword) {
			t.Errorf("expected ErrWeakPassword, got: %v", err)
		}
	})

	t.Run("duplicate email registration failure", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)
		ctx := context.Background()

		_, err := svc.Register(ctx, "user@example.com", "password123", "")
		if err != nil {
			t.Fatalf("expected first registration to succeed, got: %v", err)
		}

		_, err = svc.Register(ctx, "user@example.com", "otherpassword", "")
		if !errors.Is(err, ErrEmailTaken) {
			t.Errorf("expected ErrEmailTaken, got: %v", err)
		}
	})

	t.Run("require invite checks - missing, expired, already used", func(t *testing.T) {
		invitePolicy := policy
		invitePolicy.RequireInvite = true

		svc, st := setupTestService(t, invitePolicy)
		ctx := context.Background()

		// 1. Missing/invalid invite code
		_, err := svc.Register(ctx, "user@example.com", "password123", "nonexistent")
		if !errors.Is(err, ErrInvalidInvite) {
			t.Errorf("expected ErrInvalidInvite for missing code, got: %v", err)
		}

		// Create an admin user first so we can create invites
		admin, err := svc.AdminCreateUser(ctx, "admin@example.com", "adminpass123", true)
		if err != nil {
			t.Fatalf("failed to create admin: %v", err)
		}

		// 2. Expired invite code
		expiredCode := "expired-code"
		expiredTime := time.Now().Add(-1 * time.Hour)
		expiredInvite := &store.Invite{
			Code:      expiredCode,
			CreatedBy: admin.ID,
			CreatedAt: time.Now().Add(-2 * time.Hour),
			ExpiresAt: &expiredTime,
		}
		if err := st.CreateInvite(ctx, expiredInvite); err != nil {
			t.Fatalf("failed to create expired invite: %v", err)
		}

		_, err = svc.Register(ctx, "user2@example.com", "password123", expiredCode)
		if !errors.Is(err, ErrInvalidInvite) {
			t.Errorf("expected ErrInvalidInvite for expired code, got: %v", err)
		}

		// 3. Already used invite code
		usedCode := "used-code"
		anotherUser, err := svc.AdminCreateUser(ctx, "other@example.com", "pass12345", false)
		if err != nil {
			t.Fatalf("failed to create other user: %v", err)
		}
		usedInvite := &store.Invite{
			Code:      usedCode,
			CreatedBy: admin.ID,
			UsedBy:    &anotherUser.ID,
			CreatedAt: time.Now(),
		}
		if err := st.CreateInvite(ctx, usedInvite); err != nil {
			t.Fatalf("failed to create used invite: %v", err)
		}

		_, err = svc.Register(ctx, "user3@example.com", "password123", usedCode)
		if !errors.Is(err, ErrInvalidInvite) {
			t.Errorf("expected ErrInvalidInvite for used code, got: %v", err)
		}

		// 4. Successful registration consuming invite
		validInvite, err := svc.CreateInvite(ctx, admin.ID, 1*time.Hour)
		if err != nil {
			t.Fatalf("failed to create valid invite: %v", err)
		}

		u, err := svc.Register(ctx, "success@example.com", "password123", validInvite.Code)
		if err != nil {
			t.Fatalf("expected successful registration with invite, got: %v", err)
		}

		// Verify invite marked used
		inv, err := st.GetInvite(ctx, validInvite.Code)
		if err != nil {
			t.Fatalf("failed to retrieve invite: %v", err)
		}
		if inv.UsedBy == nil || *inv.UsedBy != u.ID {
			t.Errorf("expected invite to be used by %s, got %v", u.ID, inv.UsedBy)
		}
	})
}

func TestPlayers(t *testing.T) {
	policy := Policy{
		MinPasswordLength: 8,
		MaxPlayersPerUser: 2,
		PlayerNameRegex:   regexp.MustCompile(`^[a-zA-Z0-9_]{3,16}$`),
		UUIDGeneration:    "random",
		RequireInvite:     false,
	}

	t.Run("players 1:N cardinality and max enforcement", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)
		ctx := context.Background()

		u, err := svc.Register(ctx, "user@example.com", "password123", "")
		if err != nil {
			t.Fatalf("failed to register: %v", err)
		}

		// Create player 1
		p1, err := svc.CreatePlayer(ctx, u.ID, "Steve", "")
		if err != nil {
			t.Fatalf("failed to create player 1: %v", err)
		}
		if p1.UserID != u.ID {
			t.Errorf("player user_id mismatch")
		}

		// Create player 2
		_, err = svc.CreatePlayer(ctx, u.ID, "Alex", "")
		if err != nil {
			t.Fatalf("failed to create player 2: %v", err)
		}

		// Attempt player 3 (violating MaxPlayersPerUser = 2)
		_, err = svc.CreatePlayer(ctx, u.ID, "Herobrine", "")
		if !errors.Is(err, ErrPlayerLimitReached) {
			t.Errorf("expected ErrPlayerLimitReached, got: %v", err)
		}

		// Verify players owned by user
		players, err := svc.ListPlayersByUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("failed to list players: %v", err)
		}
		if len(players) != 2 {
			t.Errorf("expected exactly 2 players, got: %d", len(players))
		}
	})

	t.Run("unlimited players with -1 limit", func(t *testing.T) {
		unlimitedPolicy := policy
		unlimitedPolicy.MaxPlayersPerUser = -1

		svc, _ := setupTestService(t, unlimitedPolicy)
		ctx := context.Background()

		u, err := svc.Register(ctx, "user@example.com", "password123", "")
		if err != nil {
			t.Fatalf("failed to register: %v", err)
		}

		for i := 0; i < 5; i++ {
			name := "Player_" + string(rune('A'+i))
			_, err := svc.CreatePlayer(ctx, u.ID, name, "")
			if err != nil {
				t.Fatalf("failed to create player %s: %v", name, err)
			}
		}
	})

	t.Run("invalid name regex validation", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)
		ctx := context.Background()

		u, err := svc.Register(ctx, "user@example.com", "password123", "")
		if err != nil {
			t.Fatalf("failed to register: %v", err)
		}

		_, err = svc.CreatePlayer(ctx, u.ID, "Jo", "") // too short (regex requires 3-16)
		if !errors.Is(err, ErrInvalidPlayerName) {
			t.Errorf("expected ErrInvalidPlayerName, got: %v", err)
		}
	})

	t.Run("duplicate player name rejection", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)
		ctx := context.Background()

		u1, err := svc.Register(ctx, "u1@example.com", "password123", "")
		if err != nil {
			t.Fatalf("failed to register u1: %v", err)
		}
		u2, err := svc.Register(ctx, "u2@example.com", "password123", "")
		if err != nil {
			t.Fatalf("failed to register u2: %v", err)
		}

		_, err = svc.CreatePlayer(ctx, u1.ID, "Steve", "")
		if err != nil {
			t.Fatalf("failed to create Steve: %v", err)
		}

		// Try to create another Steve under u2
		_, err = svc.CreatePlayer(ctx, u2.ID, "Steve", "")
		if !errors.Is(err, ErrPlayerNameTaken) {
			t.Errorf("expected ErrPlayerNameTaken, got: %v", err)
		}

		// Try to create the same name with different casing under u2; Minecraft names
		// are case-insensitively unique, so this must also be rejected.
		_, err = svc.CreatePlayer(ctx, u2.ID, "steve", "")
		if !errors.Is(err, ErrPlayerNameTaken) {
			t.Errorf("expected ErrPlayerNameTaken for case-variant name, got: %v", err)
		}
	})

	t.Run("offline profile UUID generation matching Notch/jeb_ vectors", func(t *testing.T) {
		// These are the OFFLINE-mode UUIDs derived from nameUUIDFromBytes("OfflinePlayer:"+name)
		// (version-3, MD5-based), not the premium account UUIDs Mojang assigns online.
		// Verified independently against the algorithm vanilla servers use in offline mode.
		offlinePolicy := policy
		offlinePolicy.UUIDGeneration = "offline"

		svc, _ := setupTestService(t, offlinePolicy)
		ctx := context.Background()

		u, err := svc.Register(ctx, "user@example.com", "password123", "")
		if err != nil {
			t.Fatalf("failed to register: %v", err)
		}

		pNotch, err := svc.CreatePlayer(ctx, u.ID, "Notch", "")
		if err != nil {
			t.Fatalf("failed to create Notch: %v", err)
		}
		if pNotch.UUID != "b50ad385-829d-3141-a216-7e7d7539ba7f" {
			t.Errorf("expected Notch UUID %q, got %q", "b50ad385-829d-3141-a216-7e7d7539ba7f", pNotch.UUID)
		}

		pJeb, err := svc.CreatePlayer(ctx, u.ID, "jeb_", "")
		if err != nil {
			t.Fatalf("failed to create jeb_: %v", err)
		}
		if pJeb.UUID != "a762f560-4fce-3236-812a-b80efff0b62b" {
			t.Errorf("expected jeb_ UUID %q, got %q", "a762f560-4fce-3236-812a-b80efff0b62b", pJeb.UUID)
		}
	})
}

func TestPlayerRenameAndAdminToggle(t *testing.T) {
	policy := Policy{
		MinPasswordLength: 8,
		MaxPlayersPerUser: -1,
		PlayerNameRegex:   regexp.MustCompile(`^[a-zA-Z0-9_]{3,16}$`),
		UUIDGeneration:    "random",
		RequireInvite:     false,
	}

	t.Run("RenamePlayer changes name and sets NameChangedAt", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)
		ctx := context.Background()

		u, err := svc.Register(ctx, "user@example.com", "password123", "")
		if err != nil {
			t.Fatalf("failed to register: %v", err)
		}

		p, err := svc.CreatePlayer(ctx, u.ID, "OldName", "")
		if err != nil {
			t.Fatalf("failed to create player: %v", err)
		}

		if p.NameChangedAt != nil {
			t.Fatalf("expected NameChangedAt to be nil initially")
		}

		err = svc.RenamePlayer(ctx, p.ID, "NewName")
		if err != nil {
			t.Fatalf("rename failed: %v", err)
		}

		renamed, err := svc.GetPlayer(ctx, p.ID)
		if err != nil {
			t.Fatalf("fetching player failed: %v", err)
		}

		if renamed.Name != "NewName" {
			t.Errorf("expected name %q, got %q", "NewName", renamed.Name)
		}
		if renamed.NameChangedAt == nil {
			t.Errorf("expected NameChangedAt to be set after rename")
		}
	})

	t.Run("SetAdmin toggles admin status", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)
		ctx := context.Background()

		u, err := svc.Register(ctx, "user@example.com", "password123", "")
		if err != nil {
			t.Fatalf("failed to register: %v", err)
		}

		if u.IsAdmin {
			t.Errorf("expected user not to be admin initially")
		}

		err = svc.SetAdmin(ctx, u.ID, true)
		if err != nil {
			t.Fatalf("failed to set admin status: %v", err)
		}

		updated, err := svc.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("fetching user failed: %v", err)
		}
		if !updated.IsAdmin {
			t.Errorf("expected user to be admin")
		}

		err = svc.SetAdmin(ctx, u.ID, false)
		if err != nil {
			t.Fatalf("failed to demote admin status: %v", err)
		}

		demoted, err := svc.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("fetching user failed: %v", err)
		}
		if demoted.IsAdmin {
			t.Errorf("expected user not to be admin after demotion")
		}
	})
}

func TestPasswordReset(t *testing.T) {
	policy := Policy{
		MinPasswordLength: 8,
		MaxPlayersPerUser: -1,
		PlayerNameRegex:   regexp.MustCompile(`^[a-zA-Z0-9_]{3,16}$`),
		UUIDGeneration:    "random",
		RequireInvite:     false,
	}

	ctx := context.Background()

	t.Run("successful password reset flow", func(t *testing.T) {
		svc, st := setupTestService(t, policy)

		u, err := svc.Register(ctx, "reset@example.com", "password123", "")
		if err != nil {
			t.Fatalf("expected registration to succeed: %v", err)
		}

		// 1. CreatePasswordResetToken
		plaintext, err := svc.CreatePasswordResetToken(ctx, u.ID, time.Hour)
		if err != nil {
			t.Fatalf("failed to create reset token: %v", err)
		}
		if plaintext == "" {
			t.Fatal("expected non-empty plaintext token")
		}

		// Verify row exists
		h := sha256.Sum256([]byte(plaintext))
		tokenHash := hex.EncodeToString(h[:])
		tok, err := st.GetAuthToken(ctx, tokenHash)
		if err != nil {
			t.Fatalf("expected token hash to exist in store: %v", err)
		}
		if tok.UserID != u.ID || tok.Purpose != store.AuthTokenPasswordReset {
			t.Error("stored token mismatch")
		}

		// 2. ResetPassword changes the password
		userID, err := svc.ResetPassword(ctx, plaintext, "newpassword123")
		if err != nil {
			t.Fatalf("failed to reset password: %v", err)
		}
		if userID != u.ID {
			t.Errorf("expected returned userID to be %q, got %q", u.ID, userID)
		}

		// Verify password hash was updated
		updatedUser, err := svc.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("failed to get updated user: %v", err)
		}
		err = auth.CheckPassword(updatedUser.PasswordHash, "newpassword123")
		if err != nil {
			t.Errorf("expected new password to match: %v", err)
		}

		// 3. Second ResetPassword with the same token returns ErrInvalidToken
		_, err = svc.ResetPassword(ctx, plaintext, "anotherpassword")
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("expected ErrInvalidToken on double reset, got: %v", err)
		}
	})

	t.Run("expired token returns ErrInvalidToken", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)

		u, err := svc.Register(ctx, "expired@example.com", "password123", "")
		if err != nil {
			t.Fatalf("expected registration to succeed: %v", err)
		}

		// Generate token, but insert with past ExpiresAt
		plaintext, err := svc.CreatePasswordResetToken(ctx, u.ID, -time.Hour)
		if err != nil {
			t.Fatalf("failed to create reset token: %v", err)
		}

		_, err = svc.ResetPassword(ctx, plaintext, "newpassword123")
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("expected ErrInvalidToken for expired token, got: %v", err)
		}
	})

	t.Run("weak password returns ErrWeakPassword", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)

		u, err := svc.Register(ctx, "weak@example.com", "password123", "")
		if err != nil {
			t.Fatalf("expected registration to succeed: %v", err)
		}

		plaintext, err := svc.CreatePasswordResetToken(ctx, u.ID, time.Hour)
		if err != nil {
			t.Fatalf("failed to create reset token: %v", err)
		}

		_, err = svc.ResetPassword(ctx, plaintext, "weak")
		if !errors.Is(err, ErrWeakPassword) {
			t.Errorf("expected ErrWeakPassword, got: %v", err)
		}
	})
}

func TestEmailVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("Register Policy verification flags logic", func(t *testing.T) {
		// Case 1: RequireInvite=false, RequireEmailVerification=true -> verified false
		policy1 := Policy{
			MinPasswordLength:        8,
			MaxPlayersPerUser:        -1,
			PlayerNameRegex:          regexp.MustCompile(`^[a-zA-Z0-9_]{3,16}$`),
			UUIDGeneration:           "random",
			RequireInvite:            false,
			RequireEmailVerification: true,
		}
		svc1, _ := setupTestService(t, policy1)
		u1, err := svc1.Register(ctx, "u1@example.com", "password123", "")
		if err != nil {
			t.Fatalf("unexpected register error: %v", err)
		}
		if u1.EmailVerified {
			t.Errorf("expected u1.EmailVerified to be false, got true")
		}

		// Case 2: RequireInvite=true, RequireEmailVerification=true -> verified true
		policy2 := Policy{
			MinPasswordLength:        8,
			MaxPlayersPerUser:        -1,
			PlayerNameRegex:          regexp.MustCompile(`^[a-zA-Z0-9_]{3,16}$`),
			UUIDGeneration:           "random",
			RequireInvite:            true,
			RequireEmailVerification: true,
		}
		svc2, _ := setupTestService(t, policy2)
		admin, err := svc2.AdminCreateUser(ctx, "admin@example.com", "pass12345", true)
		if err != nil {
			t.Fatalf("failed to create admin: %v", err)
		}
		inv, err := svc2.CreateInvite(ctx, admin.ID, 1*time.Hour)
		if err != nil {
			t.Fatalf("failed to create invite: %v", err)
		}
		u2, err := svc2.Register(ctx, "u2@example.com", "password123", inv.Code)
		if err != nil {
			t.Fatalf("unexpected register error: %v", err)
		}
		if !u2.EmailVerified {
			t.Errorf("expected u2.EmailVerified to be true, got false")
		}

		// Case 3: RequireInvite=false, RequireEmailVerification=false -> verified true
		policy3 := Policy{
			MinPasswordLength:        8,
			MaxPlayersPerUser:        -1,
			PlayerNameRegex:          regexp.MustCompile(`^[a-zA-Z0-9_]{3,16}$`),
			UUIDGeneration:           "random",
			RequireInvite:            false,
			RequireEmailVerification: false,
		}
		svc3, _ := setupTestService(t, policy3)
		u3, err := svc3.Register(ctx, "u3@example.com", "password123", "")
		if err != nil {
			t.Fatalf("unexpected register error: %v", err)
		}
		if !u3.EmailVerified {
			t.Errorf("expected u3.EmailVerified to be true, got false")
		}
	})

	t.Run("VerifyEmail happy path, single use, and invalid tokens", func(t *testing.T) {
		policy := Policy{
			MinPasswordLength:        8,
			MaxPlayersPerUser:        -1,
			PlayerNameRegex:          regexp.MustCompile(`^[a-zA-Z0-9_]{3,16}$`),
			UUIDGeneration:           "random",
			RequireInvite:            false,
			RequireEmailVerification: true,
		}
		svc, _ := setupTestService(t, policy)
		u, err := svc.Register(ctx, "verify@example.com", "password123", "")
		if err != nil {
			t.Fatalf("unexpected register error: %v", err)
		}

		// create verify token
		plaintext, err := svc.CreateEmailVerifyToken(ctx, u.ID, time.Hour)
		if err != nil {
			t.Fatalf("failed to create verify token: %v", err)
		}

		// check GetUserByEmail wrapping
		userByEmail, err := svc.GetUserByEmail(ctx, "verify@example.com")
		if err != nil {
			t.Fatalf("GetUserByEmail failed: %v", err)
		}
		if userByEmail.ID != u.ID {
			t.Errorf("expected user ID %s, got %s", u.ID, userByEmail.ID)
		}

		// check invalid email for GetUserByEmail
		_, err = svc.GetUserByEmail(ctx, "nonexistent@example.com")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("expected ErrNotFound for nonexistent email, got: %v", err)
		}

		// pass password_reset token to VerifyEmail -> should fail
		pwResetToken, err := svc.CreatePasswordResetToken(ctx, u.ID, time.Hour)
		if err != nil {
			t.Fatalf("failed to create pw reset token: %v", err)
		}
		_, err = svc.VerifyEmail(ctx, pwResetToken)
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("expected password reset token to fail VerifyEmail with ErrInvalidToken, got: %v", err)
		}

		// verify email with correct token
		verifiedUID, err := svc.VerifyEmail(ctx, plaintext)
		if err != nil {
			t.Fatalf("VerifyEmail failed: %v", err)
		}
		if verifiedUID != u.ID {
			t.Errorf("expected verified user ID %s, got %s", u.ID, verifiedUID)
		}

		// user in DB should now have EmailVerified = true
		uReloaded, err := svc.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("failed to reload user: %v", err)
		}
		if !uReloaded.EmailVerified {
			t.Errorf("expected reloaded user to have EmailVerified = true")
		}

		// single-use: second verify with same token should fail
		_, err = svc.VerifyEmail(ctx, plaintext)
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("expected second verify with same token to fail with ErrInvalidToken, got: %v", err)
		}
	})
}

func TestGamePassword(t *testing.T) {
	policy := Policy{
		MinPasswordLength: 8,
		MaxPlayersPerUser: -1,
		PlayerNameRegex:   regexp.MustCompile(`^[a-zA-Z0-9_]{3,16}$`),
		UUIDGeneration:    "random",
		RequireInvite:     false,
	}

	t.Run("game password management flow", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)
		ctx := context.Background()

		// 1. Register a user
		u, err := svc.Register(ctx, "gamepass@example.com", "password123", "")
		if err != nil {
			t.Fatalf("expected successful registration, got: %v", err)
		}

		// 2. Reject setting a too-short password
		err = svc.SetGamePassword(ctx, u.ID, "short")
		if !errors.Is(err, ErrWeakPassword) {
			t.Errorf("expected ErrWeakPassword, got: %v", err)
		}

		// 3. Set a valid game password
		err = svc.SetGamePassword(ctx, u.ID, "validgamepass123")
		if err != nil {
			t.Fatalf("expected successful game password set, got: %v", err)
		}

		// 4. Reload and assert hash is set and GamePasswordSet is true
		retrieved, err := svc.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("failed to retrieve user: %v", err)
		}
		if !retrieved.GamePasswordSet {
			t.Errorf("expected GamePasswordSet to be true")
		}
		if err := auth.CheckPassword(retrieved.GamePasswordHash, "validgamepass123"); err != nil {
			t.Errorf("expected game password hash to match 'validgamepass123', got: %v", err)
		}

		// 5. Clear game password
		err = svc.ClearGamePassword(ctx, u.ID)
		if err != nil {
			t.Fatalf("expected successful clear, got: %v", err)
		}

		// 6. Reload and assert removed
		cleared, err := svc.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("failed to retrieve user: %v", err)
		}
		if cleared.GamePasswordSet {
			t.Errorf("expected GamePasswordSet to be false after clear")
		}
		if cleared.GamePasswordHash != "" {
			t.Errorf("expected GamePasswordHash to be empty, got: %q", cleared.GamePasswordHash)
		}
	})
}

func TestTOTPFlows(t *testing.T) {
	policy := Policy{
		MinPasswordLength: 8,
		MaxPlayersPerUser: -1,
		PlayerNameRegex:   regexp.MustCompile(`^[a-zA-Z0-9_]{3,16}$`),
		UUIDGeneration:    "random",
		RequireInvite:     false,
	}

	t.Run("entire TOTP setup, confirm, verify, disable flow", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)
		ctx := context.Background()

		u, err := svc.Register(ctx, "totpflow@example.com", "password123", "")
		if err != nil {
			t.Fatalf("failed to register: %v", err)
		}

		// 1. Begin setup
		otpUrl, secret, err := svc.BeginTOTPSetup(ctx, u.ID)
		if err != nil {
			t.Fatalf("failed to begin totp setup: %v", err)
		}
		if secret == "" || otpUrl == "" {
			t.Errorf("expected non-empty secret and url")
		}

		// User should not be enabled yet
		user, err := svc.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if user.TOTPEnabled {
			t.Errorf("expected totp to be disabled initially")
		}

		// 2. Try confirming with invalid code
		_, err = svc.ConfirmTOTP(ctx, u.ID, "000000")
		if !errors.Is(err, ErrInvalidTOTP) {
			t.Errorf("expected ErrInvalidTOTP for bad code, got: %v", err)
		}

		// 3. Confirm with valid code
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("failed to generate code: %v", err)
		}
		recoveryCodes, err := svc.ConfirmTOTP(ctx, u.ID, code)
		if err != nil {
			t.Fatalf("failed to confirm totp: %v", err)
		}
		if len(recoveryCodes) != 10 {
			t.Errorf("expected exactly 10 recovery codes, got: %d", len(recoveryCodes))
		}

		// User should be enabled now
		user, err = svc.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if !user.TOTPEnabled {
			t.Errorf("expected totp to be enabled after confirmation")
		}

		// 4. Verify using active code
		code, err = totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("failed to generate second code: %v", err)
		}
		if err := svc.VerifyTOTP(ctx, u.ID, code); err != nil {
			t.Errorf("failed to verify valid totp code: %v", err)
		}

		// 5. Verify using recovery code
		recoveryCode := recoveryCodes[0]
		if err := svc.VerifyTOTP(ctx, u.ID, recoveryCode); err != nil {
			t.Errorf("failed to verify recovery code: %v", err)
		}

		// recovery code is single-use, should fail second time
		if err := svc.VerifyTOTP(ctx, u.ID, recoveryCode); !errors.Is(err, ErrInvalidTOTP) {
			t.Errorf("expected ErrInvalidTOTP for already consumed recovery code, got: %v", err)
		}

		// 6. Disable with wrong code
		err = svc.DisableTOTP(ctx, u.ID, "000000")
		if !errors.Is(err, ErrInvalidTOTP) {
			t.Errorf("expected ErrInvalidTOTP for wrong code on disable, got: %v", err)
		}

		// Disable with another recovery code
		err = svc.DisableTOTP(ctx, u.ID, recoveryCodes[1])
		if err != nil {
			t.Fatalf("failed to disable totp via recovery code: %v", err)
		}

		// User should be disabled now
		user, err = svc.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if user.TOTPEnabled || user.TOTPSecret != "" {
			t.Errorf("expected totp to be disabled, got enabled=%v, secret=%q", user.TOTPEnabled, user.TOTPSecret)
		}
	})

	t.Run("admin disable flow", func(t *testing.T) {
		svc, _ := setupTestService(t, policy)
		ctx := context.Background()

		u, err := svc.Register(ctx, "admin-totp@example.com", "password123", "")
		if err != nil {
			t.Fatalf("failed to register: %v", err)
		}

		_, secret, err := svc.BeginTOTPSetup(ctx, u.ID)
		if err != nil {
			t.Fatalf("failed to begin totp setup: %v", err)
		}

		code, _ := totp.GenerateCode(secret, time.Now())
		_, err = svc.ConfirmTOTP(ctx, u.ID, code)
		if err != nil {
			t.Fatalf("failed to confirm totp: %v", err)
		}

		// Force disable via admin
		err = svc.AdminDisableTOTP(ctx, u.ID)
		if err != nil {
			t.Fatalf("failed to admin-disable totp: %v", err)
		}

		user, err := svc.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if user.TOTPEnabled || user.TOTPSecret != "" {
			t.Errorf("expected totp to be disabled after admin action")
		}
	})
}
