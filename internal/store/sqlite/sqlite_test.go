// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// Package sqlite implements the store interface using pure Go SQLite.
package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/achetronic/minecrauth/internal/store"
	"github.com/google/uuid"
)

// setupTestDB creates a temporary SQLite database for testing, configures it, and migrates the schema.
func setupTestDB(t *testing.T) (*Store, string) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	s, err := New(dbPath)
	if err != nil {
		t.Fatalf("failed to initialize SQLite store: %v", err)
	}

	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		s.Close()
		t.Fatalf("failed to migrate schema: %v", err)
	}

	return s, dbPath
}

// TestMigrateIdempotency verifies that running Migrate multiple times is a safe no-op.
func TestMigrateIdempotency(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()
	// Run migrate a second time and check for failures.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("expected second migrate call to be idempotent and succeed, got: %v", err)
	}
}

// TestUserCRUD verifies creation, retrieval, updates, and deletion of users.
func TestUserCRUD(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	u := &store.User{
		ID:                uuid.NewString(),
		Email:             "test@example.com",
		PasswordHash:      "hashed_pw",
		IsAdmin:           false,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	// 1. Create User
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// 2. Retrieve User by ID
	byID, err := s.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("failed to get user by id: %v", err)
	}
	if byID.Email != u.Email {
		t.Errorf("expected email %q, got %q", u.Email, byID.Email)
	}

	// 3. Retrieve User by Email
	byEmail, err := s.GetUserByEmail(ctx, u.Email)
	if err != nil {
		t.Fatalf("failed to get user by email: %v", err)
	}
	if byEmail.ID != u.ID {
		t.Errorf("expected id %q, got %q", u.ID, byEmail.ID)
	}

	// 4. Update User
	byEmail.Email = "updated@example.com"
	byEmail.IsAdmin = true
	byEmail.PreferredLanguage = "es"
	byEmail.UpdatedAt = time.Now().UTC().Truncate(time.Second)

	if err := s.UpdateUser(ctx, byEmail); err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	updated, err := s.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if updated.Email != "updated@example.com" || !updated.IsAdmin || updated.PreferredLanguage != "es" {
		t.Errorf("user update fields not saved correctly: %+v", updated)
	}

	// 5. List Users
	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("failed to list users: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user in list, got %d", len(users))
	}

	// 6. Delete User
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}

	// 7. Verify deletion (returns ErrNotFound)
	_, err = s.GetUserByID(ctx, u.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for deleted user, got: %v", err)
	}
}

// TestGamePasswordFields verifies that GamePasswordHash and GamePasswordSet round-trip correctly.
func TestGamePasswordFields(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	u := &store.User{
		ID:                uuid.NewString(),
		Email:             "gamepass@example.com",
		PasswordHash:      "hashed_pw",
		IsAdmin:           false,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	// 1. Create a fresh user (no game password set initially).
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	fresh, err := s.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if fresh.GamePasswordSet {
		t.Errorf("expected GamePasswordSet to be false initially")
	}
	if fresh.GamePasswordHash != "" {
		t.Errorf("expected GamePasswordHash to be empty initially, got %q", fresh.GamePasswordHash)
	}

	// 2. Set game_password_hash and update.
	fresh.GamePasswordHash = "game_hashed_pw"
	if err := s.UpdateUser(ctx, fresh); err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	// 3. Reload and check GamePasswordHash round-trips and GamePasswordSet is true.
	reloaded, err := s.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("failed to reload user: %v", err)
	}
	if !reloaded.GamePasswordSet {
		t.Errorf("expected GamePasswordSet to be true after setting hash")
	}
	if reloaded.GamePasswordHash != "game_hashed_pw" {
		t.Errorf("expected GamePasswordHash to be 'game_hashed_pw', got %q", reloaded.GamePasswordHash)
	}

	// Test list users respects GamePasswordSet
	listed, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("failed to list users: %v", err)
	}
	found := false
	for _, lu := range listed {
		if lu.ID == u.ID {
			found = true
			if !lu.GamePasswordSet {
				t.Errorf("expected listed user to have GamePasswordSet=true")
			}
			if lu.GamePasswordHash != "game_hashed_pw" {
				t.Errorf("expected listed user GamePasswordHash to match")
			}
		}
	}
	if !found {
		t.Errorf("failed to find user in list")
	}
}

// TestUserConflictAndNotFound verifies database errors map correctly to store.ErrNotFound and store.ErrConflict.
func TestUserConflictAndNotFound(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()

	// 1. Get non-existent user
	_, err := s.GetUserByID(ctx, "non-existent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for non-existent ID, got: %v", err)
	}

	// 2. Create duplicate users to trigger ErrConflict
	now := time.Now().UTC()
	u1 := &store.User{
		ID:                uuid.NewString(),
		Email:             "duplicate@example.com",
		PasswordHash:      "hash",
		IsAdmin:           false,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	u2 := &store.User{
		ID:                uuid.NewString(),
		Email:             "duplicate@example.com", // same email
		PasswordHash:      "hash2",
		IsAdmin:           false,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := s.CreateUser(ctx, u1); err != nil {
		t.Fatalf("failed to create first user: %v", err)
	}

	err = s.CreateUser(ctx, u2)
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("expected ErrConflict for duplicate email, got: %v", err)
	}

	// 3. Update non-existent user should return ErrNotFound
	nonExistentUser := &store.User{
		ID:                "ghost",
		Email:             "ghost@example.com",
		PasswordHash:      "ghost",
		PreferredLanguage: "en",
		UpdatedAt:         now,
	}
	err = s.UpdateUser(ctx, nonExistentUser)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound when updating ghost user, got: %v", err)
	}

	// 4. Delete non-existent user should return ErrNotFound
	err = s.DeleteUser(ctx, "ghost")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound when deleting ghost user, got: %v", err)
	}
}

// TestPlayerCRUDAnd1N verifies player CRUD operations and the 1:N user-to-players relationship.
func TestPlayerCRUDAnd1N(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// Setup a user
	u := &store.User{
		ID:                uuid.NewString(),
		Email:             "owner@example.com",
		PasswordHash:      "hash",
		IsAdmin:           false,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to setup user: %v", err)
	}

	p1 := &store.Player{
		ID:            uuid.NewString(),
		UserID:        u.ID,
		Name:          "Steve",
		UUID:          "85a12345-1234-1234-1234-123456789abc",
		CreatedAt:     now,
		NameChangedAt: nil,
	}

	// 1. Create player
	if err := s.CreatePlayer(ctx, p1); err != nil {
		t.Fatalf("failed to create player 1: %v", err)
	}

	// 2. Retrieve player by ID, Name, UUID
	byID, err := s.GetPlayerByID(ctx, p1.ID)
	if err != nil {
		t.Fatalf("failed to get player by id: %v", err)
	}
	if byID.Name != p1.Name {
		t.Errorf("expected name %q, got %q", p1.Name, byID.Name)
	}

	byName, err := s.GetPlayerByName(ctx, p1.Name)
	if err != nil {
		t.Fatalf("failed to get player by name: %v", err)
	}
	if byName.ID != p1.ID {
		t.Errorf("expected ID %q, got %q", p1.ID, byName.ID)
	}

	byUUID, err := s.GetPlayerByUUID(ctx, p1.UUID)
	if err != nil {
		t.Fatalf("failed to get player by uuid: %v", err)
	}
	if byUUID.ID != p1.ID {
		t.Errorf("expected ID %q, got %q", p1.ID, byUUID.ID)
	}

	// 3. Create second player for the same user (1:N verification)
	p2 := &store.Player{
		ID:            uuid.NewString(),
		UserID:        u.ID,
		Name:          "Alex",
		UUID:          "12345678-1234-1234-1234-123456789def",
		CreatedAt:     now,
		NameChangedAt: nil,
	}
	if err := s.CreatePlayer(ctx, p2); err != nil {
		t.Fatalf("failed to create player 2: %v", err)
	}

	// 4. Count and list players by user
	count, err := s.CountPlayersByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("failed to count players: %v", err)
	}
	if count != 2 {
		t.Errorf("expected count to be 2, got %d", count)
	}

	list, err := s.ListPlayersByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("failed to list players: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 players in list, got %d", len(list))
	}

	// 5. Update player
	changedAt := time.Now().UTC().Truncate(time.Second)
	p1.Name = "SteveUpdated"
	p1.NameChangedAt = &changedAt
	if err := s.UpdatePlayer(ctx, p1); err != nil {
		t.Fatalf("failed to update player: %v", err)
	}

	p1Updated, err := s.GetPlayerByID(ctx, p1.ID)
	if err != nil {
		t.Fatalf("failed to fetch updated player: %v", err)
	}
	if p1Updated.Name != "SteveUpdated" || p1Updated.NameChangedAt == nil || !p1Updated.NameChangedAt.Equal(changedAt) {
		t.Errorf("player update failed to persist correctly: %+v", p1Updated)
	}

	// 6. Delete player
	if err := s.DeletePlayer(ctx, p1.ID); err != nil {
		t.Fatalf("failed to delete player: %v", err)
	}

	_, err = s.GetPlayerByID(ctx, p1.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for deleted player, got: %v", err)
	}
}

// TestGetPlayerByNameCaseInsensitive verifies that GetPlayerByName matches names
// regardless of ASCII casing, mirroring Mojang's profile lookup.
func TestGetPlayerByNameCaseInsensitive(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	u := &store.User{
		ID:                uuid.NewString(),
		Email:             "owner@example.com",
		PasswordHash:      "hash",
		IsAdmin:           false,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to setup user: %v", err)
	}

	p := &store.Player{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		Name:      "Steve",
		UUID:      "85a12345-1234-1234-1234-123456789abc",
		CreatedAt: now,
	}
	if err := s.CreatePlayer(ctx, p); err != nil {
		t.Fatalf("failed to create player: %v", err)
	}

	for _, variant := range []string{"Steve", "steve", "STEVE", "StEvE"} {
		got, err := s.GetPlayerByName(ctx, variant)
		if err != nil {
			t.Errorf("GetPlayerByName(%q): %v", variant, err)
			continue
		}
		if got.ID != p.ID {
			t.Errorf("GetPlayerByName(%q) resolved to ID %q; want %q", variant, got.ID, p.ID)
		}
	}
}

// TestPlayerConflictAndNotFound verifies player constraints and errors map correctly.
func TestPlayerConflictAndNotFound(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Get non-existent player
	_, err := s.GetPlayerByID(ctx, "non-existent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}

	// Setup user
	u := &store.User{
		ID:                uuid.NewString(),
		Email:             "owner@example.com",
		PasswordHash:      "hash",
		IsAdmin:           false,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	_ = s.CreateUser(ctx, u)

	p1 := &store.Player{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		Name:      "Steve",
		UUID:      "same-uuid",
		CreatedAt: now,
	}
	_ = s.CreatePlayer(ctx, p1)

	// 2. Duplicate Name
	pDuplicateName := &store.Player{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		Name:      "Steve", // same name
		UUID:      "different-uuid",
		CreatedAt: now,
	}
	err = s.CreatePlayer(ctx, pDuplicateName)
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("expected ErrConflict for duplicate name, got: %v", err)
	}

	// 3. Duplicate UUID
	pDuplicateUUID := &store.Player{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		Name:      "SteveDifferent",
		UUID:      "same-uuid", // same uuid
		CreatedAt: now,
	}
	err = s.CreatePlayer(ctx, pDuplicateUUID)
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("expected ErrConflict for duplicate UUID, got: %v", err)
	}
}

// TestTokenOperations verifies creating, fetching, deleting, and expiring tokens.
func TestTokenOperations(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// Setup structures
	u := &store.User{
		ID:                uuid.NewString(),
		Email:             "owner@example.com",
		PasswordHash:      "hash",
		IsAdmin:           false,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	_ = s.CreateUser(ctx, u)

	p := &store.Player{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		Name:      "Steve",
		UUID:      "steve-uuid",
		CreatedAt: now,
	}
	_ = s.CreatePlayer(ctx, p)

	// 1. Create a non-expiring token
	t1 := &store.YggdrasilToken{
		AccessToken: "access-token-1",
		ClientToken: "client-token-1",
		UserID:      u.ID,
		PlayerID:    &p.ID,
		CreatedAt:   now,
		ExpiresAt:   nil,
	}
	if err := s.CreateToken(ctx, t1); err != nil {
		t.Fatalf("failed to create token 1: %v", err)
	}

	// 2. Get token
	fetched, err := s.GetToken(ctx, t1.AccessToken)
	if err != nil {
		t.Fatalf("failed to get token: %v", err)
	}
	if fetched.ClientToken != t1.ClientToken || *fetched.PlayerID != p.ID {
		t.Errorf("fetched token mismatch: %+v", fetched)
	}

	// 3. Create an expired token
	past := now.Add(-10 * time.Minute)
	t2 := &store.YggdrasilToken{
		AccessToken: "access-token-expired",
		ClientToken: "client-token-2",
		UserID:      u.ID,
		PlayerID:    nil, // unselected profile
		CreatedAt:   past,
		ExpiresAt:   &past,
	}
	if err := s.CreateToken(ctx, t2); err != nil {
		t.Fatalf("failed to create expired token: %v", err)
	}

	// 4. Delete expired tokens
	if err := s.DeleteExpiredTokens(ctx); err != nil {
		t.Fatalf("failed to delete expired tokens: %v", err)
	}

	// Verify t1 (non-expiring) is still there, t2 (expired) is gone
	_, err = s.GetToken(ctx, t1.AccessToken)
	if err != nil {
		t.Errorf("non-expired token was mistakenly deleted: %v", err)
	}

	_, err = s.GetToken(ctx, t2.AccessToken)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for expired token, got: %v", err)
	}

	// 5. Delete token (explicit single deletion)
	if err := s.DeleteToken(ctx, t1.AccessToken); err != nil {
		t.Fatalf("failed to delete token: %v", err)
	}
	_, err = s.GetToken(ctx, t1.AccessToken)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound after deleting token, got: %v", err)
	}
}

// TestDeleteTokensByUser verifies deleting all active user tokens (signout).
func TestDeleteTokensByUser(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	u := &store.User{
		ID:                uuid.NewString(),
		Email:             "owner@example.com",
		PasswordHash:      "hash",
		IsAdmin:           false,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	_ = s.CreateUser(ctx, u)

	t1 := &store.YggdrasilToken{
		AccessToken: "token-a",
		ClientToken: "client-a",
		UserID:      u.ID,
		CreatedAt:   now,
	}
	t2 := &store.YggdrasilToken{
		AccessToken: "token-b",
		ClientToken: "client-b",
		UserID:      u.ID,
		CreatedAt:   now,
	}
	_ = s.CreateToken(ctx, t1)
	_ = s.CreateToken(ctx, t2)

	// Perform user-level token wipeout
	if err := s.DeleteTokensByUser(ctx, u.ID); err != nil {
		t.Fatalf("failed to delete tokens by user: %v", err)
	}

	// Verify both tokens are deleted
	_, err := s.GetToken(ctx, "token-a")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for token-a, got: %v", err)
	}
	_, err = s.GetToken(ctx, "token-b")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for token-b, got: %v", err)
	}
}

// TestInviteOperations verifies invite codes CRUD and usage state validation.
func TestInviteOperations(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// Setup users
	admin := &store.User{
		ID:                uuid.NewString(),
		Email:             "admin@example.com",
		PasswordHash:      "hash",
		IsAdmin:           true,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	_ = s.CreateUser(ctx, admin)

	invitee := &store.User{
		ID:                uuid.NewString(),
		Email:             "invitee@example.com",
		PasswordHash:      "hash",
		IsAdmin:           false,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	_ = s.CreateUser(ctx, invitee)

	expiry := now.Add(24 * time.Hour)
	invite := &store.Invite{
		Code:      "WELCOME2026",
		CreatedBy: admin.ID,
		UsedBy:    nil,
		CreatedAt: now,
		ExpiresAt: &expiry,
	}

	// 1. Create Invite
	if err := s.CreateInvite(ctx, invite); err != nil {
		t.Fatalf("failed to create invite: %v", err)
	}

	// 2. Fetch Invite
	fetched, err := s.GetInvite(ctx, invite.Code)
	if err != nil {
		t.Fatalf("failed to get invite: %v", err)
	}
	if fetched.CreatedBy != admin.ID || fetched.UsedBy != nil {
		t.Errorf("fetched invite metadata invalid: %+v", fetched)
	}

	// 3. Mark Invite Used (Success)
	if err := s.MarkInviteUsed(ctx, invite.Code, invitee.ID); err != nil {
		t.Fatalf("failed to mark invite as used: %v", err)
	}

	// 4. Verify invite is marked used
	used, err := s.GetInvite(ctx, invite.Code)
	if err != nil {
		t.Fatalf("failed to get invite after use: %v", err)
	}
	if used.UsedBy == nil || *used.UsedBy != invitee.ID {
		t.Errorf("expected UsedBy to be %q, got: %+v", invitee.ID, used.UsedBy)
	}

	// 5. Try to use it again (returns ErrConflict)
	err = s.MarkInviteUsed(ctx, invite.Code, invitee.ID)
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("expected ErrConflict when using already-used invite, got: %v", err)
	}

	// 6. Try to use a non-existent invite (returns ErrNotFound)
	err = s.MarkInviteUsed(ctx, "NONEXISTENT", invitee.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for non-existent invite, got: %v", err)
	}

	// 7. List invites
	list, err := s.ListInvites(ctx)
	if err != nil {
		t.Fatalf("failed to list invites: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 invite, got %d", len(list))
	}

	// 8. Delete invite
	if err := s.DeleteInvite(ctx, invite.Code); err != nil {
		t.Fatalf("failed to delete invite: %v", err)
	}
	_, err = s.GetInvite(ctx, invite.Code)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound after deleting invite, got: %v", err)
	}
}

// TestOnDeleteCascade verifies deleting a user removes associated players and tokens automatically.
func TestOnDeleteCascade(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Create a user
	u := &store.User{
		ID:                uuid.NewString(),
		Email:             "cascade@example.com",
		PasswordHash:      "hash",
		IsAdmin:           false,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	_ = s.CreateUser(ctx, u)

	// 2. Create players belonging to the user
	p := &store.Player{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		Name:      "SteveCascade",
		UUID:      "cascade-uuid",
		CreatedAt: now,
	}
	_ = s.CreatePlayer(ctx, p)

	// 3. Create tokens belonging to the user/player
	t1 := &store.YggdrasilToken{
		AccessToken: "token-cascade",
		ClientToken: "client-cascade",
		UserID:      u.ID,
		PlayerID:    &p.ID,
		CreatedAt:   now,
	}
	_ = s.CreateToken(ctx, t1)

	// Confirm elements exist first
	if _, err := s.GetPlayerByID(ctx, p.ID); err != nil {
		t.Fatalf("pre-condition failed, player not found: %v", err)
	}
	if _, err := s.GetToken(ctx, t1.AccessToken); err != nil {
		t.Fatalf("pre-condition failed, token not found: %v", err)
	}

	// 4. Delete the User
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}

	// 5. Verify players and tokens are gone automatically
	_, err := s.GetPlayerByID(ctx, p.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected player to be deleted on cascade, got: %v", err)
	}

	_, err = s.GetToken(ctx, t1.AccessToken)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected token to be deleted on cascade, got: %v", err)
	}
}

func TestStore_AuthTokens(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()

	// Create user for foreign key constraint
	u := &store.User{
		ID:                uuid.NewString(),
		Email:             "token-test@example.com",
		PasswordHash:      "hash",
		IsAdmin:           false,
		Blocked:           false,
		EmailVerified:     true,
		PreferredLanguage: "en",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	now := time.Now()
	tok := &store.AuthToken{
		TokenHash: "hash123",
		UserID:    u.ID,
		Purpose:   store.AuthTokenPasswordReset,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		UsedAt:    nil,
	}

	// 1. CreateAuthToken
	if err := s.CreateAuthToken(ctx, tok); err != nil {
		t.Fatalf("failed to create auth token: %v", err)
	}

	// 2. GetAuthToken
	retrieved, err := s.GetAuthToken(ctx, "hash123")
	if err != nil {
		t.Fatalf("failed to get auth token: %v", err)
	}
	if retrieved.UserID != u.ID || retrieved.Purpose != store.AuthTokenPasswordReset {
		t.Errorf("retrieved token mismatch")
	}

	// 2b. Get missing token -> ErrNotFound
	_, err = s.GetAuthToken(ctx, "missing_hash")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing token, got: %v", err)
	}

	// 3. ConsumeAuthToken
	if err := s.ConsumeAuthToken(ctx, "hash123"); err != nil {
		t.Fatalf("failed to consume auth token: %v", err)
	}

	// 4. Consume twice -> ErrConflict
	err = s.ConsumeAuthToken(ctx, "hash123")
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("expected ErrConflict on double consume, got: %v", err)
	}

	// Consume missing -> ErrNotFound
	err = s.ConsumeAuthToken(ctx, "missing_hash")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound on missing consume, got: %v", err)
	}

	// 5. DeleteAuthTokensByUser
	tok2 := &store.AuthToken{
		TokenHash: "hash456",
		UserID:    u.ID,
		Purpose:   store.AuthTokenPasswordReset,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		UsedAt:    nil,
	}
	if err := s.CreateAuthToken(ctx, tok2); err != nil {
		t.Fatalf("failed to create second auth token: %v", err)
	}

	if err := s.DeleteAuthTokensByUser(ctx, u.ID, store.AuthTokenPasswordReset); err != nil {
		t.Fatalf("failed to delete auth tokens by user: %v", err)
	}

	_, err = s.GetAuthToken(ctx, "hash456")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected token to be deleted, got: %v", err)
	}
}

func TestBackupTo(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()

	// Seed some users
	u1 := &store.User{
		ID:           "user-1",
		Email:        "user1@example.com",
		PasswordHash: "hash-1",
		IsAdmin:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateUser(ctx, u1); err != nil {
		t.Fatalf("failed to seed user 1: %v", err)
	}

	u2 := &store.User{
		ID:           "user-2",
		Email:        "user2@example.com",
		PasswordHash: "hash-2",
		IsAdmin:      false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateUser(ctx, u2); err != nil {
		t.Fatalf("failed to seed user 2: %v", err)
	}

	// Backup to a temp path
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "backup.db")

	if err := s.BackupTo(ctx, backupPath); err != nil {
		t.Fatalf("failed to backup: %v", err)
	}

	// Open the snapshot as a new sqlite store
	backupStore, err := New(backupPath)
	if err != nil {
		t.Fatalf("failed to open backup store: %v", err)
	}
	defer backupStore.Close()

	// Verify the users are present
	gotU1, err := backupStore.GetUserByID(ctx, "user-1")
	if err != nil {
		t.Fatalf("failed to retrieve user 1 from backup: %v", err)
	}
	if gotU1.Email != "user1@example.com" {
		t.Errorf("expected user 1 email %q, got %q", "user1@example.com", gotU1.Email)
	}

	gotU2, err := backupStore.GetUserByID(ctx, "user-2")
	if err != nil {
		t.Fatalf("failed to retrieve user 2 from backup: %v", err)
	}
	if gotU2.Email != "user2@example.com" {
		t.Errorf("expected user 2 email %q, got %q", "user2@example.com", gotU2.Email)
	}
}

func TestTOTPAndRecoveryCodes(t *testing.T) {
	s, _ := setupTestDB(t)
	defer s.Close()

	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	u := &store.User{
		ID:                uuid.NewString(),
		Email:             "totp@example.com",
		PasswordHash:      "hashed_pw",
		IsAdmin:           false,
		PreferredLanguage: "en",
		TOTPSecret:        "SECRET32",
		TOTPEnabled:       true,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	// 1. Create User with TOTP fields
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// 2. Retrieve and check
	byID, err := s.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("failed to retrieve user: %v", err)
	}
	if byID.TOTPSecret != "SECRET32" || !byID.TOTPEnabled {
		t.Errorf("TOTP fields mismatch, got secret: %q, enabled: %v", byID.TOTPSecret, byID.TOTPEnabled)
	}

	// 3. Update fields
	byID.TOTPSecret = ""
	byID.TOTPEnabled = false
	if err := s.UpdateUser(ctx, byID); err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	byID2, err := s.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("failed to retrieve user: %v", err)
	}
	if byID2.TOTPSecret != "" || byID2.TOTPEnabled {
		t.Errorf("expected TOTP fields to be cleared, got secret: %q, enabled: %v", byID2.TOTPSecret, byID2.TOTPEnabled)
	}

	// 4. Create Recovery Codes
	hashes := []string{"hash1", "hash2", "hash3"}
	if err := s.CreateRecoveryCodes(ctx, u.ID, hashes); err != nil {
		t.Fatalf("failed to create recovery codes: %v", err)
	}

	// 5. Consume recovery code once
	if err := s.ConsumeRecoveryCode(ctx, u.ID, "hash1"); err != nil {
		t.Fatalf("failed to consume recovery code: %v", err)
	}

	// 6. Consume again -> ErrNotFound
	if err := s.ConsumeRecoveryCode(ctx, u.ID, "hash1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for already used code, got: %v", err)
	}

	// Consume for wrong user -> ErrNotFound
	if err := s.ConsumeRecoveryCode(ctx, "other-user", "hash2"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for wrong user, got: %v", err)
	}

	// 7. Delete recovery codes
	if err := s.DeleteRecoveryCodes(ctx, u.ID); err != nil {
		t.Fatalf("failed to delete recovery codes: %v", err)
	}

	// Consume remaining should fail now
	if err := s.ConsumeRecoveryCode(ctx, u.ID, "hash2"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound after deletion, got: %v", err)
	}
}
