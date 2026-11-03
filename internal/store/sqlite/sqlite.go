// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// Package sqlite implements the store interface using pure Go SQLite.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/achetronic/minecrauth/internal/store"
	_ "modernc.org/sqlite"
)

// Ensure Store implements store.Store interface.
var _ store.Store = (*Store)(nil)

// Store implements store.Store using SQLite.
type Store struct {
	db *sql.DB
}

// New opens a SQLite database at the specified path, creating its parent directory if needed.
// PRAGMAs are passed through the DSN so they apply to every connection in the database/sql
// pool. Running PRAGMA foreign_keys via a single Exec would only configure one pooled
// connection, leaving cascade deletes silently unenforced on the others.
// Ref: https://pkg.go.dev/modernc.org/sqlite#hdr-Connecting_to_a_database
func New(path string) (*Store, error) {
	if path != "" && path != ":memory:" {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create database directory %s: %w", dir, err)
		}
	}

	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}
	return nil
}

// Ping verifies the database connection is alive. Used by readiness checks.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}
	return nil
}

// Schema migrations definition.
var migrations = []string{
	// Migration 1: Create users table
	`CREATE TABLE users (
		id TEXT PRIMARY KEY,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		is_admin BOOLEAN NOT NULL DEFAULT 0,
		preferred_language TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);`,

	// Migration 2: Create players table
	`CREATE TABLE players (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL UNIQUE,
		uuid TEXT NOT NULL UNIQUE,
		created_at DATETIME NOT NULL,
		name_changed_at DATETIME,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE INDEX idx_players_user_id ON players(user_id);`,

	// Migration 3: Create yggdrasil_tokens table
	`CREATE TABLE yggdrasil_tokens (
		access_token TEXT PRIMARY KEY,
		client_token TEXT NOT NULL,
		user_id TEXT NOT NULL,
		player_id TEXT,
		created_at DATETIME NOT NULL,
		expires_at DATETIME,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (player_id) REFERENCES players(id) ON DELETE CASCADE
	);
	CREATE INDEX idx_tokens_user_id ON yggdrasil_tokens(user_id);
	CREATE INDEX idx_tokens_player_id ON yggdrasil_tokens(player_id);`,

	// Migration 4: Create invites table
	`CREATE TABLE invites (
		code TEXT PRIMARY KEY,
		created_by TEXT NOT NULL,
		used_by TEXT,
		created_at DATETIME NOT NULL,
		expires_at DATETIME,
		FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (used_by) REFERENCES users(id) ON DELETE SET NULL
	);
	CREATE INDEX idx_invites_created_by ON invites(created_by);
	CREATE INDEX idx_invites_used_by ON invites(used_by);`,

	// Migration 5: Add texture columns to players.
	// Three separate ALTER TABLE statements are needed because SQLite only allows
	// adding one column at a time per statement.
	`ALTER TABLE players ADD COLUMN skin_hash TEXT;
	ALTER TABLE players ADD COLUMN skin_model TEXT;
	ALTER TABLE players ADD COLUMN cape_hash TEXT;`,

	// Migration 6: Add blocked flag to users.
	// Default 0 (not blocked) makes the column backwards-compatible with existing rows.
	`ALTER TABLE users ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0;`,

	// Migration 7: Create browser UI sessions table.
	// Sessions are distinct from Yggdrasil access tokens and are used only by the Vue Web UI.
	`CREATE TABLE sessions (
		token TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		csrf_token TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE INDEX idx_sessions_user_id ON sessions(user_id);`,

	// Migration 8: Add the impersonated_by column to sessions.
	// Set to the real admin user id while a session is an admin impersonation; NULL otherwise.
	`ALTER TABLE sessions ADD COLUMN impersonated_by TEXT;`,

	// Migration 9: retired. This slot previously created the audit_log table for an
	// admin audit-log feature that has since been removed. The slot is intentionally
	// kept as a no-op to preserve sequential migration numbering: existing databases
	// that already ran it keep the now-orphaned audit_log table, and fresh databases
	// simply skip it. Do NOT reuse this index for a new migration.
	``,

	// Migration 10: Add email_verified to users and create auth_tokens table.
	`ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1;
	 CREATE TABLE auth_tokens (
		token_hash TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		purpose TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		used_at DATETIME,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	 );
	 CREATE INDEX idx_auth_tokens_user ON auth_tokens(user_id);`,

	// Migration 11: Add game_password_hash to users.
	`ALTER TABLE users ADD COLUMN game_password_hash TEXT NOT NULL DEFAULT '';`,

	// Migration 12: Add TOTP secret/enabled to users and create totp_recovery_codes table.
	`ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';
	 ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
	 CREATE TABLE totp_recovery_codes (
		code_hash TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		used_at DATETIME,
		created_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	 );
	 CREATE INDEX idx_totp_recovery_user ON totp_recovery_codes(user_id);`,
}

// Migrate runs schema migrations sequentially in transactions.
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to create schema_version table: %w", err)
	}

	var currentVersion int
	err = s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("failed to read schema version: %w", err)
	}

	for i, migration := range migrations {
		version := i + 1
		if version <= currentVersion {
			continue
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin migration tx for version %d: %w", version, err)
		}

		statements := strings.Split(migration, ";")
		for _, stmt := range statements {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("failed to execute migration %d statement: %w", version, err)
			}
		}

		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (?)", version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("failed to record migration version %d: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration version %d: %w", version, err)
		}
	}

	return nil
}

// mapError translates database/driver errors to store sentinel errors.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	errStr := err.Error()
	if strings.Contains(errStr, "constraint failed") || strings.Contains(errStr, "UNIQUE constraint failed") {
		return store.ErrConflict
	}
	return err
}

// CreateUser inserts a new user record.
func (s *Store) CreateUser(ctx context.Context, u *store.User) error {
	query := `INSERT INTO users (id, email, password_hash, game_password_hash, is_admin, blocked, email_verified, preferred_language, totp_secret, totp_enabled, created_at, updated_at)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, u.ID, u.Email, u.PasswordHash, u.GamePasswordHash, u.IsAdmin, u.Blocked, u.EmailVerified, u.PreferredLanguage, u.TOTPSecret, u.TOTPEnabled, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// GetUserByID retrieves a user by id.
func (s *Store) GetUserByID(ctx context.Context, id string) (*store.User, error) {
	query := `SELECT id, email, password_hash, game_password_hash, is_admin, blocked, email_verified, preferred_language, totp_secret, totp_enabled, created_at, updated_at
	          FROM users WHERE id = ?`
	u := &store.User{}
	err := s.db.QueryRowContext(ctx, query, id).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.GamePasswordHash, &u.IsAdmin, &u.Blocked, &u.EmailVerified, &u.PreferredLanguage, &u.TOTPSecret, &u.TOTPEnabled, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, mapError(err)
	}
	u.GamePasswordSet = u.GamePasswordHash != ""
	return u, nil
}

// GetUserByEmail retrieves a user by email.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	query := `SELECT id, email, password_hash, game_password_hash, is_admin, blocked, email_verified, preferred_language, totp_secret, totp_enabled, created_at, updated_at
	          FROM users WHERE email = ?`
	u := &store.User{}
	err := s.db.QueryRowContext(ctx, query, email).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.GamePasswordHash, &u.IsAdmin, &u.Blocked, &u.EmailVerified, &u.PreferredLanguage, &u.TOTPSecret, &u.TOTPEnabled, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, mapError(err)
	}
	u.GamePasswordSet = u.GamePasswordHash != ""
	return u, nil
}

// UpdateUser modifies an existing user record.
func (s *Store) UpdateUser(ctx context.Context, u *store.User) error {
	query := `UPDATE users SET email = ?, password_hash = ?, game_password_hash = ?, is_admin = ?, blocked = ?, email_verified = ?, preferred_language = ?, totp_secret = ?, totp_enabled = ?, updated_at = ?
	          WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, u.Email, u.PasswordHash, u.GamePasswordHash, u.IsAdmin, u.Blocked, u.EmailVerified, u.PreferredLanguage, u.TOTPSecret, u.TOTPEnabled, u.UpdatedAt, u.ID)
	if err != nil {
		return mapError(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeleteUser deletes a user by id.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return mapError(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ListUsers lists all users.
func (s *Store) ListUsers(ctx context.Context) ([]*store.User, error) {
	query := `SELECT id, email, password_hash, game_password_hash, is_admin, blocked, email_verified, preferred_language, totp_secret, totp_enabled, created_at, updated_at
	          FROM users ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, mapError(err)
	}
	defer func() { _ = rows.Close() }()

	users := make([]*store.User, 0)
	for rows.Next() {
		u := &store.User{}
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.GamePasswordHash, &u.IsAdmin, &u.Blocked, &u.EmailVerified, &u.PreferredLanguage, &u.TOTPSecret, &u.TOTPEnabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user row: %w", err)
		}
		u.GamePasswordSet = u.GamePasswordHash != ""
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row error: %w", err)
	}
	return users, nil
}

// CreatePlayer inserts a new player record.
func (s *Store) CreatePlayer(ctx context.Context, p *store.Player) error {
	query := `INSERT INTO players (id, user_id, name, uuid, created_at, name_changed_at, skin_hash, skin_model, cape_hash)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, p.ID, p.UserID, p.Name, p.UUID, p.CreatedAt, p.NameChangedAt, p.SkinHash, p.SkinModel, p.CapeHash)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// GetPlayerByID retrieves a player by id.
func (s *Store) GetPlayerByID(ctx context.Context, id string) (*store.Player, error) {
	query := `SELECT id, user_id, name, uuid, created_at, name_changed_at, skin_hash, skin_model, cape_hash
	          FROM players WHERE id = ?`
	p := &store.Player{}
	err := s.db.QueryRowContext(ctx, query, id).Scan(&p.ID, &p.UserID, &p.Name, &p.UUID, &p.CreatedAt, &p.NameChangedAt, &p.SkinHash, &p.SkinModel, &p.CapeHash)
	if err != nil {
		return nil, mapError(err)
	}
	return p, nil
}

// GetPlayerByName retrieves a player by name (unique, the in-game name).
// Matching is case-insensitive (ASCII) to mirror Mojang's profile lookup.
func (s *Store) GetPlayerByName(ctx context.Context, name string) (*store.Player, error) {
	query := `SELECT id, user_id, name, uuid, created_at, name_changed_at, skin_hash, skin_model, cape_hash
	          FROM players WHERE name = ? COLLATE NOCASE`
	p := &store.Player{}
	err := s.db.QueryRowContext(ctx, query, name).Scan(&p.ID, &p.UserID, &p.Name, &p.UUID, &p.CreatedAt, &p.NameChangedAt, &p.SkinHash, &p.SkinModel, &p.CapeHash)
	if err != nil {
		return nil, mapError(err)
	}
	return p, nil
}

// GetPlayerByUUID retrieves a player by their canonical profile UUID.
func (s *Store) GetPlayerByUUID(ctx context.Context, uuid string) (*store.Player, error) {
	query := `SELECT id, user_id, name, uuid, created_at, name_changed_at, skin_hash, skin_model, cape_hash
	          FROM players WHERE uuid = ?`
	p := &store.Player{}
	err := s.db.QueryRowContext(ctx, query, uuid).Scan(&p.ID, &p.UserID, &p.Name, &p.UUID, &p.CreatedAt, &p.NameChangedAt, &p.SkinHash, &p.SkinModel, &p.CapeHash)
	if err != nil {
		return nil, mapError(err)
	}
	return p, nil
}

// ListPlayersByUser lists all players owned by a User.
func (s *Store) ListPlayersByUser(ctx context.Context, userID string) ([]*store.Player, error) {
	query := `SELECT id, user_id, name, uuid, created_at, name_changed_at, skin_hash, skin_model, cape_hash
	          FROM players WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, mapError(err)
	}
	defer func() { _ = rows.Close() }()

	players := make([]*store.Player, 0)
	for rows.Next() {
		p := &store.Player{}
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.UUID, &p.CreatedAt, &p.NameChangedAt, &p.SkinHash, &p.SkinModel, &p.CapeHash); err != nil {
			return nil, fmt.Errorf("failed to scan player row: %w", err)
		}
		players = append(players, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row error: %w", err)
	}
	return players, nil
}

// ListAllPlayers returns every player record in the store.
// Used for O(n) offline-UUID reverse lookup when OfflineSkins is enabled.
func (s *Store) ListAllPlayers(ctx context.Context) ([]*store.Player, error) {
	query := `SELECT id, user_id, name, uuid, created_at, name_changed_at, skin_hash, skin_model, cape_hash
	          FROM players ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, mapError(err)
	}
	defer func() { _ = rows.Close() }()

	players := make([]*store.Player, 0)
	for rows.Next() {
		p := &store.Player{}
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.UUID, &p.CreatedAt, &p.NameChangedAt, &p.SkinHash, &p.SkinModel, &p.CapeHash); err != nil {
			return nil, fmt.Errorf("failed to scan player row: %w", err)
		}
		players = append(players, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row error: %w", err)
	}
	return players, nil
}

// UpdatePlayer modifies an existing player record.
func (s *Store) UpdatePlayer(ctx context.Context, p *store.Player) error {
	query := `UPDATE players SET user_id = ?, name = ?, uuid = ?, name_changed_at = ?, skin_hash = ?, skin_model = ?, cape_hash = ?
	          WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, p.UserID, p.Name, p.UUID, p.NameChangedAt, p.SkinHash, p.SkinModel, p.CapeHash, p.ID)
	if err != nil {
		return mapError(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeletePlayer deletes a player by id.
func (s *Store) DeletePlayer(ctx context.Context, id string) error {
	query := `DELETE FROM players WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return mapError(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// CountPlayersByUser counts the number of players owned by a User.
func (s *Store) CountPlayersByUser(ctx context.Context, userID string) (int, error) {
	query := `SELECT COUNT(*) FROM players WHERE user_id = ?`
	var count int
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&count)
	if err != nil {
		return 0, mapError(err)
	}
	return count, nil
}

// CreateToken inserts a new authentication session token.
func (s *Store) CreateToken(ctx context.Context, t *store.YggdrasilToken) error {
	query := `INSERT INTO yggdrasil_tokens (access_token, client_token, user_id, player_id, created_at, expires_at)
	          VALUES (?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, t.AccessToken, t.ClientToken, t.UserID, t.PlayerID, t.CreatedAt, t.ExpiresAt)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// GetToken retrieves an authentication session token by the access token string.
func (s *Store) GetToken(ctx context.Context, accessToken string) (*store.YggdrasilToken, error) {
	query := `SELECT access_token, client_token, user_id, player_id, created_at, expires_at
	          FROM yggdrasil_tokens WHERE access_token = ?`
	t := &store.YggdrasilToken{}
	err := s.db.QueryRowContext(ctx, query, accessToken).Scan(&t.AccessToken, &t.ClientToken, &t.UserID, &t.PlayerID, &t.CreatedAt, &t.ExpiresAt)
	if err != nil {
		return nil, mapError(err)
	}
	return t, nil
}

// DeleteToken deletes an authentication session token by access token string.
func (s *Store) DeleteToken(ctx context.Context, accessToken string) error {
	query := `DELETE FROM yggdrasil_tokens WHERE access_token = ?`
	res, err := s.db.ExecContext(ctx, query, accessToken)
	if err != nil {
		return mapError(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeleteTokensByUser deletes all authentication session tokens associated with a User.
func (s *Store) DeleteTokensByUser(ctx context.Context, userID string) error {
	query := `DELETE FROM yggdrasil_tokens WHERE user_id = ?`
	_, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// DeleteExpiredTokens deletes all expired tokens.
func (s *Store) DeleteExpiredTokens(ctx context.Context) error {
	query := `DELETE FROM yggdrasil_tokens WHERE expires_at IS NOT NULL AND expires_at < ?`
	_, err := s.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return mapError(err)
	}
	return nil
}

// CreateInvite inserts a new invite code.
func (s *Store) CreateInvite(ctx context.Context, i *store.Invite) error {
	query := `INSERT INTO invites (code, created_by, used_by, created_at, expires_at)
	          VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, i.Code, i.CreatedBy, i.UsedBy, i.CreatedAt, i.ExpiresAt)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// GetInvite retrieves an invite record by its unique code.
func (s *Store) GetInvite(ctx context.Context, code string) (*store.Invite, error) {
	query := `SELECT code, created_by, used_by, created_at, expires_at
	          FROM invites WHERE code = ?`
	i := &store.Invite{}
	err := s.db.QueryRowContext(ctx, query, code).Scan(&i.Code, &i.CreatedBy, &i.UsedBy, &i.CreatedAt, &i.ExpiresAt)
	if err != nil {
		return nil, mapError(err)
	}
	return i, nil
}

// MarkInviteUsed marks an invite code as used by a specific User.
// Returns ErrNotFound if the code does not exist, or ErrConflict if it has already been used.
func (s *Store) MarkInviteUsed(ctx context.Context, code string, userID string) error {
	query := `UPDATE invites SET used_by = ? WHERE code = ? AND used_by IS NULL`
	res, err := s.db.ExecContext(ctx, query, userID, code)
	if err != nil {
		return mapError(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		var dummy string
		err := s.db.QueryRowContext(ctx, "SELECT code FROM invites WHERE code = ?", code).Scan(&dummy)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return store.ErrNotFound
			}
			return fmt.Errorf("failed to check invite existence: %w", err)
		}
		return store.ErrConflict
	}
	return nil
}

// DeleteInvite deletes an invite code by its code string.
func (s *Store) DeleteInvite(ctx context.Context, code string) error {
	query := `DELETE FROM invites WHERE code = ?`
	res, err := s.db.ExecContext(ctx, query, code)
	if err != nil {
		return mapError(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ListInvites lists all invite records.
func (s *Store) ListInvites(ctx context.Context) ([]*store.Invite, error) {
	query := `SELECT code, created_by, used_by, created_at, expires_at
	          FROM invites ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, mapError(err)
	}
	defer func() { _ = rows.Close() }()

	invites := make([]*store.Invite, 0)
	for rows.Next() {
		i := &store.Invite{}
		if err := rows.Scan(&i.Code, &i.CreatedBy, &i.UsedBy, &i.CreatedAt, &i.ExpiresAt); err != nil {
			return nil, fmt.Errorf("failed to scan invite row: %w", err)
		}
		invites = append(invites, i)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row error: %w", err)
	}
	return invites, nil
}

// --- Session operations ---

// CreateSession inserts a new browser UI session record.
func (s *Store) CreateSession(ctx context.Context, sess *store.Session) error {
	var imp any
	if sess.ImpersonatedBy != nil {
		imp = *sess.ImpersonatedBy
	}
	query := `INSERT INTO sessions (token, user_id, csrf_token, impersonated_by, created_at, expires_at)
	          VALUES (?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, sess.Token, sess.UserID, sess.CSRFToken, imp, sess.CreatedAt, sess.ExpiresAt)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// GetSession retrieves a browser UI session by its opaque token.
func (s *Store) GetSession(ctx context.Context, token string) (*store.Session, error) {
	query := `SELECT token, user_id, csrf_token, impersonated_by, created_at, expires_at
	          FROM sessions WHERE token = ?`
	sess := &store.Session{}
	var imp sql.NullString
	err := s.db.QueryRowContext(ctx, query, token).Scan(&sess.Token, &sess.UserID, &sess.CSRFToken, &imp, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		return nil, mapError(err)
	}
	if imp.Valid {
		v := imp.String
		sess.ImpersonatedBy = &v
	}
	return sess, nil
}

// DeleteSession deletes a browser UI session by its opaque token.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	query := `DELETE FROM sessions WHERE token = ?`
	_, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// DeleteSessionsByUser deletes all browser UI sessions belonging to a user.
// Used when a user is blocked or their password changes, to force re-authentication.
func (s *Store) DeleteSessionsByUser(ctx context.Context, userID string) error {
	query := `DELETE FROM sessions WHERE user_id = ?`
	_, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// DeleteExpiredSessions deletes all sessions whose expires_at is in the past of the provided now time.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	query := `DELETE FROM sessions WHERE expires_at < ?`
	_, err := s.db.ExecContext(ctx, query, now)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// CreateAuthToken inserts a new auth token.
func (s *Store) CreateAuthToken(ctx context.Context, t *store.AuthToken) error {
	query := `INSERT INTO auth_tokens (token_hash, user_id, purpose, created_at, expires_at, used_at)
	          VALUES (?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, t.TokenHash, t.UserID, t.Purpose, t.CreatedAt, t.ExpiresAt, t.UsedAt)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// GetAuthToken retrieves an auth token by token_hash.
func (s *Store) GetAuthToken(ctx context.Context, tokenHash string) (*store.AuthToken, error) {
	query := `SELECT token_hash, user_id, purpose, created_at, expires_at, used_at
	          FROM auth_tokens WHERE token_hash = ?`
	t := &store.AuthToken{}
	err := s.db.QueryRowContext(ctx, query, tokenHash).Scan(&t.TokenHash, &t.UserID, &t.Purpose, &t.CreatedAt, &t.ExpiresAt, &t.UsedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return t, nil
}

// ConsumeAuthToken marks a token as used.
func (s *Store) ConsumeAuthToken(ctx context.Context, tokenHash string) error {
	now := time.Now()
	query := `UPDATE auth_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL`
	res, err := s.db.ExecContext(ctx, query, now, tokenHash)
	if err != nil {
		return mapError(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		// Distinguish between missing token vs already used token
		var exists bool
		checkQuery := `SELECT EXISTS(SELECT 1 FROM auth_tokens WHERE token_hash = ?)`
		err = s.db.QueryRowContext(ctx, checkQuery, tokenHash).Scan(&exists)
		if err != nil {
			return mapError(err)
		}
		if !exists {
			return store.ErrNotFound
		}
		return store.ErrConflict
	}
	return nil
}

// DeleteAuthTokensByUser removes auth tokens of a specific purpose for a user.
func (s *Store) DeleteAuthTokensByUser(ctx context.Context, userID, purpose string) error {
	query := `DELETE FROM auth_tokens WHERE user_id = ? AND purpose = ?`
	_, err := s.db.ExecContext(ctx, query, userID, purpose)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// CreateRecoveryCodes inserts a list of recovery codes in bulk.
func (s *Store) CreateRecoveryCodes(ctx context.Context, userID string, codeHashes []string) error {
	if len(codeHashes) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin tx for CreateRecoveryCodes: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	query := `INSERT INTO totp_recovery_codes (code_hash, user_id, created_at, used_at) VALUES (?, ?, ?, NULL)`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare stmt: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, hash := range codeHashes {
		if _, err := stmt.ExecContext(ctx, hash, userID, now); err != nil {
			return mapError(err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit tx for CreateRecoveryCodes: %w", err)
	}
	return nil
}

// ConsumeRecoveryCode marks a recovery code as used if it exists, is unused, and belongs to the user.
// Returns ErrNotFound if missing or already used or wrong user.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID, codeHash string) error {
	now := time.Now()
	query := `UPDATE totp_recovery_codes SET used_at = ? WHERE code_hash = ? AND user_id = ? AND used_at IS NULL`
	res, err := s.db.ExecContext(ctx, query, now, codeHash, userID)
	if err != nil {
		return mapError(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeleteRecoveryCodes deletes all recovery codes for a user.
func (s *Store) DeleteRecoveryCodes(ctx context.Context, userID string) error {
	query := `DELETE FROM totp_recovery_codes WHERE user_id = ?`
	_, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// BackupTo writes a consistent snapshot of the database to destPath using
// SQLite's VACUUM INTO, which is safe to run on a live WAL database.
func (s *Store) BackupTo(ctx context.Context, destPath string) error {
	// VACUUM INTO produces a clean, fully-consistent copy even while the DB is in use.
	// Ref: https://www.sqlite.org/lang_vacuum.html#vacuuminto
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", destPath); err != nil {
		return fmt.Errorf("backing up database to %q: %w", destPath, err)
	}
	return nil
}

// mapError translates
