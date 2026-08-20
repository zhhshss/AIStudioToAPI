/**
 * File: src/utils/PostgresStore.js
 * Description: Optional PostgreSQL persistence for auth records, usage stats, and sessions
 */

const { Pool } = require("pg");
const session = require("express-session");

const buildPoolConfig = connectionString => {
    const parsed = new URL(connectionString);
    const sslMode = String(parsed.searchParams.get("sslmode") || "").toLowerCase();
    const config = {
        connectionString,
        max: Number.parseInt(process.env.PG_POOL_MAX || "4", 10) || 4,
    };

    if (sslMode === "disable") {
        return config;
    }

    if (sslMode === "verify-full") {
        config.ssl = { rejectUnauthorized: true };
        return config;
    }

    // Aiven and similar managed Postgres providers often present a chain Node
    // does not trust by default. Keep TLS on, but do not fail the handshake.
    parsed.searchParams.delete("sslmode");
    config.connectionString = parsed.toString();
    config.ssl = { rejectUnauthorized: false };
    return config;
};

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS auth_records (
    account_index INTEGER PRIMARY KEY,
    payload JSONB NOT NULL,
    expired BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS usage_stats (
    request_id TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    finished_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS web_sessions (
    sid VARCHAR(255) PRIMARY KEY,
    sess JSONB NOT NULL,
    expire TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS web_sessions_expire_idx ON web_sessions (expire);
`;

class PostgresStore {
    constructor(connectionString, logger) {
        this.logger = logger;
        this.pool = new Pool(buildPoolConfig(connectionString));
        this.ready = this._init();
    }

    async _init() {
        await this.pool.query(SCHEMA_SQL);
        if (this.logger) this.logger.info("[Postgres] Connected and schema is ready.");
        return this;
    }

    async close() {
        await this.pool.end();
    }

    async listAuthRecords() {
        const { rows } = await this.pool.query(
            "SELECT account_index, payload FROM auth_records ORDER BY account_index ASC"
        );
        return rows.map(row => ({ index: row.account_index, payload: row.payload }));
    }

    async getAuthRecord(index) {
        const { rows } = await this.pool.query("SELECT payload FROM auth_records WHERE account_index = $1", [index]);
        return rows[0]?.payload || null;
    }

    async upsertAuthRecord(index, payload) {
        await this.pool.query(
            `INSERT INTO auth_records (account_index, payload, expired, updated_at)
             VALUES ($1, $2::jsonb, $3, NOW())
             ON CONFLICT (account_index)
             DO UPDATE SET payload = EXCLUDED.payload, expired = EXCLUDED.expired, updated_at = NOW()`,
            [index, JSON.stringify(payload), payload?.expired === true]
        );
    }

    async deleteAuthRecord(index) {
        const result = await this.pool.query("DELETE FROM auth_records WHERE account_index = $1", [index]);
        return result.rowCount > 0;
    }

    async listUsageRecords() {
        const { rows } = await this.pool.query("SELECT payload FROM usage_stats ORDER BY finished_at ASC NULLS LAST");
        return rows.map(row => row.payload);
    }

    async appendUsageRecord(record) {
        await this.pool.query(
            `INSERT INTO usage_stats (request_id, payload, finished_at)
             VALUES ($1, $2::jsonb, $3)
             ON CONFLICT (request_id)
             DO UPDATE SET payload = EXCLUDED.payload, finished_at = EXCLUDED.finished_at`,
            [record.requestId || `anon-${Date.now()}`, JSON.stringify(record), record.finishedAt || null]
        );
    }

    async replaceUsageRecords(records) {
        const client = await this.pool.connect();
        try {
            await client.query("BEGIN");
            await client.query("DELETE FROM usage_stats");
            for (const record of records) {
                await client.query(
                    `INSERT INTO usage_stats (request_id, payload, finished_at)
                     VALUES ($1, $2::jsonb, $3)`,
                    [record.requestId || `anon-${Date.now()}`, JSON.stringify(record), record.finishedAt || null]
                );
            }
            await client.query("COMMIT");
        } catch (error) {
            await client.query("ROLLBACK");
            throw error;
        } finally {
            client.release();
        }
    }
}

class PostgresSessionStore extends session.Store {
    constructor(postgresStore) {
        super();
        this.postgres = postgresStore;
    }

    get(sid, callback) {
        this.postgres.pool
            .query("SELECT sess FROM web_sessions WHERE sid = $1 AND expire > NOW()", [sid])
            .then(({ rows }) => callback(null, rows[0]?.sess || null))
            .catch(err => callback(err));
    }

    set(sid, sess, callback) {
        const maxAge = sess?.cookie?.maxAge || 604800000;
        const expire = new Date(Date.now() + maxAge);
        this.postgres.pool
            .query(
                `INSERT INTO web_sessions (sid, sess, expire)
                 VALUES ($1, $2::jsonb, $3)
                 ON CONFLICT (sid)
                 DO UPDATE SET sess = EXCLUDED.sess, expire = EXCLUDED.expire`,
                [sid, JSON.stringify(sess), expire]
            )
            .then(() => callback(null))
            .catch(err => callback(err));
    }

    destroy(sid, callback) {
        this.postgres.pool
            .query("DELETE FROM web_sessions WHERE sid = $1", [sid])
            .then(() => callback(null))
            .catch(err => callback(err));
    }

    touch(sid, sess, callback) {
        const maxAge = sess?.cookie?.maxAge || 604800000;
        const expire = new Date(Date.now() + maxAge);
        this.postgres.pool
            .query("UPDATE web_sessions SET expire = $2 WHERE sid = $1", [sid, expire])
            .then(() => callback(null))
            .catch(err => callback(err));
    }
}

const createPostgresStore = async (connectionString, logger) => {
    const store = new PostgresStore(connectionString, logger);
    await store.ready;
    return store;
};

module.exports = { buildPoolConfig, createPostgresStore, PostgresSessionStore, PostgresStore };
