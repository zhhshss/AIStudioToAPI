const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const AuthSource = require("../auth/AuthSource");
const UsageStatsService = require("../core/UsageStatsService");
const { buildPoolConfig, PostgresSessionStore } = require("./PostgresStore");

const silentLogger = {
    debug() {},
    error() {},
    info() {},
    warn() {},
};

class MemoryPostgresStore {
    constructor() {
        this.auth = new Map();
        this.usage = [];
        this.sessions = new Map();
        this.pool = {
            query: async (sql, params = []) => {
                if (sql.includes("FROM web_sessions") && sql.includes("SELECT sess")) {
                    const session = this.sessions.get(params[0]);
                    if (!session || session.expire <= new Date()) return { rows: [] };
                    return { rows: [{ sess: session.sess }] };
                }
                if (sql.startsWith("INSERT INTO web_sessions")) {
                    this.sessions.set(params[0], { expire: params[2], sess: JSON.parse(params[1]) });
                    return { rowCount: 1, rows: [] };
                }
                if (sql.startsWith("DELETE FROM web_sessions")) {
                    this.sessions.delete(params[0]);
                    return { rowCount: 1, rows: [] };
                }
                if (sql.startsWith("UPDATE web_sessions")) {
                    const session = this.sessions.get(params[0]);
                    if (session) session.expire = params[1];
                    return { rowCount: session ? 1 : 0, rows: [] };
                }
                throw new Error(`Unexpected SQL: ${sql}`);
            },
        };
    }

    async listAuthRecords() {
        return [...this.auth.entries()].sort((a, b) => a[0] - b[0]).map(([index, payload]) => ({ index, payload }));
    }

    async upsertAuthRecord(index, payload) {
        this.auth.set(index, payload);
    }

    async deleteAuthRecord(index) {
        return this.auth.delete(index);
    }

    async listUsageRecords() {
        return [...this.usage];
    }

    async appendUsageRecord(record) {
        const requestId = record.requestId || `anon-${this.usage.length}`;
        const existing = this.usage.findIndex(item => item.requestId === requestId);
        if (existing >= 0) this.usage[existing] = record;
        else this.usage.push(record);
    }

    async replaceUsageRecords(records) {
        this.usage = [...records];
    }
}

const run = async () => {
    const originalCwd = process.cwd();
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "aistudio-pg-"));
    const authDir = path.join(tempRoot, "configs", "auth");
    const dataDir = path.join(tempRoot, "data");
    fs.mkdirSync(authDir, { recursive: true });
    fs.mkdirSync(dataDir, { recursive: true });
    process.chdir(tempRoot);

    try {
        fs.writeFileSync(
            path.join(authDir, "auth-0.json"),
            JSON.stringify({ accountName: "one@example.com", cookies: [], origins: [] }, null, 2)
        );

        const fileAuth = new AuthSource(silentLogger);
        assert.deepStrictEqual(fileAuth.availableIndices, [0]);
        const createdIndex = await fileAuth.saveNewAuthData({
            accountName: "two@example.com",
            cookies: [],
            origins: [],
        });
        assert.strictEqual(createdIndex, 1);
        assert.ok(fs.existsSync(path.join(authDir, "auth-1.json")));
        await fileAuth.markAsExpired(1);
        assert.strictEqual(fileAuth.getAuth(1).expired, true);
        await fileAuth.unmarkAsExpired(1);
        assert.strictEqual(fileAuth.getAuth(1).expired, undefined);
        await fileAuth.removeAuth(1);
        assert.deepStrictEqual(fileAuth.availableIndices, [0]);
        assert.ok(!fs.existsSync(path.join(authDir, "auth-1.json")));

        const store = new MemoryPostgresStore();
        const pgAuth = new AuthSource(silentLogger);
        await pgAuth.setStore(store);
        assert.deepStrictEqual(pgAuth.availableIndices, [0]);
        assert.strictEqual(store.auth.size, 1);

        const pgIndex = await pgAuth.saveNewAuthData({
            accountName: "pg@example.com",
            cookies: [{ name: "sid", value: "1" }],
            origins: [],
        });
        assert.strictEqual(pgIndex, 1);
        assert.strictEqual(pgAuth.getAuth(1).accountName, "pg@example.com");
        await pgAuth.markAsExpired(1);
        assert.strictEqual(store.auth.get(1).expired, true);
        await pgAuth.removeAuth(0);
        assert.deepStrictEqual(pgAuth.availableIndices, [1]);
        assert.ok(!store.auth.has(0));

        const usage = new UsageStatsService(pgAuth, silentLogger, dataDir, true);
        await usage.setStore(store);
        usage.records.push({
            durationMs: 12,
            finishedAt: "2026-08-20T00:00:00.000Z",
            outcome: "success",
            requestId: "req-1",
            sequence: 1,
        });
        usage._appendRecord(usage.records[0]);
        await usage.appendPromise;
        assert.strictEqual(store.usage.length, 1);
        const exported = await usage.exportJsonl();
        assert.ok(exported.includes("req-1"));

        const sessionStore = new PostgresSessionStore(store);
        await new Promise((resolve, reject) => {
            sessionStore.set("abc", { cookie: { maxAge: 60000 }, user: "demo" }, err =>
                err ? reject(err) : resolve()
            );
        });
        const loaded = await new Promise((resolve, reject) => {
            sessionStore.get("abc", (err, sess) => (err ? reject(err) : resolve(sess)));
        });
        assert.strictEqual(loaded.user, "demo");

        const requireConfig = buildPoolConfig("postgres://user:pass@example.com:5432/db?sslmode=require");
        assert.deepStrictEqual(requireConfig.ssl, { rejectUnauthorized: false });
        assert.ok(!requireConfig.connectionString.includes("sslmode="));

        const verifyFullConfig = buildPoolConfig("postgres://user:pass@example.com:5432/db?sslmode=verify-full");
        assert.deepStrictEqual(verifyFullConfig.ssl, { rejectUnauthorized: true });
        assert.ok(verifyFullConfig.connectionString.includes("sslmode=verify-full"));
    } finally {
        process.chdir(originalCwd);
        fs.rmSync(tempRoot, { force: true, recursive: true });
    }
};

run()
    .then(() => {
        console.log("Persistence tests passed.");
    })
    .catch(error => {
        console.error(error);
        process.exit(1);
    });
