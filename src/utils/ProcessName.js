/**
 * File: src/utils/ProcessName.js
 * Description: Generate a per-boot generic process name for the Node runtime
 */

const crypto = require("crypto");

const PREFIXES = ["worker", "runtime", "service", "daemon", "agent", "task", "helper"];

const randomToken = (length = 8) => crypto.randomBytes(Math.ceil(length / 2)).toString("hex").slice(0, length);

const createProcessName = () => {
    const configured = String(process.env.PROCESS_NAME || "").trim();
    if (configured) return configured.slice(0, 15);
    const prefix = PREFIXES[crypto.randomInt(PREFIXES.length)];
    return `${prefix}-${randomToken(6)}`.slice(0, 15);
};

const applyProcessName = name => {
    const nextName = String(name || createProcessName()).slice(0, 15);
    process.title = nextName;
    process.env.PROCESS_NAME = nextName;
    return nextName;
};

module.exports = { applyProcessName, createProcessName };
