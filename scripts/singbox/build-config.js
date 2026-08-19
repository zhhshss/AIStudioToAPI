#!/usr/bin/env node

const fs = require("fs");
const http = require("http");
const https = require("https");
const path = require("path");
const YAML = require("yaml");

const GOOGLE_DOMAINS = [
    "ai.studio",
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "gstatic.com",
    "ggpht.com",
    "youtube.com",
    "youtube-nocookie.com",
    "googlevideo.com",
    "ytimg.com",
];
const RESERVED_OUTBOUND_TYPES = new Set(["block", "direct", "dns"]);

const fail = message => {
    throw new Error(`[Sing-box] ${message}`);
};

const parseInteger = (value, fallback) => {
    const parsed = Number.parseInt(value, 10);
    return Number.isInteger(parsed) && parsed > 0 && parsed <= 65535 ? parsed : fallback;
};

const parsePositiveInteger = (value, fallback, maximum = Number.MAX_SAFE_INTEGER) => {
    const parsed = Number.parseInt(value, 10);
    return Number.isInteger(parsed) && parsed > 0 && parsed <= maximum ? parsed : fallback;
};

const decodeBase64 = value => {
    const normalized = String(value).trim().replace(/-/g, "+").replace(/_/g, "/");
    if (!normalized || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) return null;

    try {
        const decoded = Buffer.from(normalized, "base64").toString("utf8").trim();
        return decoded && /[\x20-\x7e\r\n\t]/.test(decoded) ? decoded : null;
    } catch {
        return null;
    }
};

const fetchText = (urlValue, headers = {}, redirectsLeft = 5) =>
    new Promise((resolve, reject) => {
        let parsed;
        try {
            parsed = new URL(urlValue);
        } catch {
            reject(new Error("subscription URL is invalid"));
            return;
        }

        if (!new Set(["http:", "https:"]).has(parsed.protocol)) {
            reject(new Error("subscription URL must use http or https"));
            return;
        }

        const client = parsed.protocol === "https:" ? https : http;
        const request = client.get(
            parsed,
            {
                headers: {
                    "user-agent": "sing-box",
                    ...headers,
                },
                timeout: parsePositiveInteger(process.env.SINGBOX_SUBSCRIPTION_TIMEOUT_MS, 15000, 120000),
            },
            response => {
                if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                    response.resume();
                    if (redirectsLeft === 0) {
                        reject(new Error("subscription URL redirected too many times"));
                        return;
                    }
                    resolve(fetchText(new URL(response.headers.location, parsed).toString(), headers, redirectsLeft - 1));
                    return;
                }

                if (response.statusCode < 200 || response.statusCode >= 300) {
                    response.resume();
                    reject(new Error(`subscription request returned HTTP ${response.statusCode}`));
                    return;
                }

                const chunks = [];
                let size = 0;
                const maxBytes = parsePositiveInteger(
                    process.env.SINGBOX_SUBSCRIPTION_MAX_BYTES,
                    4 * 1024 * 1024,
                    32 * 1024 * 1024
                );
                response.on("data", chunk => {
                    size += chunk.length;
                    if (size > maxBytes) {
                        request.destroy(new Error("subscription response is too large"));
                        return;
                    }
                    chunks.push(chunk);
                });
                response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
            }
        );
        request.on("timeout", () => request.destroy(new Error("subscription request timed out")));
        request.on("error", reject);
    });

const parseJson = value => {
    try {
        return JSON.parse(value);
    } catch {
        return null;
    }
};

const uniqueTag = (candidate, usedTags) => {
    const base = String(candidate || "node")
        .trim()
        .replace(/[^A-Za-z0-9_.-]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 64) || "node";
    let tag = base;
    let suffix = 2;
    while (usedTags.has(tag)) {
        tag = `${base}-${suffix++}`;
    }
    usedTags.add(tag);
    return tag;
};

const tlsFromQuery = (query, fallbackServerName) => {
    const security = query.get("security");
    const enabled = security === "tls" || security === "reality" || query.get("tls") === "1";
    if (!enabled) return undefined;

    const tls = {
        enabled: true,
        server_name: query.get("sni") || query.get("peer") || fallbackServerName,
    };
    if (query.get("allowInsecure") === "1" || query.get("insecure") === "1") tls.insecure = true;
    if (query.get("alpn")) tls.alpn = query.get("alpn").split(",").filter(Boolean);
    if (query.get("fp")) tls.utls = { enabled: true, fingerprint: query.get("fp") };
    if (security === "reality") {
        tls.reality = {
            enabled: true,
            public_key: query.get("pbk") || "",
            short_id: query.get("sid") || "",
        };
    }
    return tls;
};

const transportFromQuery = query => {
    const type = query.get("type") || query.get("network");
    if (!type || type === "tcp") return undefined;

    if (type === "ws") {
        const transport = { type: "ws", path: query.get("path") || "/" };
        const host = query.get("host");
        if (host) transport.headers = { Host: host };
        return transport;
    }
    if (type === "grpc") {
        return { type: "grpc", service_name: query.get("serviceName") || query.get("service_name") || "" };
    }
    if (type === "http" || type === "h2") {
        return {
            type: "http",
            host: query.get("host") ? query.get("host").split(",") : undefined,
            path: query.get("path") || "/",
        };
    }
    if (type === "httpupgrade") {
        const transport = { type: "httpupgrade", path: query.get("path") || "/" };
        if (query.get("host")) transport.host = query.get("host");
        return transport;
    }
    return undefined;
};

const parseStandardUri = (line, usedTags) => {
    const uri = new URL(line);
    const type = uri.protocol.slice(0, -1).toLowerCase();
    const tag = uniqueTag(decodeURIComponent(uri.hash.slice(1)) || type, usedTags);
    const server = uri.hostname;
    const serverPort = Number.parseInt(uri.port, 10);
    if (!server || !serverPort) fail(`invalid ${type} subscription URI`);

    const common = { server, server_port: serverPort, tag, type };
    if (type === "vless" || type === "vmess") {
        const outbound = { ...common, uuid: decodeURIComponent(uri.username) };
        if (type === "vless" && uri.searchParams.get("flow")) outbound.flow = uri.searchParams.get("flow");
        if (type === "vmess") outbound.security = uri.searchParams.get("encryption") || "auto";
        const tls = tlsFromQuery(uri.searchParams, server);
        const transport = transportFromQuery(uri.searchParams);
        if (tls) outbound.tls = tls;
        if (transport) outbound.transport = transport;
        if (uri.searchParams.get("packetEncoding")) outbound.packet_encoding = uri.searchParams.get("packetEncoding");
        return outbound;
    }
    if (type === "trojan") {
        const outbound = { ...common, password: decodeURIComponent(uri.username) };
        outbound.tls = tlsFromQuery(uri.searchParams, server) || { enabled: true, server_name: server };
        const transport = transportFromQuery(uri.searchParams);
        if (transport) outbound.transport = transport;
        return outbound;
    }
    if (type === "hysteria2" || type === "hy2") {
        const outbound = {
            ...common,
            password: decodeURIComponent(uri.username || uri.password),
            tls: tlsFromQuery(uri.searchParams, server) || { enabled: true, server_name: uri.searchParams.get("sni") || server },
            type: "hysteria2",
        };
        if (uri.searchParams.get("obfs")) {
            outbound.obfs = {
                password: uri.searchParams.get("obfs-password") || "",
                type: uri.searchParams.get("obfs"),
            };
        }
        return outbound;
    }
    if (type === "tuic") {
        return {
            ...common,
            congestion_control: uri.searchParams.get("congestion_control") || "bbr",
            password: decodeURIComponent(uri.password),
            tls: tlsFromQuery(uri.searchParams, server) || { enabled: true, server_name: uri.searchParams.get("sni") || server },
            uuid: decodeURIComponent(uri.username),
        };
    }
    if (type === "socks" || type === "socks5" || type === "http" || type === "https") {
        const outbound = {
            ...common,
            type: type.startsWith("socks") ? "socks" : "http",
        };
        if (uri.username) outbound.username = decodeURIComponent(uri.username);
        if (uri.password) outbound.password = decodeURIComponent(uri.password);
        if (type === "https") outbound.tls = { enabled: true, server_name: server };
        return outbound;
    }
    fail(`unsupported subscription URI scheme: ${type}`);
};

const parseShadowsocksUri = (line, usedTags) => {
    const hashIndex = line.indexOf("#");
    const tagText = hashIndex >= 0 ? decodeURIComponent(line.slice(hashIndex + 1)) : "shadowsocks";
    const withoutHash = hashIndex >= 0 ? line.slice(0, hashIndex) : line;
    const queryIndex = withoutHash.indexOf("?");
    const query = new URLSearchParams(queryIndex >= 0 ? withoutHash.slice(queryIndex + 1) : "");
    let authority = withoutHash.slice("ss://".length, queryIndex >= 0 ? queryIndex : undefined);

    if (!authority.includes("@")) {
        const decoded = decodeBase64(authority);
        if (!decoded) fail("invalid Shadowsocks subscription URI");
        authority = decoded;
    } else {
        const at = authority.lastIndexOf("@");
        const credentials = authority.slice(0, at);
        if (!credentials.includes(":")) {
            const decodedCredentials = decodeBase64(credentials);
            if (decodedCredentials) authority = `${decodedCredentials}@${authority.slice(at + 1)}`;
        }
    }

    const parsed = new URL(`http://${authority}`);
    const outbound = {
        method: decodeURIComponent(parsed.username),
        password: decodeURIComponent(parsed.password),
        server: parsed.hostname,
        server_port: Number.parseInt(parsed.port, 10),
        tag: uniqueTag(tagText, usedTags),
        type: "shadowsocks",
    };
    if (!outbound.method || !outbound.password || !outbound.server || !outbound.server_port) {
        fail("invalid Shadowsocks subscription URI");
    }
    if (query.get("plugin")) {
        const [plugin, ...pluginOptions] = query.get("plugin").split(";");
        outbound.plugin = plugin;
        if (pluginOptions.length) outbound.plugin_opts = pluginOptions.join(";");
    }
    return outbound;
};

const parseVmessLegacyUri = (line, usedTags) => {
    const decoded = decodeBase64(line.slice("vmess://".length));
    const data = decoded && parseJson(decoded);
    if (!data) return null;

    const query = new URLSearchParams({
        alpn: data.alpn || "",
        fp: data.fp || "",
        host: data.host || "",
        path: data.path || "",
        security: data.tls ? "tls" : "",
        sni: data.sni || "",
        type: data.net || "tcp",
    });
    const outbound = {
        alter_id: Number.parseInt(data.aid || "0", 10),
        security: data.scy || "auto",
        server: data.add,
        server_port: Number.parseInt(data.port, 10),
        tag: uniqueTag(data.ps || "vmess", usedTags),
        type: "vmess",
        uuid: data.id,
    };
    const tls = tlsFromQuery(query, data.add);
    const transport = transportFromQuery(query);
    if (tls) outbound.tls = tls;
    if (transport) outbound.transport = transport;
    return outbound;
};

const parseUriList = value => {
    const decoded = decodeBase64(value);
    const content = decoded && decoded.includes("://") ? decoded : value;
    const lines = content
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(line => line && !line.startsWith("#"));
    const usedTags = new Set();
    const outbounds = [];

    for (const line of lines) {
        try {
            if (line.startsWith("ss://")) {
                outbounds.push(parseShadowsocksUri(line, usedTags));
            } else if (line.startsWith("vmess://")) {
                outbounds.push(parseVmessLegacyUri(line, usedTags) || parseStandardUri(line, usedTags));
            } else if (/^(vless|trojan|hysteria2|hy2|tuic|socks|socks5|http|https):\/\//i.test(line)) {
                outbounds.push(parseStandardUri(line, usedTags));
            }
        } catch (error) {
            console.warn(`${error.message}; entry skipped`);
        }
    }
    return outbounds;
};

const clashTls = proxy => {
    if (!proxy.tls && proxy.type !== "trojan" && proxy.type !== "hysteria2" && proxy.type !== "tuic") return undefined;
    const tls = {
        enabled: true,
        server_name: proxy.servername || proxy.sni || proxy.server,
    };
    if (proxy["skip-cert-verify"] === true) tls.insecure = true;
    if (Array.isArray(proxy.alpn)) tls.alpn = proxy.alpn;
    if (proxy["client-fingerprint"]) tls.utls = { enabled: true, fingerprint: proxy["client-fingerprint"] };
    return tls;
};

const clashTransport = proxy => {
    const network = proxy.network;
    const options = proxy[`${network}-opts`] || {};
    if (network === "ws") {
        const transport = { type: "ws", path: options.path || "/" };
        if (options.headers) transport.headers = options.headers;
        return transport;
    }
    if (network === "grpc") return { type: "grpc", service_name: options["grpc-service-name"] || "" };
    if (network === "h2") return { type: "http", host: options.host, path: options.path || "/" };
    if (network === "httpupgrade") return { type: "httpupgrade", host: options.host, path: options.path || "/" };
    return undefined;
};

const parseClashProxy = (proxy, usedTags) => {
    if (!proxy || typeof proxy !== "object") return null;
    const typeMap = { hy2: "hysteria2", ss: "shadowsocks", socks5: "socks" };
    const type = typeMap[proxy.type] || proxy.type;
    const common = {
        server: proxy.server,
        server_port: Number.parseInt(proxy.port, 10),
        tag: uniqueTag(proxy.name || type, usedTags),
        type,
    };
    let outbound;
    if (type === "shadowsocks") {
        outbound = { ...common, method: proxy.cipher, password: String(proxy.password || "") };
        if (proxy.plugin) outbound.plugin = proxy.plugin;
        if (proxy["plugin-opts"]) outbound.plugin_opts = Object.entries(proxy["plugin-opts"])
            .map(([key, value]) => `${key}=${value}`)
            .join(";");
    } else if (type === "vmess" || type === "vless") {
        outbound = { ...common, uuid: proxy.uuid };
        if (type === "vmess") {
            outbound.alter_id = Number.parseInt(proxy.alterId || 0, 10);
            outbound.security = proxy.cipher || "auto";
        } else if (proxy.flow) outbound.flow = proxy.flow;
    } else if (type === "trojan" || type === "hysteria2") {
        outbound = { ...common, password: String(proxy.password || "") };
    } else if (type === "tuic") {
        outbound = {
            ...common,
            congestion_control: proxy["congestion-controller"] || "bbr",
            password: String(proxy.password || ""),
            uuid: proxy.uuid,
        };
    } else if (type === "socks" || type === "http") {
        outbound = { ...common };
        if (proxy.username) outbound.username = String(proxy.username);
        if (proxy.password) outbound.password = String(proxy.password);
    } else {
        return null;
    }

    const tls = clashTls(proxy);
    const transport = clashTransport(proxy);
    if (tls) outbound.tls = tls;
    if (transport) outbound.transport = transport;
    return outbound;
};

const parseSource = value => {
    const trimmed = String(value || "").trim();
    if (!trimmed) fail("configuration source is empty");

    const json = parseJson(trimmed);
    if (json) {
        if (Array.isArray(json)) return json;
        if (Array.isArray(json.outbounds)) return json.outbounds;
        if (json.type) return [json];
    }

    try {
        const yaml = YAML.parse(trimmed);
        if (Array.isArray(yaml?.proxies)) {
            const usedTags = new Set();
            return yaml.proxies.map(proxy => parseClashProxy(proxy, usedTags)).filter(Boolean);
        }
    } catch {
        // URI subscriptions are handled below.
    }

    return parseUriList(trimmed);
};

const readSource = async () => {
    if (process.env.SINGBOX_OUTBOUND_JSON_BASE64) {
        const decoded = decodeBase64(process.env.SINGBOX_OUTBOUND_JSON_BASE64);
        if (!decoded) fail("SINGBOX_OUTBOUND_JSON_BASE64 is invalid");
        return decoded;
    }
    if (process.env.SINGBOX_OUTBOUND_JSON) return process.env.SINGBOX_OUTBOUND_JSON;
    if (process.env.SINGBOX_OUTBOUND_FILE) return fs.readFileSync(process.env.SINGBOX_OUTBOUND_FILE, "utf8");
    if (process.env.SINGBOX_SUBSCRIPTION_URL) {
        let headers = {};
        if (process.env.SINGBOX_SUBSCRIPTION_HEADERS_JSON) {
            headers = parseJson(process.env.SINGBOX_SUBSCRIPTION_HEADERS_JSON);
            if (!headers || Array.isArray(headers) || typeof headers !== "object") {
                fail("SINGBOX_SUBSCRIPTION_HEADERS_JSON must be a JSON object");
            }
        }
        return fetchText(process.env.SINGBOX_SUBSCRIPTION_URL, headers);
    }
    fail("no outbound JSON or subscription URL was provided");
};

const normalizeOutbounds = sourceOutbounds => {
    if (!Array.isArray(sourceOutbounds) || sourceOutbounds.length === 0) fail("no supported outbounds were found");

    const usedTags = new Set();
    const outbounds = sourceOutbounds.map((source, index) => {
        if (!source || typeof source !== "object" || Array.isArray(source) || !source.type) {
            fail(`outbound #${index + 1} is invalid`);
        }
        const outbound = { ...source };
        outbound.tag = uniqueTag(outbound.tag || `node-${index + 1}`, usedTags);
        return outbound;
    });

    const candidates = outbounds.filter(outbound => !RESERVED_OUTBOUND_TYPES.has(outbound.type));
    if (candidates.length === 0) fail("configuration does not contain a usable proxy outbound");

    const requestedTag = String(process.env.SINGBOX_OUTBOUND_TAG || "").trim();
    let routeTag;
    if (requestedTag) {
        if (!outbounds.some(outbound => outbound.tag === requestedTag)) {
            fail(`SINGBOX_OUTBOUND_TAG '${requestedTag}' was not found`);
        }
        routeTag = requestedTag;
    } else if (outbounds.some(outbound => outbound.tag === "proxy")) {
        routeTag = "proxy";
    } else if (candidates.length === 1) {
        routeTag = candidates[0].tag;
    } else {
        routeTag = uniqueTag("google-egress", usedTags);
        outbounds.push({
            default: candidates[0].tag,
            outbounds: candidates.map(outbound => outbound.tag),
            tag: routeTag,
            type: "selector",
        });
    }

    if (!outbounds.some(outbound => outbound.tag === "direct")) {
        outbounds.push({ tag: "direct", type: "direct" });
    }
    return { outbounds, routeTag };
};

const buildConfig = (sourceOutbounds, port) => {
    const { outbounds, routeTag } = normalizeOutbounds(sourceOutbounds);
    return {
        inbounds: [
            {
                listen: "127.0.0.1",
                listen_port: port,
                tag: "local-mixed",
                type: "mixed",
            },
        ],
        log: {
            disabled: process.env.SINGBOX_LOG_LEVEL === "silent",
            level: process.env.SINGBOX_LOG_LEVEL || "warn",
            timestamp: true,
        },
        outbounds,
        route: {
            auto_detect_interface: true,
            final: "direct",
            rule_set: [
                {
                    download_detour: "direct",
                    format: "binary",
                    tag: "google-sites",
                    type: "remote",
                    update_interval: "24h",
                    url: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google.srs",
                },
            ],
            rules: [
                {
                    action: "route",
                    domain_suffix: GOOGLE_DOMAINS,
                    outbound: routeTag,
                },
                {
                    action: "route",
                    outbound: routeTag,
                    rule_set: ["google-sites"],
                },
            ],
        },
    };
};

const main = async () => {
    const destination = process.argv[2] || process.env.SINGBOX_CONFIG_PATH || "/tmp/private-runtime/config.json";
    const port = parseInteger(process.env.SINGBOX_MIXED_PORT, 2080);
    const source = await readSource();
    const config = buildConfig(parseSource(source), port);
    fs.mkdirSync(path.dirname(destination), { mode: 0o700, recursive: true });
    fs.writeFileSync(destination, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
    console.log(`[Sing-box] Runtime configuration created with ${config.outbounds.length} outbounds.`);
};

if (require.main === module) {
    main().catch(error => {
        console.error(error.message);
        process.exit(1);
    });
}

module.exports = { buildConfig, parseSource };
