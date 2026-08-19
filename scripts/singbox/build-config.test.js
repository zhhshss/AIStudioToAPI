const assert = require("assert");
const { buildConfig, parseSource } = require("./build-config");

const single = parseSource('{"type":"socks","server":"127.0.0.1","server_port":1080}');
assert.strictEqual(single.length, 1);
assert.strictEqual(single[0].type, "socks");

const uriList = Buffer.from("vless://id@example.com:443?security=tls&sni=example.com#primary").toString("base64");
const parsedUris = parseSource(uriList);
assert.strictEqual(parsedUris[0].tag, "primary");
assert.strictEqual(parsedUris[0].tls.server_name, "example.com");

const clash = parseSource("proxies:\n  - name: edge\n    type: trojan\n    server: example.com\n    port: 443\n    password: secret\n");
assert.strictEqual(clash[0].type, "trojan");
assert.strictEqual(clash[0].tls.enabled, true);

const config = buildConfig(
    [
        { type: "socks", tag: "a", server: "127.0.0.1", server_port: 1080 },
        { type: "socks", tag: "b", server: "127.0.0.2", server_port: 1080 },
    ],
    2080
);
assert.strictEqual(config.inbounds[0].listen, "127.0.0.1");
assert.strictEqual(config.route.final, "direct");
assert(config.route.rules.some(rule => rule.rule_set?.includes("google-sites")));
assert(config.outbounds.some(outbound => outbound.type === "selector"));

console.log("Sing-box configuration tests passed.");
