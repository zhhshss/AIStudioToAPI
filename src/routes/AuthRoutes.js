/**
 * File: src/routes/AuthRoutes.js
 * Description: Authentication routes for login and logout functionality
 *
 * Author: Ellinav, iBenzene, bbbugg
 */

const CreateAuth = require("../auth/CreateAuth");

/**
 * Auth Routes Manager
 * Manages authentication-related routes (login, logout, session, and auth creation)
 */
class AuthRoutes {
    constructor(serverSystem) {
        this.serverSystem = serverSystem;
        this.logger = serverSystem.logger;
        this.distIndexPath = serverSystem.distIndexPath;
        this.loginAttempts = new Map(); // Track login attempts for rate limiting

        // Initialize auth creation handler
        this.createAuth = new CreateAuth(serverSystem);

        // Rate limiting configuration from environment variables
        this.rateLimitEnabled = process.env.RATE_LIMIT_MAX_ATTEMPTS !== "0";

        const parsedWindow = parseInt(process.env.RATE_LIMIT_WINDOW_MINUTES, 10);
        this.rateLimitWindow = Number.isFinite(parsedWindow) && parsedWindow > 0 ? parsedWindow : 15; // minutes

        const parsedMaxAttempts = parseInt(process.env.RATE_LIMIT_MAX_ATTEMPTS, 10);
        this.rateLimitMaxAttempts = Number.isFinite(parsedMaxAttempts) && parsedMaxAttempts > 0 ? parsedMaxAttempts : 5;

        if (this.rateLimitEnabled) {
            this.logger.info(
                `[Auth] Rate limiting enabled: ${this.rateLimitMaxAttempts} attempts per ${this.rateLimitWindow} minutes`
            );
        } else {
            this.logger.info("[Auth] Rate limiting disabled");
        }
    }

    _rejectIfSystemBusy(res) {
        if (!this.serverSystem.requestHandler?.isSystemBusy) {
            return false;
        }

        return res.status(409).json({
            error: "System is busy switching or recovering accounts. Please try again later.",
            message: "systemBusySwitchingOrRecoveringAccounts",
        });
    }

    /**
     * Get real client IP address, handling various proxy scenarios
     * Priority: CDN headers > X-Real-IP > X-Forwarded-For (first IP) > req.ip
     *
     * Supports common CDN providers:
     * - Cloudflare: CF-Connecting-IP
     * - Fastly/Firebase: Fastly-Client-IP
     * - Akamai/Cloudfront: True-Client-IP
     */
    getClientIP(req) {
        // Priority 1: CDN-specific headers (most reliable when using CDN)
        // Cloudflare
        if (req.headers["cf-connecting-ip"]) {
            return req.headers["cf-connecting-ip"];
        }
        // Fastly / Firebase Hosting
        if (req.headers["fastly-client-ip"]) {
            return req.headers["fastly-client-ip"];
        }
        // Akamai / Cloudfront
        if (req.headers["true-client-ip"]) {
            return req.headers["true-client-ip"];
        }
        // Alibaba Cloud's ESA
        if (req.headers["ali-real-client-ip"]) {
            return req.headers["ali-real-client-ip"];
        }
        // Tencent Cloud's EdgeOne
        if (req.headers["eo-connecting-ip"]) {
            return req.headers["eo-connecting-ip"];
        }

        // Priority 2: X-Real-IP (reliable in trusted internal proxy chains)
        if (req.headers["x-real-ip"]) {
            return req.headers["x-real-ip"];
        }

        // Priority 3: X-Forwarded-For (can be spoofed, use as fallback)
        // Format: client, proxy1, proxy2, ...
        // We want the first IP (the original client)
        if (req.headers["x-forwarded-for"]) {
            return req.headers["x-forwarded-for"].split(",")[0].trim();
        }

        // Priority 4: Direct connection IP (fallback)
        // This will be the direct connection IP if no proxy headers exist
        return req.ip || req.connection.remoteAddress || "unknown";
    }

    /**
     * Authentication middleware
     */
    isAuthenticated(req, res, next) {
        if (req.session?.isAuthenticated) {
            return next();
        }

        // Use 303 See Other to force the browser to use GET for the redirect
        // This solves the issue where DELETE/POST requests would otherwise be redirected as DELETE/POST /login
        if (req.xhr || req.headers.accept?.includes("application/json")) {
            return res.status(401).json({ message: "unlimited" });
        }

        res.redirect(303, "/login");
    }

    isAuthenticatedOrApiKey(req, res, next) {
        if (req.session?.isAuthenticated) return next();

        const authorization = req.headers.authorization || "";
        const candidate =
            req.headers["x-api-key"] ||
            req.headers["x-goog-api-key"] ||
            (authorization.startsWith("Bearer ") ? authorization.slice(7) : "");
        if (candidate && this.serverSystem.config.apiKeys.includes(candidate)) return next();

        return res.status(404).end();
    }

    _renderLoginPage(req) {
        const requireUsername = !!process.env.WEB_CONSOLE_USERNAME && !!process.env.WEB_CONSOLE_PASSWORD;
        const requirePassword = !!process.env.WEB_CONSOLE_PASSWORD;
        const errorCode = String(req.query.error || "");
        const errorText =
            errorCode === "2" ? "Too many attempts. Try again later." : errorCode === "1" ? "Access denied." : "";
        const userField = requireUsername
            ? '<input name="username" type="text" autocomplete="username" placeholder="Username" required autofocus>'
            : "";
        const passwordName = requirePassword ? "password" : "apiKey";
        return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Private access</title>
<style>html{color-scheme:light dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f5f7;color:#18181b;font:14px system-ui,sans-serif}form{width:min(320px,calc(100vw - 32px));padding:24px;border:1px solid #d4d4d8;border-radius:6px;background:#fff;box-shadow:0 8px 30px #00000012}h1{margin:0 0 18px;font-size:18px;letter-spacing:0}input,button{width:100%;height:40px;border-radius:4px;font:inherit}input{margin:0 0 12px;padding:0 12px;border:1px solid #a1a1aa;background:#fff;color:#18181b}button{border:0;background:#18181b;color:#fff;cursor:pointer}.error{margin:14px 0 0;color:#b91c1c;text-align:center}@media(prefers-color-scheme:dark){body{background:#111113;color:#fafafa}form{background:#1c1c1f;border-color:#3f3f46}input{background:#27272a;border-color:#52525b;color:#fafafa}button{background:#fafafa;color:#18181b}}</style>
</head><body><form action="/login" method="post"><h1>Private access</h1>${userField}<input name="${passwordName}" type="password" autocomplete="current-password" placeholder="Password" required${requireUsername ? "" : " autofocus"}><button type="submit">Continue</button>${errorText ? `<p class="error">${errorText}</p>` : ""}</form></body></html>`;
    }

    /**
     * Setup authentication routes
     */
    setupRoutes(app) {
        app.get("/login", (req, res) => {
            if (req.session.isAuthenticated) {
                return res.redirect("/");
            }
            res.setHeader(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
            );
            res.status(200).type("html").send(this._renderLoginPage(req));
        });

        // Login endpoint with rate limiting
        app.post("/login", (req, res) => {
            const ip = this.getClientIP(req);
            const now = Date.now();
            const RATE_LIMIT_WINDOW = this.rateLimitWindow * 60 * 1000; // Convert minutes to milliseconds
            const MAX_ATTEMPTS = this.rateLimitMaxAttempts;

            // Skip rate limiting if disabled
            if (this.rateLimitEnabled) {
                const attempts = this.loginAttempts.get(ip) || { count: 0, firstAttempt: now, lastAttempt: 0 };

                // Clean up old entries (older than rate limit window)
                if (now - attempts.firstAttempt > RATE_LIMIT_WINDOW) {
                    // Time window expired, reset counter
                    attempts.count = 0;
                    attempts.firstAttempt = now;
                }

                // Check if IP is rate limited (MAX_ATTEMPTS in RATE_LIMIT_WINDOW)
                if (attempts.count >= MAX_ATTEMPTS) {
                    const timeLeft = Math.ceil((RATE_LIMIT_WINDOW - (now - attempts.firstAttempt)) / 60000);
                    this.logger.warn(`[Auth] Rate limit exceeded for IP: ${ip}, ${timeLeft} minutes remaining`);
                    return res.redirect("/login?error=2");
                }
            }

            const { apiKey, username, password } = req.body;
            let authSuccess = false;
            const submittedPassword = password || apiKey;
            const expectedUsername = process.env.WEB_CONSOLE_USERNAME;
            const expectedPassword = process.env.WEB_CONSOLE_PASSWORD;

            if (expectedUsername && expectedPassword) {
                if (username === expectedUsername && submittedPassword === expectedPassword) {
                    authSuccess = true;
                }
            } else if (!expectedUsername && expectedPassword) {
                if (submittedPassword === expectedPassword) {
                    authSuccess = true;
                }
            } else {
                if (submittedPassword && this.serverSystem.config.apiKeys.includes(submittedPassword)) {
                    authSuccess = true;
                }
            }

            if (authSuccess) {
                // Clear failed attempts on successful login
                if (this.rateLimitEnabled) {
                    this.loginAttempts.delete(ip);
                }

                // Regenerate session to prevent session fixation attacks
                req.session.regenerate(err => {
                    if (err) {
                        this.logger.error(`[Auth] Session regeneration failed: ${err.message}`);
                        return res.redirect("/login?error=1");
                    }
                    req.session.isAuthenticated = true;
                    this.logger.info(`[Auth] Successful login from IP: ${ip}`);
                    res.redirect("/");
                });
            } else {
                // Record failed login attempt (only if rate limiting is enabled)
                if (this.rateLimitEnabled) {
                    const attempts = this.loginAttempts.get(ip) || { count: 0, firstAttempt: now, lastAttempt: 0 };
                    attempts.count++;
                    attempts.lastAttempt = now;
                    this.loginAttempts.set(ip, attempts);
                    this.logger.warn(`[Auth] Failed login attempt from IP: ${ip} (${attempts.count}/${MAX_ATTEMPTS})`);

                    // Periodic cleanup: remove expired entries from other IPs
                    if (Math.random() < 0.1) {
                        // 10% chance to trigger cleanup
                        this._cleanupExpiredAttempts(now, RATE_LIMIT_WINDOW);
                    }
                } else {
                    this.logger.warn(`[Auth] Failed login attempt from IP: ${ip}`);
                }

                res.redirect("/login?error=1");
            }
        });

        // Logout endpoint
        const isAuthenticated = this.isAuthenticated.bind(this);
        app.post("/logout", isAuthenticated, (req, res) => {
            const ip = this.getClientIP(req);
            req.session.destroy(err => {
                if (err) {
                    this.logger.error(`[Auth] Session destruction failed for IP ${ip}: ${err.message}`);
                    return res.status(500).json({ message: "logoutFailed" });
                }
                this.logger.info(`[Auth] User logged out from IP: ${ip}`);
                res.clearCookie(process.env.SESSION_COOKIE_NAME || "sid");
                res.status(200).json({ message: "logoutSuccess" });
            });
        });

        // VNC-based auth creation routes
        app.post("/api/vnc/sessions", isAuthenticated, (req, res, next) => {
            if (this._rejectIfSystemBusy(res)) return;
            return this.createAuth.startVncSession(req, res, next);
        });
        app.post("/api/vnc/auth", isAuthenticated, (req, res, next) => {
            if (this._rejectIfSystemBusy(res)) return;
            return this.createAuth.saveAuthFile(req, res, next);
        });
        app.delete("/api/vnc/sessions", isAuthenticated, async (req, res) => {
            this.logger.info("[VNC] Received cleanup request from client (beacon).");
            await this.createAuth._cleanupVncSession("client_beacon");
            res.sendStatus(204); // No content
        });
    }

    /**
     * Clean up expired login attempt records to prevent memory leaks
     */
    _cleanupExpiredAttempts(now, rateLimit) {
        for (const [ip, data] of this.loginAttempts.entries()) {
            if (now - data.firstAttempt > rateLimit) {
                this.loginAttempts.delete(ip);
            }
        }
    }
}

module.exports = AuthRoutes;
