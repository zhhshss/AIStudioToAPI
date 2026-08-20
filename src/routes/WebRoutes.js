/**
 * File: src/routes/WebRoutes.js
 * Description: Web routes coordinator - delegates to specialized route handlers
 *
 * Author: Ellinav, iBenzene, bbbugg
 */

const session = require("express-session");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const express = require("express");
const path = require("path");
const AuthRoutes = require("./AuthRoutes");
const StatusRoutes = require("./StatusRoutes");
const { PostgresSessionStore } = require("../utils/PostgresStore");

/**
 * Web Routes Manager
 * Coordinates and delegates to specialized route handlers
 */
class WebRoutes {
    constructor(serverSystem) {
        this.serverSystem = serverSystem;
        this.logger = serverSystem.logger;
        this.distIndexPath = path.join(__dirname, "..", "..", "ui", "dist", "index.html");

        // Pass distIndexPath to serverSystem for other modules to access
        serverSystem.distIndexPath = this.distIndexPath;

        // Initialize specialized route handlers
        this.authRoutes = new AuthRoutes(serverSystem);
        this.statusRoutes = new StatusRoutes(serverSystem);
    }

    /**
     * Configure session and login related middleware
     */
    setupSession(app) {
        const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

        // Trust first proxy (Nginx) for secure cookies and IP forwarding
        app.set("trust proxy", 1);

        app.use(cookieParser());
        const sessionOptions = {
            cookie: {
                httpOnly: true,
                maxAge: 604800000,
                sameSite: "lax",
                // This allows HTTP access in production if HTTPS is not configured
                // Set SECURE_COOKIES=true when using HTTPS/SSL
                secure: process.env.SECURE_COOKIES?.toLowerCase() === "true",
            },
            name: process.env.SESSION_COOKIE_NAME || "sid",
            resave: false,
            saveUninitialized: false,
            secret: sessionSecret,
        };
        if (this.serverSystem.postgresStore) {
            sessionOptions.store = new PostgresSessionStore(this.serverSystem.postgresStore);
            this.logger.info("[WebUI] Using PostgreSQL session store.");
        }
        this.sessionParser = session(sessionOptions);
        app.use(this.sessionParser);

        // The login gate is the only public HTML. The application bundle and every
        // management page are registered behind the session middleware below.
        this.authRoutes.setupRoutes(app);
        const isAuthenticated = this.authRoutes.isAuthenticated.bind(this.authRoutes);
        const isAuthenticatedOrApiKey = this.authRoutes.isAuthenticatedOrApiKey.bind(this.authRoutes);
        app.use("/assets", isAuthenticated, express.static(path.join(__dirname, "..", "..", "ui", "dist", "assets")));
        app.use("/locales", isAuthenticated, express.static(path.join(__dirname, "..", "..", "ui", "locales")));
        this.statusRoutes.setupRoutes(app, isAuthenticated, isAuthenticatedOrApiKey);
    }
}

module.exports = WebRoutes;
