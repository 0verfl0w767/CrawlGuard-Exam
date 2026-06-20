const path = require("node:path");
const express = require("express");

const {
  buildFingerprint,
  config,
  createId,
  enforceIssueLimit,
  issueAccessToken,
  issueChallenge,
  parseCookies,
  pruneExpiredState,
  rotateAccessToken,
  assertChallengeAnswer,
  verifyAccessToken,
  verifySignedRequest,
} = require("./security");

function createApp() {
  const app = express();

  app.disable("x-powered-by");
  app.use(express.json());

  app.use((req, res, next) => {
    pruneExpiredState();

    req.cookies = parseCookies(req.headers.cookie);
    req.sessionId = req.cookies[config.sessionCookieName];

    if (!req.sessionId) {
      req.sessionId = createId(16);
      res.cookie(config.sessionCookieName, req.sessionId, {
        httpOnly: true,
        maxAge: config.sessionTtlMs,
        path: "/",
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production",
      });
    }

    req.clientFingerprint = buildFingerprint(req);
    next();
  });

  app.get("/health", (req, res) => {
    res.json({
      ok: true,
      service: "crawlguard-express-demo",
      difficulty: config.challengeDifficulty,
    });
  });

  function buildFeedItems() {
    return [
      {
        id: "feed-001",
        title: "Challenge gate enabled",
        sensitivity: "internal",
      },
      {
        id: "feed-002",
        title: "Token is pinned to session, IP, and User-Agent",
        sensitivity: "internal",
      },
      {
        id: "feed-003",
        title: "Replay with copied headers becomes harder",
        sensitivity: "internal",
      },
    ];
  }

  app.get("/api/test/open-feed", (req, res) => {
    res.json({
      ok: true,
      route: "/api/test/open-feed",
      protection: "none",
      directRequestAllowed: true,
      message: "This test API is intentionally open, so a plain request succeeds.",
      data: buildFeedItems(),
    });
  });

  app.get("/api/challenge", (req, res) => {
    const rateLimit = enforceIssueLimit(req);

    if (rateLimit.limited) {
      return res.status(429).json({
        error: "Too many challenge requests.",
        retryAfterMs: rateLimit.retryAfterMs,
      });
    }

    const challenge = issueChallenge({
      sessionId: req.sessionId,
      fingerprint: req.clientFingerprint,
    });

    return res.json({
      challengeId: challenge.id,
      salt: challenge.salt,
      difficulty: challenge.difficulty,
      expiresAt: challenge.expiresAt,
      algorithm: "sha256",
      binding: {
        cookie: config.sessionCookieName,
        ip: true,
        userAgent: true,
      },
      note: "Solve sha256(challengeId:salt:nonce) until the digest starts with N leading zeroes.",
    });
  });

  app.post("/api/challenge/verify", (req, res, next) => {
    try {
      const challengeId = req.body?.challengeId;
      const nonceInput = req.body?.nonce;
      const nonce =
        typeof nonceInput === "number" ? String(nonceInput) : nonceInput;

      if (!challengeId || typeof challengeId !== "string") {
        return res.status(400).json({ error: "challengeId is required." });
      }

      if (!nonce || typeof nonce !== "string") {
        return res.status(400).json({ error: "nonce is required." });
      }

      const challenge = assertChallengeAnswer({
        challengeId,
        nonce,
        sessionId: req.sessionId,
        fingerprint: req.clientFingerprint,
      });

      const access = issueAccessToken({
        sessionId: req.sessionId,
        fingerprint: req.clientFingerprint,
        challengeId: challenge.id,
      });

      return res.json({
        accessToken: access.token,
        tokenType: "Bearer",
        expiresAt: access.expiresAt,
        challengeId: challenge.id,
        tokenPolicy: {
          ttlMs: config.tokenTtlMs,
          rotationEnabled: true,
          previousTokenGraceMs: config.rotatedTokenGraceMs,
        },
        requestSigning: {
          algorithm: "hmac-sha256",
          headers: [
            "x-cg-timestamp",
            "x-cg-nonce",
            "x-cg-signature",
          ],
          windowMs: config.requestSignatureWindowMs,
          note: "signature = HMAC(accessToken, METHOD\\nPATH\\nbodyHash\\ntimestamp\\nnonce)",
        },
        binding: {
          sessionId: `${req.sessionId.slice(0, 8)}...`,
          fingerprint: `${req.clientFingerprint.slice(0, 12)}...`,
        },
      });
    } catch (error) {
      return next(error);
    }
  });

  function requireBoundToken(req, res, next) {
    const authorization = req.get("authorization") || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Direct request blocked. Complete the challenge flow and send a bound bearer token.",
      });
    }

    try {
      const token = authorization.slice(7);

      req.currentAccessToken = token;
      req.accessToken = verifyAccessToken(token, {
        sessionId: req.sessionId,
        fingerprint: req.clientFingerprint,
      });

      verifySignedRequest({
        token,
        tokenPayload: req.accessToken,
        method: req.method,
        requestPath: req.originalUrl,
        timestamp: req.get("x-cg-timestamp"),
        nonce: req.get("x-cg-nonce"),
        signature: req.get("x-cg-signature"),
      });

      return next();
    } catch (error) {
      return next(error);
    }
  }

  function sendGuardedFeed(req, res) {
    const nextAccess = rotateAccessToken(req.currentAccessToken, req.accessToken);

    res.json({
      ok: true,
      route: "/api/test/guarded-feed",
      protection: "challenge+bound-token+request-signature+rotation",
      directRequestAllowed: false,
      message:
        "Challenge verified, token binding matched, request signature verified, and token rotated.",
      token: {
        challengeId: req.accessToken.challengeId,
        expiresAt: req.accessToken.exp,
        state: req.accessToken.tokenState,
        acceptedUntil: req.accessToken.acceptedUntil,
      },
      rotation: {
        nextAccessToken: nextAccess.token,
        nextExpiresAt: nextAccess.expiresAt,
        previousTokenGraceUntil: nextAccess.previousTokenGraceUntil,
      },
      data: buildFeedItems(),
    });
  }

  app.get("/api/test/guarded-feed", requireBoundToken, sendGuardedFeed);
  app.get("/api/protected/feed", requireBoundToken, sendGuardedFeed);

  app.use(express.static(path.join(__dirname, "..", "public")));

  app.use((error, req, res, next) => {
    const statusCode = error.statusCode || 500;
    const message =
      statusCode >= 500 ? "Unexpected server error." : error.message;

    res.status(statusCode).json({
      error: message,
    });
  });

  return app;
}

module.exports = {
  createApp,
};
