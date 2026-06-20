const crypto = require("node:crypto");

const config = {
  challengeDifficulty: Number(process.env.CHALLENGE_DIFFICULTY || 4),
  challengeTtlMs: Number(process.env.CHALLENGE_TTL_MS || 2 * 60 * 1000),
  tokenTtlMs: Number(process.env.TOKEN_TTL_MS || 10 * 1000),
  rotatedTokenGraceMs: Number(
    process.env.ROTATED_TOKEN_GRACE_MS || 5 * 1000
  ),
  requestSignatureWindowMs: Number(
    process.env.REQUEST_SIGNATURE_WINDOW_MS || 30 * 1000
  ),
  issueLimit: Number(process.env.CHALLENGE_ISSUE_LIMIT || 20),
  issueWindowMs: Number(process.env.CHALLENGE_ISSUE_WINDOW_MS || 60 * 1000),
  sessionCookieName: "cg_session",
  sessionTtlMs: Number(process.env.SESSION_TTL_MS || 24 * 60 * 60 * 1000),
  secret:
    process.env.CRAWLGUARD_SECRET || crypto.randomBytes(32).toString("hex"),
};

const challenges = new Map();
const tokens = new Map();
const issueWindows = new Map();
const requestNonces = new Map();

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function hmac(value) {
  return crypto.createHmac("sha256", config.secret).update(value).digest("base64url");
}

function hmacHex(key, value) {
  return crypto.createHmac("sha256", key).update(value).digest("hex");
}

function createId(size = 16) {
  return crypto.randomBytes(size).toString("hex");
}

function parseCookies(cookieHeader = "") {
  if (!cookieHeader) {
    return {};
  }

  return cookieHeader
    .split(";")
    .map((chunk) => chunk.trim())
    .filter(Boolean)
    .reduce((cookies, chunk) => {
      const separatorIndex = chunk.indexOf("=");

      if (separatorIndex === -1) {
        return cookies;
      }

      const name = chunk.slice(0, separatorIndex);
      const value = chunk.slice(separatorIndex + 1);
      cookies[name] = decodeURIComponent(value);
      return cookies;
    }, {});
}

function normalizeIp(ip = "") {
  if (!ip) {
    return "unknown";
  }

  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}

function buildFingerprint(req) {
  const ip = normalizeIp(req.ip);
  const userAgent = req.get("user-agent") || "unknown";
  return sha256Hex(`${ip}|${userAgent}`);
}

function proofOfWorkDigest(challengeId, salt, nonce) {
  return sha256Hex(`${challengeId}:${salt}:${nonce}`);
}

function pruneExpiredState() {
  const now = Date.now();

  for (const [challengeId, challenge] of challenges) {
    if (challenge.expiresAt <= now || challenge.used) {
      challenges.delete(challengeId);
    }
  }

  for (const [tokenDigest, tokenRecord] of tokens) {
    if (tokenRecord.expiresAt <= now) {
      tokens.delete(tokenDigest);
    }
  }

  for (const [key, windowRecord] of issueWindows) {
    if (windowRecord.resetAt <= now) {
      issueWindows.delete(key);
    }
  }

  for (const [key, nonceRecord] of requestNonces) {
    if (nonceRecord.expiresAt <= now) {
      requestNonces.delete(key);
    }
  }
}

function enforceIssueLimit(req) {
  const ip = normalizeIp(req.ip);
  const now = Date.now();
  const currentWindow = issueWindows.get(ip);

  if (!currentWindow || currentWindow.resetAt <= now) {
    issueWindows.set(ip, {
      count: 1,
      resetAt: now + config.issueWindowMs,
    });

    return {
      limited: false,
      remaining: config.issueLimit - 1,
      retryAfterMs: 0,
    };
  }

  if (currentWindow.count >= config.issueLimit) {
    return {
      limited: true,
      remaining: 0,
      retryAfterMs: Math.max(0, currentWindow.resetAt - now),
    };
  }

  currentWindow.count += 1;

  return {
    limited: false,
    remaining: Math.max(0, config.issueLimit - currentWindow.count),
    retryAfterMs: 0,
  };
}

function issueChallenge({ sessionId, fingerprint }) {
  const challenge = {
    id: createId(12),
    salt: createId(8),
    difficulty: config.challengeDifficulty,
    sessionId,
    fingerprint,
    expiresAt: Date.now() + config.challengeTtlMs,
    used: false,
  };

  challenges.set(challenge.id, challenge);
  return challenge;
}

function assertChallengeAnswer({ challengeId, nonce, sessionId, fingerprint }) {
  const challenge = challenges.get(challengeId);

  if (!challenge) {
    const error = new Error("Challenge not found.");
    error.statusCode = 404;
    throw error;
  }

  if (challenge.used) {
    const error = new Error("Challenge already used.");
    error.statusCode = 409;
    throw error;
  }

  if (challenge.expiresAt <= Date.now()) {
    challenges.delete(challengeId);
    const error = new Error("Challenge expired.");
    error.statusCode = 410;
    throw error;
  }

  if (challenge.sessionId !== sessionId) {
    const error = new Error("Challenge session mismatch.");
    error.statusCode = 401;
    throw error;
  }

  if (challenge.fingerprint !== fingerprint) {
    const error = new Error("Challenge fingerprint mismatch.");
    error.statusCode = 401;
    throw error;
  }

  const digest = proofOfWorkDigest(challenge.id, challenge.salt, nonce);

  if (!digest.startsWith("0".repeat(challenge.difficulty))) {
    const error = new Error("Invalid challenge answer.");
    error.statusCode = 400;
    throw error;
  }

  challenge.used = true;
  return challenge;
}

function encodePayload(payload) {
  return Buffer.from(JSON.stringify(payload)).toString("base64url");
}

function decodePayload(serializedPayload) {
  return JSON.parse(Buffer.from(serializedPayload, "base64url").toString("utf8"));
}

function buildRequestSignatureInput({
  method,
  requestPath,
  bodyHash,
  timestamp,
  nonce,
}) {
  return [
    method.toUpperCase(),
    requestPath,
    bodyHash,
    String(timestamp),
    nonce,
  ].join("\n");
}

function signRequest({
  token,
  method,
  requestPath,
  bodyHash = sha256Hex(""),
  timestamp,
  nonce,
}) {
  return hmacHex(
    token,
    buildRequestSignatureInput({
      method,
      requestPath,
      bodyHash,
      timestamp,
      nonce,
    })
  );
}

function safeCompareHex(left, right) {
  if (
    typeof left !== "string" ||
    typeof right !== "string" ||
    left.length !== right.length
  ) {
    return false;
  }

  const leftBuffer = Buffer.from(left, "hex");
  const rightBuffer = Buffer.from(right, "hex");

  if (leftBuffer.length !== rightBuffer.length || leftBuffer.length * 2 !== left.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function issueAccessToken({ sessionId, fingerprint, challengeId }) {
  const now = Date.now();
  const payload = {
    jti: createId(12),
    sid: sessionId,
    fp: fingerprint,
    challengeId,
    iat: now,
    exp: now + config.tokenTtlMs,
  };

  const encodedPayload = encodePayload(payload);
  const signature = hmac(encodedPayload);
  const token = `${encodedPayload}.${signature}`;

  tokens.set(sha256Hex(token), {
    jti: payload.jti,
    sessionId,
    fingerprint,
    challengeId,
    state: "active",
    expiresAt: payload.exp,
  });

  return {
    token,
    expiresAt: payload.exp,
  };
}

function verifyAccessToken(token, { sessionId, fingerprint }) {
  const [encodedPayload, signature] = (token || "").split(".");

  if (!encodedPayload || !signature) {
    const error = new Error("Malformed bearer token.");
    error.statusCode = 401;
    throw error;
  }

  const expectedSignature = hmac(encodedPayload);

  if (signature !== expectedSignature) {
    const error = new Error("Invalid bearer token signature.");
    error.statusCode = 401;
    throw error;
  }

  const payload = decodePayload(encodedPayload);

  if (payload.exp <= Date.now()) {
    tokens.delete(sha256Hex(token));
    const error = new Error("Bearer token expired.");
    error.statusCode = 401;
    throw error;
  }

  if (payload.sid !== sessionId) {
    const error = new Error("Bearer token session mismatch.");
    error.statusCode = 401;
    throw error;
  }

  if (payload.fp !== fingerprint) {
    const error = new Error("Bearer token fingerprint mismatch.");
    error.statusCode = 401;
    throw error;
  }

  const tokenRecord = tokens.get(sha256Hex(token));

  if (!tokenRecord) {
    const error = new Error("Bearer token not active.");
    error.statusCode = 401;
    throw error;
  }

  if (tokenRecord.expiresAt <= Date.now()) {
    tokens.delete(sha256Hex(token));
    const error = new Error("Bearer token expired.");
    error.statusCode = 401;
    throw error;
  }

  return {
    ...payload,
    tokenState: tokenRecord.state,
    acceptedUntil: tokenRecord.expiresAt,
  };
}

function rotateAccessToken(currentToken, tokenPayload) {
  const tokenDigest = sha256Hex(currentToken);
  const tokenRecord = tokens.get(tokenDigest);

  if (!tokenRecord) {
    const error = new Error("Bearer token not active for rotation.");
    error.statusCode = 401;
    throw error;
  }

  const now = Date.now();
  const graceExpiresAt = Math.min(
    tokenRecord.expiresAt,
    now + config.rotatedTokenGraceMs
  );

  tokenRecord.state = "grace";
  tokenRecord.expiresAt = graceExpiresAt;

  const nextAccess = issueAccessToken({
    sessionId: tokenPayload.sid,
    fingerprint: tokenPayload.fp,
    challengeId: tokenPayload.challengeId,
  });

  return {
    ...nextAccess,
    previousTokenGraceUntil: graceExpiresAt,
  };
}

function verifySignedRequest({
  token,
  tokenPayload,
  method,
  requestPath,
  bodyHash = sha256Hex(""),
  timestamp,
  nonce,
  signature,
}) {
  if (!timestamp || !nonce || !signature) {
    const error = new Error(
      "Signed request headers missing. Send x-cg-timestamp, x-cg-nonce, and x-cg-signature."
    );
    error.statusCode = 401;
    throw error;
  }

  const parsedTimestamp = Number(timestamp);

  if (!Number.isFinite(parsedTimestamp)) {
    const error = new Error("Invalid request timestamp.");
    error.statusCode = 400;
    throw error;
  }

  const now = Date.now();

  if (
    Math.abs(now - parsedTimestamp) > config.requestSignatureWindowMs
  ) {
    const error = new Error("Request timestamp expired.");
    error.statusCode = 401;
    throw error;
  }

  if (typeof nonce !== "string" || nonce.length < 8) {
    const error = new Error("Invalid request nonce.");
    error.statusCode = 400;
    throw error;
  }

  const expectedSignature = signRequest({
    token,
    method,
    requestPath,
    bodyHash,
    timestamp: parsedTimestamp,
    nonce,
  });

  if (!safeCompareHex(signature, expectedSignature)) {
    const error = new Error("Invalid request signature.");
    error.statusCode = 401;
    throw error;
  }

  const nonceKey = `${tokenPayload.jti}:${nonce}`;

  if (requestNonces.has(nonceKey)) {
    const error = new Error("Request nonce already used.");
    error.statusCode = 409;
    throw error;
  }

  requestNonces.set(nonceKey, {
    expiresAt: parsedTimestamp + config.requestSignatureWindowMs,
  });
}

module.exports = {
  buildFingerprint,
  buildRequestSignatureInput,
  config,
  createId,
  enforceIssueLimit,
  issueAccessToken,
  issueChallenge,
  parseCookies,
  proofOfWorkDigest,
  pruneExpiredState,
  signRequest,
  assertChallengeAnswer,
  rotateAccessToken,
  verifyAccessToken,
  verifySignedRequest,
};
