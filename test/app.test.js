const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const { createApp } = require("../src/app");
const { signRequest } = require("../src/security");

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

async function solveChallenge(challenge) {
  const target = "0".repeat(challenge.difficulty);
  let nonce = 0;

  while (true) {
    const digest = sha256Hex(`${challenge.challengeId}:${challenge.salt}:${nonce}`);

    if (digest.startsWith(target)) {
      return String(nonce);
    }

    nonce += 1;
  }
}

function buildSignedHeaders(token, path) {
  const timestamp = String(Date.now());
  const nonce = crypto.randomBytes(12).toString("hex");

  return {
    authorization: `Bearer ${token}`,
    "x-cg-timestamp": timestamp,
    "x-cg-nonce": nonce,
    "x-cg-signature": signRequest({
      token,
      method: "GET",
      requestPath: path,
      timestamp,
      nonce,
    }),
  };
}

test("challenge handshake unlocks the protected route", async () => {
  const app = createApp();
  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const userAgent = "crawlguard-test-client";

  try {
    const challengeResponse = await fetch(`${baseUrl}/api/challenge`, {
      headers: {
        "user-agent": userAgent,
      },
    });

    assert.equal(challengeResponse.status, 200);

    const cookie = challengeResponse.headers.get("set-cookie");
    assert.ok(cookie);

    const cookieHeader = cookie.split(";")[0];
    const challenge = await challengeResponse.json();
    const nonce = await solveChallenge(challenge);

    const verifyResponse = await fetch(`${baseUrl}/api/challenge/verify`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: cookieHeader,
        "user-agent": userAgent,
      },
      body: JSON.stringify({
        challengeId: challenge.challengeId,
        nonce,
      }),
    });

    assert.equal(verifyResponse.status, 200);

    const tokenPayload = await verifyResponse.json();
    assert.ok(tokenPayload.accessToken);

    const protectedResponse = await fetch(`${baseUrl}/api/test/guarded-feed`, {
      headers: {
        ...buildSignedHeaders(tokenPayload.accessToken, "/api/test/guarded-feed"),
        cookie: cookieHeader,
        "user-agent": userAgent,
      },
    });

    assert.equal(protectedResponse.status, 200);

    const data = await protectedResponse.json();
    assert.equal(data.ok, true);
    assert.equal(data.data.length, 3);
    assert.ok(data.rotation.nextAccessToken);
    assert.equal(
      data.protection,
      "challenge+bound-token+request-signature+rotation"
    );

    const rotatedResponse = await fetch(`${baseUrl}/api/test/guarded-feed`, {
      headers: {
        ...buildSignedHeaders(
          data.rotation.nextAccessToken,
          "/api/test/guarded-feed"
        ),
        cookie: cookieHeader,
        "user-agent": userAgent,
      },
    });

    assert.equal(rotatedResponse.status, 200);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("plain direct request works on the open test API", async () => {
  const app = createApp();
  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const response = await fetch(`${baseUrl}/api/test/open-feed`);
    assert.equal(response.status, 200);

    const payload = await response.json();
    assert.equal(payload.directRequestAllowed, true);
    assert.equal(payload.route, "/api/test/open-feed");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("plain direct request is blocked on the guarded test API", async () => {
  const app = createApp();
  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const response = await fetch(`${baseUrl}/api/test/guarded-feed`);
    assert.equal(response.status, 401);

    const payload = await response.json();
    assert.match(payload.error, /direct request blocked/i);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("replayed signed request is blocked by nonce reuse", async () => {
  const app = createApp();
  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const userAgent = "replay-test-client";

  try {
    const challengeResponse = await fetch(`${baseUrl}/api/challenge`, {
      headers: {
        "user-agent": userAgent,
      },
    });

    const cookie = challengeResponse.headers.get("set-cookie");
    const cookieHeader = cookie.split(";")[0];
    const challenge = await challengeResponse.json();
    const nonce = await solveChallenge(challenge);

    const verifyResponse = await fetch(`${baseUrl}/api/challenge/verify`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: cookieHeader,
        "user-agent": userAgent,
      },
      body: JSON.stringify({
        challengeId: challenge.challengeId,
        nonce,
      }),
    });

    const tokenPayload = await verifyResponse.json();
    const signedHeaders = buildSignedHeaders(
      tokenPayload.accessToken,
      "/api/test/guarded-feed"
    );

    const firstResponse = await fetch(`${baseUrl}/api/test/guarded-feed`, {
      headers: {
        ...signedHeaders,
        cookie: cookieHeader,
        "user-agent": userAgent,
      },
    });

    assert.equal(firstResponse.status, 200);

    const replayResponse = await fetch(`${baseUrl}/api/test/guarded-feed`, {
      headers: {
        ...signedHeaders,
        cookie: cookieHeader,
        "user-agent": userAgent,
      },
    });

    assert.equal(replayResponse.status, 409);

    const replayPayload = await replayResponse.json();
    assert.match(replayPayload.error, /nonce already used/i);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("previous token stays valid briefly after rotation, then expires", async () => {
  const app = createApp();
  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const userAgent = "rotation-grace-client";

  try {
    const challengeResponse = await fetch(`${baseUrl}/api/challenge`, {
      headers: {
        "user-agent": userAgent,
      },
    });

    const cookie = challengeResponse.headers.get("set-cookie");
    const cookieHeader = cookie.split(";")[0];
    const challenge = await challengeResponse.json();
    const nonce = await solveChallenge(challenge);

    const verifyResponse = await fetch(`${baseUrl}/api/challenge/verify`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: cookieHeader,
        "user-agent": userAgent,
      },
      body: JSON.stringify({
        challengeId: challenge.challengeId,
        nonce,
      }),
    });

    const tokenPayload = await verifyResponse.json();
    const originalToken = tokenPayload.accessToken;

    const firstResponse = await fetch(`${baseUrl}/api/test/guarded-feed`, {
      headers: {
        ...buildSignedHeaders(originalToken, "/api/test/guarded-feed"),
        cookie: cookieHeader,
        "user-agent": userAgent,
      },
    });

    assert.equal(firstResponse.status, 200);

    const graceResponse = await fetch(`${baseUrl}/api/test/guarded-feed`, {
      headers: {
        ...buildSignedHeaders(originalToken, "/api/test/guarded-feed"),
        cookie: cookieHeader,
        "user-agent": userAgent,
      },
    });

    assert.equal(graceResponse.status, 200);

    await new Promise((resolve) => setTimeout(resolve, 5200));

    const expiredGraceResponse = await fetch(`${baseUrl}/api/test/guarded-feed`, {
      headers: {
        ...buildSignedHeaders(originalToken, "/api/test/guarded-feed"),
        cookie: cookieHeader,
        "user-agent": userAgent,
      },
    });

    assert.equal(expiredGraceResponse.status, 401);
    const expiredGracePayload = await expiredGraceResponse.json();
    assert.match(expiredGracePayload.error, /token expired|not active/i);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("copied token fails when the binding fingerprint changes", async () => {
  const app = createApp();
  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const challengeResponse = await fetch(`${baseUrl}/api/challenge`, {
      headers: {
        "user-agent": "original-client",
      },
    });

    const cookie = challengeResponse.headers.get("set-cookie");
    const cookieHeader = cookie.split(";")[0];
    const challenge = await challengeResponse.json();
    const nonce = await solveChallenge(challenge);

    const verifyResponse = await fetch(`${baseUrl}/api/challenge/verify`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: cookieHeader,
        "user-agent": "original-client",
      },
      body: JSON.stringify({
        challengeId: challenge.challengeId,
        nonce,
      }),
    });

    const tokenPayload = await verifyResponse.json();

    const replayResponse = await fetch(`${baseUrl}/api/test/guarded-feed`, {
      headers: {
        ...buildSignedHeaders(tokenPayload.accessToken, "/api/test/guarded-feed"),
        cookie: cookieHeader,
        "user-agent": "copied-client",
      },
    });

    assert.equal(replayResponse.status, 401);

    const replayPayload = await replayResponse.json();
    assert.match(replayPayload.error, /fingerprint mismatch/i);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
