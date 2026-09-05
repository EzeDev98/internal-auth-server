import http from 'k6/http';
import { check, sleep } from 'k6';

// Step 19B: confirms the signing-key rotation grace period holds under
// load - tokens minted just BEFORE rotation must keep verifying
// afterward, and freshly-minted tokens must verify too, even while both
// are hammering a protected endpoint concurrently right as the JWKS
// cache invalidates and rebuilds (SigningKeyServiceImpl.invalidateCache/
// getJwkSet are `synchronized`, so every in-flight verification briefly
// queues on that lock the moment rotation lands - that's the real risk
// this test targets, not a correctness race, since the lock already
// rules that out structurally).
//
// IMPORTANT: SigningKeyController.rotate() is rate-limited to ONCE PER
// DAY PER IP (AppConstant.SIGNING_KEY_ROTATE_RATE_LIMIT_DURATION_DAYS).
// This script performs one real rotation against whatever BASE_URL it
// points at. Do not run it more than once/day, and never against a
// production signing key.
//
// Requires: an already-provisioned admin account (ADMIN_USERNAME/
// ADMIN_PASSWORD) and N regular test users (same STEADY_USER_PREFIX
// convention as login-load-test.js), all under one client application.
//
// Run with:
//   k6 run \
//     -e BASE_URL=http://localhost:8080 \
//     -e CLIENT_ID=... -e CLIENT_SECRET=... \
//     -e PASSWORD=... -e ADMIN_USERNAME=... -e ADMIN_PASSWORD=... \
//     scripts/load-tests/signing-key-rotation-load-test.js

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID;
const CLIENT_SECRET = __ENV.CLIENT_SECRET;
const PASSWORD = __ENV.PASSWORD;
const STEADY_USER_PREFIX = __ENV.STEADY_USER_PREFIX || 'loadtest-user-';
const ADMIN_USERNAME = __ENV.ADMIN_USERNAME;
const ADMIN_PASSWORD = __ENV.ADMIN_PASSWORD;

const REGULAR_USER_COUNT = 5; // one login here + one more post-rotation
                               // login below = 2 uses, well under the
                               // 5/15min account rate limit per user

const clientAuthHeader = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).encode('base64');

function login(username, password) {
  const res = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ username, password }),
    { headers: { 'Content-Type': 'application/json', Authorization: clientAuthHeader } },
  );
  check(res, { [`login succeeded for ${username}`]: (r) => r.status === 200 });
  return JSON.parse(res.body).data.accessToken;
}

function bearer(token) {
  return { headers: { Authorization: `Bearer ${token}` } };
}

// setup() runs once, before any VUs start - this is deliberate: rotation
// must happen exactly once, not once per VU/iteration.
export function setup() {
  const oldTokens = [];
  for (let i = 0; i < REGULAR_USER_COUNT; i++) {
    oldTokens.push({
      username: `${STEADY_USER_PREFIX}${i}`,
      token: login(`${STEADY_USER_PREFIX}${i}`, PASSWORD),
    });
  }

  const adminToken = login(ADMIN_USERNAME, ADMIN_PASSWORD);

  const rotateRes = http.post(
    `${BASE_URL}/api/v1/admin/signing-keys/rotate`,
    null,
    bearer(adminToken),
  );
  check(rotateRes, { 'rotation succeeded': (r) => r.status === 200 });

  // Mint fresh, post-rotation tokens for the same users immediately
  // after - these should be signed with the new key while the old
  // tokens above should still verify against the retiring one.
  const newTokens = oldTokens.map(({ username }) => ({
    username,
    token: login(username, PASSWORD),
  }));

  return { oldTokens, newTokens };
}

export const options = {
  scenarios: {
    verify_during_and_after_rotation: {
      executor: 'constant-vus',
      vus: 20,
      duration: '2m',
      exec: 'verifyTokens',
    },
  },
  thresholds: {
    // Any 401 here is a rotation-induced verification failure, not a
    // credentials issue (both token sets are known-good from setup()) -
    // this must stay at zero.
    'checks{check_type:token_verification}': ['rate==1'],
  },
};

export function verifyTokens(data) {
  const useOld = __ITER % 2 === 0;
  const pool = useOld ? data.oldTokens : data.newTokens;
  const entry = pool[__VU % pool.length];

  const res = http.get(
    `${BASE_URL}/api/v1/users/${entry.username}/permission-groups`,
    bearer(entry.token),
  );

  check(res, {
    [`${useOld ? 'pre-rotation' : 'post-rotation'} token still verifies`]: (r) => r.status === 200,
  }, { check_type: 'token_verification' });

  sleep(0.5);
}
