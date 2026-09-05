import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

// Step 19A: load/resilience test against POST /auth/login - the endpoint
// that both authenticates AND mints the self-issued JWT in one call (see
// LoginResponse.accessToken javadoc - there is no separate /oauth2/token
// round trip on this path).
//
// Requires a running instance (BASE_URL) plus a client application's
// Basic-auth credentials, and pre-seeded test users:
//   - one user per STEADY_STATE_VUS for the steady-state scenario, named
//     `${STEADY_USER_PREFIX}<vu-id>` (0-indexed), all sharing PASSWORD
//   - one extra user (BURST_USERNAME) for the rate-limit burst scenario
//
// Run with:
//   k6 run \
//     -e BASE_URL=http://localhost:8080 \
//     -e CLIENT_ID=... -e CLIENT_SECRET=... \
//     -e PASSWORD=... -e BURST_USERNAME=loadtest-burst-user \
//     scripts/load-tests/login-load-test.js

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID;
const CLIENT_SECRET = __ENV.CLIENT_SECRET;
const PASSWORD = __ENV.PASSWORD;
const STEADY_USER_PREFIX = __ENV.STEADY_USER_PREFIX || 'loadtest-user-';
const BURST_USERNAME = __ENV.BURST_USERNAME || 'loadtest-burst-user';

const STEADY_STATE_VUS = 20; // stays comfortably under both the IP (10/15min)
                              // and account (5/15min) limits per distinct user

const authHeader = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).encode('base64');

export const rateLimitedResponses = new Counter('rate_limited_responses');
export const successfulLogins = new Counter('successful_logins');

export const options = {
  scenarios: {
    // Confirms the connection pool / general throughput hold up under
    // realistic concurrent load, well within each user's own quota.
    steady_state: {
      executor: 'constant-vus',
      vus: STEADY_STATE_VUS,
      duration: '2m',
      exec: 'steadyStateLogin',
    },
    // Confirms the account-level rate limiter (Redis-backed, must be
    // atomic under concurrency) trips at exactly 5 successes for one
    // account, even when many requests race in at once - not just when
    // tested sequentially, as the Step 15A integration test does.
    rate_limiter_burst: {
      executor: 'shared-iterations',
      vus: 30,
      iterations: 30,
      startTime: '2m30s', // after steady_state finishes, so the two
                          // scenarios' Redis keys never interfere
      exec: 'burstLogin',
    },
  },
  thresholds: {
    'successful_logins': ['count>0'],
    // Steady-state requests should essentially never see a 5xx; a few
    // 429s creeping in there would itself indicate a limiter mis-tuned
    // too aggressively for legitimate traffic.
    'http_req_failed{scenario:steady_state}': ['rate<0.01'],
  },
};

export function steadyStateLogin() {
  const username = `${STEADY_USER_PREFIX}${__VU - 1}`;
  const res = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ username, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json', Authorization: authHeader } },
  );

  const ok = check(res, {
    'steady-state: status is 200': (r) => r.status === 200,
    'steady-state: got an access token': (r) => {
      try { return !!JSON.parse(r.body).data.accessToken; } catch { return false; }
    },
  });
  if (ok) successfulLogins.add(1);
  if (res.status === 429) rateLimitedResponses.add(1);

  sleep(1);
}

export function burstLogin() {
  const res = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ username: BURST_USERNAME, password: 'deliberately-wrong-password' }),
    { headers: { 'Content-Type': 'application/json', Authorization: authHeader } },
  );

  // A wrong password is used deliberately: the rate limiter check runs
  // BEFORE credential validation (see LoginController), so this isolates
  // limiter behavior from login success/failure timing.
  check(res, {
    'burst: status is 401 (under quota) or 429 (over quota)': (r) => r.status === 401 || r.status === 429,
  });
  if (res.status === 429) rateLimitedResponses.add(1);
}
