// k6 load test for the login endpoint.
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID;
const CLIENT_SECRET = __ENV.CLIENT_SECRET;
const PASSWORD = __ENV.PASSWORD;
const STEADY_USER_PREFIX = __ENV.STEADY_USER_PREFIX || 'loadtest-user-';
const BURST_USERNAME = __ENV.BURST_USERNAME || 'loadtest-burst-user';

const STEADY_STATE_VUS = 20;

const authHeader = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).encode('base64');

export const rateLimitedResponses = new Counter('rate_limited_responses');
export const successfulLogins = new Counter('successful_logins');

export const options = {
  scenarios: {
    steady_state: {
      executor: 'constant-vus',
      vus: STEADY_STATE_VUS,
      duration: '2m',
      exec: 'steadyStateLogin',
    },
    rate_limiter_burst: {
      executor: 'shared-iterations',
      vus: 30,
      iterations: 30,
      startTime: '2m30s',
      exec: 'burstLogin',
    },
  },
  thresholds: {
    'successful_logins': ['count>0'],
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

  check(res, {
    'burst: status is 401 (under quota) or 429 (over quota)': (r) => r.status === 401 || r.status === 429,
  });
  if (res.status === 429) rateLimitedResponses.add(1);
}
