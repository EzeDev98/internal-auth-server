// k6 load test for login during signing key rotation.
import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID;
const CLIENT_SECRET = __ENV.CLIENT_SECRET;
const PASSWORD = __ENV.PASSWORD;
const STEADY_USER_PREFIX = __ENV.STEADY_USER_PREFIX || 'loadtest-user-';
const ADMIN_USERNAME = __ENV.ADMIN_USERNAME;
const ADMIN_PASSWORD = __ENV.ADMIN_PASSWORD;

const REGULAR_USER_COUNT = 5;

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
