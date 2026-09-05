import sys

path = "src/main/java/com/internal/auth/config/auth/JwtSessionTrackingFilter.java"

old = '''        String sid = extractSessionId(jwt);
        String cacheKey = sid != null ? sid : username;

        if (sessionStorage.getCache(TRACKED_CACHE, cacheKey) != null) {'''

new = '''        String sid = extractSessionId(jwt);
        String cacheKey = resolveCacheKey(sid, username);

        if (sessionStorage.getCache(TRACKED_CACHE, cacheKey) != null) {'''

with open(path, "r") as f:
    content = f.read()

count = content.count(old)
if count != 1:
    print(f"ABORT: expected exactly 1 match for the first anchor, found {count}. No changes written.", file=sys.stderr)
    sys.exit(1)

content = content.replace(old, new)

# Insert the new resolveCacheKey helper right after resolveUser's closing brace,
# anchored on the start of extractRawToken so the insertion point is unambiguous.
anchor2 = '''    private String extractRawToken(HttpServletRequest request) {'''

helper = '''    /**
     * Step 14A fix: this short-circuit cache previously fell straight back
     * to the bare username whenever a token carried no "sid" claim - which
     * is every self-issued local-login token (see class javadoc), so two
     * tenants sharing a username shared one cache entry and whichever
     * user's request landed second within TRACKED_CACHE_TTL_SECONDS had
     * its own session tracking silently skipped, even though resolveUser()
     * above already resolves the correct per-tenant User. Now prefixes the
     * username with client_application_id when the token carries that
     * claim (the same composite-key pattern LoginServiceImpl's login-MFA
     * OTP cooldown key already uses), so same-username tenants never share
     * a cache entry. A Keycloak-issued token carries no such claim and
     * falls back to the prior username-only key, unchanged.
     */
    private String resolveCacheKey(String sid, String username) {
        if (sid != null) {
            return sid;
        }
        Long clientApplicationId = authenticationHelper.getCurrentClientApplicationId();
        return clientApplicationId != null ? clientApplicationId + ":" + username : username;
    }

    private String extractRawToken(HttpServletRequest request) {'''

count2 = content.count(anchor2)
if count2 != 1:
    print(f"ABORT: expected exactly 1 match for the second anchor, found {count2}. No changes written.", file=sys.stderr)
    sys.exit(1)

content = content.replace(anchor2, helper)

with open(path, "w") as f:
    f.write(content)

print("Patched JwtSessionTrackingFilter.java: cache key is now tenant-aware for self-issued tokens.")
