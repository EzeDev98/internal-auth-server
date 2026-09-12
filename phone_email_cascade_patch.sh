#!/bin/bash
set -e

python3 << 'PYEOF'
import io

def patch(path, old, new, label):
    with io.open(path, "r", encoding="utf-8") as f:
        content = f.read()
    count = content.count(old)
    if count != 1:
        raise SystemExit(f"ABORT [{label}]: expected 1 match in {path}, found {count}. File may have already been patched or has diverged — check manually.")
    content = content.replace(old, new, 1)
    with io.open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Patched: {path} ({label})")

# 1. PhoneVerificationServiceImpl.verify() — cascade phoneVerified -> emailVerified.
#    Deliberately one-directional: see EmailVerificationServiceImpl's own
#    activate() (left untouched) for why the reverse cascade is NOT done -
#    phoneVerified also gates MfaAdminServiceImpl's SMS-MFA-enable check,
#    so treating an unverified phone as verified just because the email
#    was confirmed would let SMS MFA be enabled on a number nobody proved
#    they control. phoneVerified -> emailVerified carries no equivalent
#    risk: emailVerified gates nothing security-sensitive today.
patch(
    "src/main/java/com/internal/auth/feature/identity/service/impl/PhoneVerificationServiceImpl.java",
    '''        user.setPhoneVerified(true);
        userRepository.save(user);

        log.info("Phone number verified for user id {}", user.getId());
        return new ActivationResponse("Your phone number has been verified.");''',
    '''        user.setPhoneVerified(true);

        // Product decision: verifying phone is sufficient proof of account
        // ownership to also clear the email leg of the login gate (see
        // User's class Javadoc / UserLoginServiceImpl#describeUnverifiedContactMethods)
        // for an account that supplied both. Deliberately one-directional -
        // EmailVerificationServiceImpl#activate does NOT set phoneVerified
        // in return, since phoneVerified also gates MfaAdminServiceImpl's
        // SMS-MFA-enable check and email verification is not proof anyone
        // received anything at the phone number on file.
        if (user.getEmail() != null && !user.getEmail().isBlank() && !user.isEmailVerified()) {
            user.setEmailVerified(true);
            log.info("Email auto-verified for user id {} via phone verification", user.getId());
        }

        userRepository.save(user);

        log.info("Phone number verified for user id {}", user.getId());
        return new ActivationResponse("Your phone number has been verified.");''',
    "PhoneVerificationServiceImpl.verify cascade"
)

# 2. UserLoginServiceImpl — fix the stray doc comment on describeUnverifiedContactMethods
#    that was already wrong before this change (claimed "either is sufficient"
#    while the code required both). Now that phone-verification actively sets
#    emailVerified too, leaving that comment would make it look accidentally
#    correct again for the wrong reason - so it's corrected to describe what
#    the method itself actually does: a strict per-field AND check, with the
#    OR-like end-user experience coming from the cascade above it, not from here.
patch(
    "src/main/java/com/internal/auth/feature/identity/service/impl/UserLoginServiceImpl.java",
    '''    /**
     * Blocks login only when the user has verified none of the contact
     * methods they supplied at registration - not when any one of several
     * is still unverified. Verifying either email or phone is sufficient;
     * a user who verified their email is never forced to also verify a
     * phone number they also happened to register with, and vice versa.
     */
    private String describeUnverifiedContactMethods(User user) {''',
    '''    /**
     * Strict per-field gate: blocks login if ANY contact method the user
     * supplied at registration is still unverified, per User's class
     * Javadoc (Step 10E) - an account with both phone and email needs
     * both flags true. This method itself never treats one as a
     * substitute for the other. The reason verifying phone alone is
     * often enough in practice is PhoneVerificationServiceImpl#verify,
     * which auto-sets emailVerified too as a deliberate, one-directional
     * product decision (see that method's comment for why the reverse
     * isn't also done) - by the time this runs, that account's
     * emailVerified may already be true for a reason unrelated to the
     * email flow itself.
     */
    private String describeUnverifiedContactMethods(User user) {''',
    "UserLoginServiceImpl stray comment fix"
)

print("All patches applied successfully.")
PYEOF

echo ""
echo "Done. Behavior change: verifying phone now also marks email as verified"
echo "(when an email is on file and wasn't already verified). Verifying email"
echo "alone still does NOT auto-verify phone - that account still needs the"
echo "phone OTP flow before login succeeds, and before SMS MFA can be enabled."
