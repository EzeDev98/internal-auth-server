package com.internal.auth.common.email;

/**
 * Decoupled abstraction for delivering transactional email - starting with
 * the email-verification link (Step 10C). The Stage 1 assessment (§25)
 * flagged that no email-provider abstraction exists anywhere in this
 * codebase, only an SMS one (OtpDeliveryService, common.reset.delivery);
 * this is meant to be the one home for email delivery generally, not a
 * single-purpose one-off, so it isn't named/scoped to verification only.
 *
 * <p>Step 15F: takes the calling app's display name
 * (ClientApplication.name, e.g. "SyncPoint"/"Notare") for the same reason
 * OtpDeliveryService's send methods already do - so the email is branded
 * per app rather than one fixed global sender name. See
 * MailjetEmailDeliveryService.
 */
public interface EmailDeliveryService {

    /**
     * Send an email-verification link to the given address.
     *
     * @param email            the recipient's email address
     * @param verificationLink the full, ready-to-click activation URL
     *                         (already includes the raw token)
     * @param appName          the calling app's display name, for email
     *                         branding (sender name and message copy)
     */
    void sendVerificationEmail(String email, String verificationLink, String appName);
}