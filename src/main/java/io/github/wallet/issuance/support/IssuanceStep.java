package io.github.wallet.issuance.support;

/** Étapes du flux OpenID4VCI pré-autorisé, pour situer une erreur. */
public enum IssuanceStep {
    /** Lecture de la Credential Offer (par valeur ou {@code credential_offer_uri}). */
    OFFER,
    /** {@code /.well-known/openid-credential-issuer}. */
    ISSUER_METADATA,
    /** {@code /.well-known/oauth-authorization-server} (ou {@code openid-configuration}). */
    AUTHORIZATION_SERVER_METADATA,
    /** Échange du {@code pre-authorized_code} contre un access token. */
    TOKEN,
    /** Obtention d'un {@code c_nonce} au nonce endpoint. */
    NONCE,
    /** Credential endpoint. */
    CREDENTIAL,
    /** Lecture et contrôle du credential reçu. */
    VALIDATION,
    /** Notification endpoint ({@code credential_accepted}). */
    NOTIFICATION
}
