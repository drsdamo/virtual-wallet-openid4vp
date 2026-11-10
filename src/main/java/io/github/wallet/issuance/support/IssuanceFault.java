package io.github.wallet.issuance.support;

/**
 * Défauts injectables dans le flux d'émission, pour vérifier qu'un émetteur les refuse.
 * Un émetteur correct doit rejeter la requête (sauf {@link #TOKEN_REPLAY}, contrôlé à part).
 */
public enum IssuanceFault {
    PROOF_WRONG_AUDIENCE("proof JWT : aud n'est pas le credential_issuer"),
    PROOF_WRONG_NONCE("proof JWT : nonce altéré"),
    PROOF_NO_NONCE("proof JWT : claim nonce absent alors que l'émetteur publie un nonce endpoint"),
    PROOF_STALE("proof JWT : iat daté de la veille"),
    PROOF_WRONG_TYP("proof JWT : typ JWT au lieu de openid4vci-proof+jwt"),
    PROOF_BAD_SIGNATURE("proof JWT : signature altérée"),
    PROOF_KEY_MISMATCH("proof JWT : signé par une autre clé que le jwk de l'en-tête"),
    ACCESS_TOKEN_TAMPERED("credential endpoint : access token altéré"),
    TOKEN_REPLAY("token endpoint : rejoue le pre-authorized_code après usage (il doit être refusé)");

    private final String description;

    IssuanceFault(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
