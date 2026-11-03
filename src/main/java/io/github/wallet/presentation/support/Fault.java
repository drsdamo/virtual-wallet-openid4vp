package io.github.wallet.presentation.support;

/**
 * Défauts volontaires injectés dans une présentation, pour vérifier que le verifier les rejette.
 * Un verifier correct doit refuser toute réponse construite avec l'un de ces défauts, sauf {@link #OVER_DISCLOSURE}.
 */
public enum Fault {
    // SD-JWT VC
    SD_JWT_WRONG_NONCE("dc+sd-jwt", "KB-JWT avec un nonce différent de celui de la requête"),
    SD_JWT_WRONG_AUDIENCE("dc+sd-jwt", "KB-JWT avec un aud qui n'est pas le client_id"),
    SD_JWT_STALE_KB("dc+sd-jwt", "KB-JWT émis il y a 24 h (iat ancien)"),
    SD_JWT_BAD_KB_SIGNATURE("dc+sd-jwt", "signature du KB-JWT altérée"),
    SD_JWT_KB_WRONG_KEY("dc+sd-jwt", "KB-JWT signé par une autre clé que celle du cnf"),
    SD_JWT_NO_KB("dc+sd-jwt", "présentation sans KB-JWT"),
    SD_JWT_BAD_ISSUER_SIGNATURE("dc+sd-jwt", "signature de l'émetteur altérée"),
    SD_JWT_FORGED_DISCLOSURE("dc+sd-jwt", "disclosure modifiée (digest absent du JWT)"),
    OVER_DISCLOSURE(null, "divulgue tous les claims au lieu des seuls demandés (le verifier peut accepter)"),

    // mdoc
    MDOC_WRONG_NONCE("mso_mdoc", "SessionTranscript calculé avec un autre nonce"),
    MDOC_WRONG_CLIENT_ID("mso_mdoc", "SessionTranscript calculé avec un autre client_id"),
    MDOC_DEVICE_KEY_MISMATCH("mso_mdoc", "DeviceSignature faite avec une clé autre que celle du MSO"),
    MDOC_TAMPERED_ELEMENT("mso_mdoc", "valeur d'un élément modifiée (digest du MSO invalide)"),
    MDOC_BAD_ISSUER_SIGNATURE("mso_mdoc", "signature de l'issuerAuth altérée"),

    // vp_token
    VP_TOKEN_WRONG_QUERY_ID(null, "vp_token indexé par un id de requête DCQL inconnu");

    private final String format;
    private final String description;

    Fault(String format, String description) {
        this.format = format;
        this.description = description;
    }

    /** Format de credential concerné, {@code null} pour tous. */
    public String getFormat() {
        return format;
    }

    /** Explication affichée dans l'UI et l'API. */
    public String getDescription() {
        return description;
    }
}
