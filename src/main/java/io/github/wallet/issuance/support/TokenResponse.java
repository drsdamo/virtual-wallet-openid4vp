package io.github.wallet.issuance.support;

import java.util.List;
import java.util.Map;

/**
 * Réponse du token endpoint.
 *
 * @param cNonce                {@code c_nonce} des brouillons OpenID4VCI (supprimé en 1.0 au profit du nonce endpoint)
 * @param credentialIdentifiers {@code authorization_details[].credential_identifiers} par configuration ; quand
 *                              l'émetteur en renvoie, la requête credential doit utiliser {@code credential_identifier}
 */
public record TokenResponse(String accessToken, String tokenType, Long expiresIn, String cNonce,
                            Map<String, List<String>> credentialIdentifiers) {
}
