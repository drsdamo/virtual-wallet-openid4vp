package io.github.wallet.issuance.dto;

import java.time.Instant;
import java.util.List;

/**
 * Credential reçu par OpenID4VCI, tel que stocké en base.
 *
 * @param credential sérialisation reçue de l'émetteur (SD-JWT compact, ou IssuerSigned mdoc en base64url)
 * @param holderKey  JWK privée de la clé du porteur liée au credential
 * @param warnings   anomalies relevées à la réception (signature non vérifiée, cnf différent de la clé…)
 */
public record ReceivedCredentialDTO(String id, String identityId, String credentialIssuer, String configurationId,
                                    String format, String credential, String holderKey, List<String> warnings,
                                    Instant receivedAt) {
}
