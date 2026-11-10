package io.github.wallet.issuance.support;

import java.util.List;

/**
 * Credential Offer OpenID4VCI 1.0 (§4.1.1), réduite à ce que le wallet exploite.
 *
 * @param credentialIssuer          URL de l'émetteur, qui sert à trouver ses metadata
 * @param credentialConfigurationIds credentials proposés, clés de {@code credential_configurations_supported}
 * @param preAuthorizedCode         code du grant pré-autorisé ; {@code null} si l'offre ne propose pas ce grant
 * @param txCode                    code de transaction exigé, {@code null} sinon
 * @param authorizationServer       serveur d'autorisation imposé par le grant, {@code null} sinon
 * @param authorizationCodeGrant    l'offre propose aussi (ou seulement) le grant {@code authorization_code}
 * @param json                      offre reçue, en JSON
 */
public record CredentialOffer(String credentialIssuer, List<String> credentialConfigurationIds,
                              String preAuthorizedCode, TxCodeSpec txCode, String authorizationServer,
                              boolean authorizationCodeGrant, String json) {

    /** Type de grant pré-autorisé (RFC 6749 étendue par OpenID4VCI). */
    public static final String PRE_AUTHORIZED_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    public boolean preAuthorized() {
        return preAuthorizedCode != null;
    }
}
