package io.github.wallet.issuance.support;

import java.util.List;

/**
 * Metadata OAuth du serveur d'autorisation (RFC 8414), réduites au token endpoint.
 *
 * @param dpopSigningAlgs {@code dpop_signing_alg_values_supported} : DPoP n'est pas géré, l'information est affichée
 * @param url             URL d'où les metadata ont été lues
 */
public record AuthorizationServerMetadata(String issuer, String tokenEndpoint, List<String> dpopSigningAlgs, String url) {
}
