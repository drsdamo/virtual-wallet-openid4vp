package io.github.wallet.presentation.dto;

/**
 * Verifier tel que vu par le wallet après authentification de la requête.
 *
 * @param clientId          client_id complet, préfixe compris (par ex. {@code x509_san_dns:verifier.example})
 * @param legalName         CN du certificat qui signe la requête, pour les préfixes x509
 * @param responseMode      {@code direct_post}, {@code direct_post.jwt}…
 * @param encryptedResponse la réponse doit être chiffrée (JWE ECDH-ES)
 */
public record VerifierInfoDTO(String clientId, String prefix, String legalName, String responseMode,
                              String responseUri, boolean encryptedResponse) {
}
