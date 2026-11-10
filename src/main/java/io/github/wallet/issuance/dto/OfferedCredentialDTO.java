package io.github.wallet.issuance.dto;

/**
 * Credential proposé par une offre, décrit par les metadata de l'émetteur.
 *
 * @param supported le wallet sait le recevoir (configuration connue, format SD-JWT VC ou mdoc)
 * @param reason    pourquoi il ne le sait pas, sinon {@code null}
 */
public record OfferedCredentialDTO(String configurationId, String format, String type, String name, boolean bound,
                                   boolean supported, String reason) {
}
