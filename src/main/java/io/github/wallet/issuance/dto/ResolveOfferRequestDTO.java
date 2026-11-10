package io.github.wallet.issuance.dto;

/**
 * Corps de {@code POST /api/offers}.
 *
 * @param offer {@code openid-credential-offer://…} (contenu du QR code), lien https équivalent, ou JSON de l'offre
 */
public record ResolveOfferRequestDTO(String offer) {
}
