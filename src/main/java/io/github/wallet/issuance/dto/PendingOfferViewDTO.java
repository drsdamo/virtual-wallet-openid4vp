package io.github.wallet.issuance.dto;

import io.github.wallet.issuance.support.IssuanceStep;
import io.github.wallet.issuance.support.TxCodeSpec;
import io.github.wallet.presentation.dto.HttpExchangeDTO;
import java.time.Instant;
import java.util.List;

/**
 * Offre reçue en attente de la décision du porteur. Pour une offre invalide, seuls {@code error} et {@code step}
 * sont renseignés (avec les échanges).
 *
 * @param tokenEndpoint      token endpoint retenu (offre, puis {@code authorization_servers}, puis l'émetteur)
 * @param dpopSigningAlgs    l'AS annonce DPoP (non géré par le wallet) : un échec au token endpoint est probable
 */
public record PendingOfferViewDTO(String id, Instant receivedAt, boolean valid, String credentialIssuer,
                                  String issuerName, List<OfferedCredentialDTO> credentials, TxCodeSpec txCode,
                                  String tokenEndpoint, String credentialEndpoint, String nonceEndpoint,
                                  List<String> dpopSigningAlgs, String offer, String error, IssuanceStep step,
                                  List<HttpExchangeDTO> exchanges) {
}
