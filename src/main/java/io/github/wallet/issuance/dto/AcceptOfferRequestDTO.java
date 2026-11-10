package io.github.wallet.issuance.dto;

import io.github.wallet.issuance.support.IssuanceFault;
import java.util.List;

/**
 * Corps de {@code POST /api/offers/{id}/accept}.
 *
 * @param txCode     code de transaction, si l'offre en exige un
 * @param identityId identité à laquelle rattacher les credentials reçus ; {@code null} = la première
 * @param faults     défauts à injecter
 */
public record AcceptOfferRequestDTO(String txCode, String identityId, List<IssuanceFault> faults) {
}
