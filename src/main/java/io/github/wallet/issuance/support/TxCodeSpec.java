package io.github.wallet.issuance.support;

/**
 * Objet {@code tx_code} d'une Credential Offer : un code de transaction, transmis par un autre canal (SMS, mail…),
 * doit accompagner le {@code pre-authorized_code}.
 *
 * @param inputMode   {@code numeric} (défaut) ou {@code text}
 * @param length      longueur attendue, si l'émetteur l'indique
 * @param description indication à afficher au porteur
 */
public record TxCodeSpec(String inputMode, Integer length, String description) {
}
