package io.github.wallet.issuance.support;

import java.util.List;

/**
 * Entrée de {@code credential_configurations_supported} dans les metadata de l'émetteur.
 *
 * @param id                 identifiant de la configuration
 * @param format             {@code dc+sd-jwt}, {@code mso_mdoc}…
 * @param type               {@code vct} (SD-JWT VC) ou {@code doctype} (mdoc)
 * @param proofSigningAlgs   algorithmes acceptés pour un proof {@code jwt} ; {@code null} si l'émetteur ne demande
 *                           pas de preuve de possession (credential non lié à une clé)
 * @param displayName        nom affichable ({@code credential_metadata.display[0].name}), s'il existe
 */
public record CredentialConfiguration(String id, String format, String type, List<String> proofSigningAlgs,
                                      String displayName) {

    /** L'émetteur attend un proof JWT : le credential sera lié à une clé du wallet. */
    public boolean proofRequired() {
        return proofSigningAlgs != null;
    }
}
