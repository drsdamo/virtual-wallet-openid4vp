package io.github.wallet.credentials.support;

import java.util.Map;

/** Credential détenu par le wallet. */
public sealed interface WalletCredential permits SdJwtVcCredential, MdocCredential {

    /** Identifiant {@code <id identité>:<type>}. */
    String getId();

    /** Identifiant de format OpenID4VP ({@code dc+sd-jwt} ou {@code mso_mdoc}). */
    String getFormat();

    /** {@code vct} pour SD-JWT VC, {@code doctype} pour mdoc. */
    String getType();

    /** Claims lisibles, pour l'affichage et le matching des requêtes DCQL. */
    Map<String, Object> getClaims();
}
