package io.github.wallet.credentials.support;

import java.util.Map;
import org.multipaz.crypto.EcPrivateKey;

/** Credential détenu par le wallet. */
public sealed interface WalletCredential permits SdJwtVcCredential, MdocCredential {

    /** Identifiant {@code <id identité>:<suffixe>}. */
    String getId();

    /** Identifiant de format OpenID4VP ({@code dc+sd-jwt} ou {@code mso_mdoc}). */
    String getFormat();

    /** {@code vct} pour SD-JWT VC, {@code doctype} pour mdoc. */
    String getType();

    /** Claims lisibles, pour l'affichage et le matching des requêtes DCQL. */
    Map<String, Object> getClaims();

    /** Émetteur : l'autorité de test, ou le {@code credential_issuer} OpenID4VCI d'un credential reçu. */
    String getIssuer();

    /** Clé privée du porteur liée au credential ({@code cnf} / {@code deviceKey}), qui signe les présentations. */
    EcPrivateKey getHolderKey();
}
