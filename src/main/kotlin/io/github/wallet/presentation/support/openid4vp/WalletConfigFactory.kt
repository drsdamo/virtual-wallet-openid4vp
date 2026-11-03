package io.github.wallet.presentation.support.openid4vp

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.openid4vp.CoseAlgorithm
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionConfiguration
import eu.europa.ec.eudi.openid4vp.SignedRequestConfiguration
import eu.europa.ec.eudi.openid4vp.SupportedClientIdPrefix
import eu.europa.ec.eudi.openid4vp.VpFormatsSupported
import eu.europa.ec.eudi.openid4vp.X509CertificateTrust

/**
 * Construit la [OpenId4VPConfig] de la lib EUDI. Écrite en Kotlin car cette configuration repose sur des
 * arguments par défaut, des value classes et des interfaces fonctionnelles `suspend` que Java ne sait pas exprimer.
 *
 * Le wallet accepte les préfixes x509_san_dns, x509_hash et redirect_uri, les formats SD-JWT VC (profil HAIP)
 * et mdoc (ES256), et les réponses chiffrées ECDH-ES (A128GCM / A256GCM).
 */
class WalletConfigFactory {

    /** COSE ES256 (RFC 9053). */
    private val COSE_ES256 = CoseAlgorithm(-7)

    /** Configuration sans ancre de confiance : seul [trustAllVerifiers] permet d'accepter une requête x509. */
    fun create(trustAllVerifiers: Boolean): OpenId4VPConfig = create(VerifierTrust(emptyList(), trustAllVerifiers))

    /** Configuration avec la politique de confiance [trust] pour les clients x509. */
    fun create(trust: X509CertificateTrust): OpenId4VPConfig {
        return OpenId4VPConfig(
            supportedClientIdPrefixes = listOf(
                SupportedClientIdPrefix.X509SanDns(trust),
                SupportedClientIdPrefix.X509Hash(trust),
                SupportedClientIdPrefix.RedirectUri,
            ),
            vpFormatsSupported = VpFormatsSupported(
                sdJwtVc = VpFormatsSupported.SdJwtVc.HAIP,
                msoMdoc = VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(COSE_ES256),
                    deviceAuthAlgorithms = listOf(COSE_ES256),
                ),
            ),
            signedRequestConfiguration = SignedRequestConfiguration(
                supportedAlgorithms = listOf(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512, JWSAlgorithm.RS256),
            ),
            responseEncryptionConfiguration = ResponseEncryptionConfiguration.Supported(
                supportedAlgorithms = listOf(JWEAlgorithm.ECDH_ES),
                supportedMethods = listOf(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM),
            ),
        )
    }
}
