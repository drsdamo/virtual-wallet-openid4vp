package io.github.wallet.presentation.support.openid4vp

import eu.europa.ec.eudi.openid4vp.X509CertificateTrust
import org.apache.logging.log4j.LogManager
import java.nio.file.Files
import java.nio.file.Path
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

/**
 * Décide si la chaîne `x5c` d'une requête signée (x509_san_dns / x509_hash) est de confiance.
 *
 * La chaîne est acceptée si elle se valide (PKIX, sans contrôle de révocation) jusqu'à l'une des [anchors],
 * ou si l'un de ses certificats est lui-même une ancre (verifiers de test auto-signés).
 *
 * @param trustAll accepte toute chaîne (tests uniquement), avec un avertissement dans les logs
 */
class VerifierTrust(
    private val anchors: List<X509Certificate>,
    private val trustAll: Boolean,
) : X509CertificateTrust {

    /** Appelé par la lib EUDI pour chaque requête signée par certificat. */
    override suspend fun isTrusted(chain: List<X509Certificate>): Boolean {
        val leaf = chain.firstOrNull()?.subjectX500Principal?.name
        if (trustAll) {
            log.warn("Trusting verifier {} without validation (wallet.trust-all-verifiers=true)", leaf)
            return true
        }
        val trusted = validates(chain)
        if (!trusted) log.warn("Untrusted verifier certificate chain {}", chain.map { it.subjectX500Principal.name })
        return trusted
    }

    private fun validates(chain: List<X509Certificate>): Boolean {
        if (chain.isEmpty() || anchors.isEmpty()) return false
        if (chain.any { it in anchors }) {
            // Le chemin jusqu'à l'ancre doit rester cohérent : on valide la partie sous l'ancre.
            val below = chain.takeWhile { it !in anchors }
            if (below.isEmpty()) return true
            return pkix(below)
        }
        return pkix(chain)
    }

    /** Validation PKIX standard du JDK ; un échec est tracé en DEBUG. */
    private fun pkix(path: List<X509Certificate>): Boolean = try {
        val certPath = CertificateFactory.getInstance("X.509").generateCertPath(path)
        val params = PKIXParameters(anchors.map { TrustAnchor(it, null) }.toSet()).apply { isRevocationEnabled = false }
        CertPathValidator.getInstance("PKIX").validate(certPath, params)
        true
    } catch (e: Exception) {
        log.debug("PKIX validation failed", e)
        false
    }

    companion object {
        private val log = LogManager.getLogger(VerifierTrust::class.java)

    }
}
