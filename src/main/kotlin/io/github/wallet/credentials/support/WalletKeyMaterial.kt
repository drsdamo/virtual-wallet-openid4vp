package io.github.wallet.credentials.support

import kotlinx.coroutines.runBlocking
import org.multipaz.asn1.ASN1Integer
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.crypto.X509KeyUsage
import org.multipaz.mdoc.util.MdocUtil
import java.nio.file.Files
import java.nio.file.Path
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/**
 * Clés et certificats de la fausse autorité d'émission et du wallet.
 *
 * ```
 * IACA de test (racine auto-signée, profil ISO 18013-5)
 *  ├── Document Signer mdoc  → signe le MSO des credentials mdoc
 *  └── Émetteur SD-JWT VC    → signe les credentials SD-JWT VC (en-tête x5c)
 * Clé du porteur             → liée à chaque credential (cnf / deviceKey)
 * ```
 *
 * Persistés en PEM par [WalletKeyMaterialLoader] pour que les verifiers n'aient à faire confiance à la racine
 * qu'une fois : la régénérer à chaque démarrage les obligerait à reconfigurer leur liste de confiance.
 */
class WalletKeyMaterial internal constructor(
    val iaca: AsymmetricKey.X509Certified,
    val documentSigner: AsymmetricKey.X509Certified,
    val sdJwtIssuer: AsymmetricKey.X509Certified,
    /** Clé du porteur, liée à chaque credential. */
    val devicePrivateKey: EcPrivateKey,
) {
    /** Clé du porteur au format Multipaz, pour signer la DeviceResponse mdoc. */
    val deviceKey: AsymmetricKey get() = AsymmetricKey.anonymous(devicePrivateKey)

    /** Certificat racine de l'autorité de test. */
    val iacaCertificate: X509Cert get() = iaca.certChain.certificates.first()

    /** Certificat racine, en PEM, à installer dans le magasin de confiance du verifier. */
    fun iacaCertificatePem(): String = iacaCertificate.toPem()

    /** Clé publique du porteur (`cnf` SD-JWT, `deviceKey` du MSO). */
    val devicePublicKey: EcPublicKey get() = devicePrivateKey.publicKey
}

/**
 * Fichiers `<nom>.key.pem` (+ `<nom>.pub.pem`) et `<nom>.chain.pem` d'un répertoire.
 * Un fichier absent est généré ; un fichier présent est relu tel quel.
 */
internal class PemStore(private val dir: Path) {

    /** Clé EC P-256 `name`, créée si elle n'existe pas. */
    suspend fun key(name: String): EcPrivateKey {
        val keyFile = dir.resolve("$name.key.pem")
        val pubFile = dir.resolve("$name.pub.pem")
        if (Files.exists(keyFile) && Files.exists(pubFile)) {
            return EcPrivateKey.fromPem(Files.readString(keyFile), EcPublicKey.fromPem(Files.readString(pubFile)))
        }
        val key = Crypto.createEcPrivateKey(EcCurve.P256)
        Files.writeString(keyFile, key.toPem())
        Files.writeString(pubFile, key.publicKey.toPem())
        return key
    }

    /** Clé `name` et sa chaîne de certificats ; [issue] n'est appelé que si la chaîne n'est pas encore sur disque. */
    suspend fun certified(
        name: String,
        issue: suspend (EcPrivateKey) -> X509CertChain,
    ): AsymmetricKey.X509Certified {
        val key = key(name)
        val chainFile = dir.resolve("$name.chain.pem")
        val chain = if (Files.exists(chainFile)) {
            X509CertChain(splitPem(Files.readString(chainFile)).map { X509Cert.fromPem(it) })
        } else {
            issue(key).also { c -> Files.writeString(chainFile, c.certificates.joinToString("") { it.toPem() }) }
        }
        return AsymmetricKey.X509CertifiedExplicit(chain, key)
    }

    /** Découpe un fichier PEM contenant plusieurs certificats. */
    private fun splitPem(pem: String): List<String> =
        Regex("-----BEGIN CERTIFICATE-----[\\s\\S]+?-----END CERTIFICATE-----").findAll(pem).map { it.value }.toList()
}
