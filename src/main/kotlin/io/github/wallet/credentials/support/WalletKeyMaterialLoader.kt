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
 * Charge le [WalletKeyMaterial] persisté en PEM dans un répertoire, ou le crée au premier démarrage.
 * Seuls les éléments manquants sont générés : supprimer un fichier régénère la clé ou le certificat concerné.
 */
class WalletKeyMaterialLoader {

    private val certValidity = (3 * 365).days

    /** Charge (ou crée) l'IACA, puis le Document Signer et l'émetteur SD-JWT qu'elle certifie, puis la clé du porteur. */
    fun loadOrCreate(directory: Path): WalletKeyMaterial = runBlocking {
        Files.createDirectories(directory)
        val store = PemStore(directory)
        val now = Clock.System.now()

        val iaca = store.certified("iaca") { key ->
            MdocUtil.generateIacaCertificate(
                iacaKey = AsymmetricKey.anonymous(key),
                subject = X500Name.fromName("CN=Virtual Wallet Test IACA,O=Virtual Wallet (TEST ONLY),C=FR"),
                serial = ASN1Integer.fromRandom(128),
                validFrom = now,
                validUntil = now + certValidity,
                issuerAltNameUrl = "https://issuer.virtual-wallet.test",
                crlUrl = "https://issuer.virtual-wallet.test/crl",
            ).let { X509CertChain(listOf(it)) }
        }
        val documentSigner = store.certified("mdoc-ds") { key ->
            MdocUtil.generateDsCertificate(
                iacaKey = iaca,
                dsKey = key.publicKey,
                subject = X500Name.fromName("CN=Virtual Wallet Test mdoc DS,O=Virtual Wallet (TEST ONLY),C=FR"),
                serial = ASN1Integer.fromRandom(128),
                validFrom = now,
                validUntil = now + certValidity,
            ).let { X509CertChain(listOf(it, iaca.certChain.certificates.first())) }
        }
        val sdJwtIssuer = store.certified("sd-jwt-issuer") { key ->
            sdJwtIssuerCertificate(iaca, key.publicKey, now)
                .let { X509CertChain(listOf(it, iaca.certChain.certificates.first())) }
        }
        WalletKeyMaterial(iaca, documentSigner, sdJwtIssuer, store.key("device"))
    }

    /** Certificat de l'émetteur SD-JWT VC, signé par l'IACA (Multipaz n'a pas d'aide dédiée). */
    private suspend fun sdJwtIssuerCertificate(
        iaca: AsymmetricKey.X509Certified,
        publicKey: EcPublicKey,
        now: Instant,
    ): X509Cert {
        val iacaCert = iaca.certChain.certificates.first()
        return X509Cert.Builder(
            publicKey = publicKey,
            signingKey = iaca,
            serialNumber = ASN1Integer.fromRandom(128),
            subject = X500Name.fromName("CN=Virtual Wallet Test SD-JWT VC Issuer,O=Virtual Wallet (TEST ONLY),C=FR"),
            issuer = iacaCert.subject,
            validFrom = now,
            validUntil = now + certValidity,
        )
            .includeSubjectKeyIdentifier()
            .setAuthorityKeyIdentifierToCertificate(iacaCert)
            .setKeyUsage(setOf(X509KeyUsage.DIGITAL_SIGNATURE))
            .build()
    }
}
