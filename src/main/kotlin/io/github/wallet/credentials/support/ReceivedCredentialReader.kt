package io.github.wallet.credentials.support

import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.JwtSignatureVerifier
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull
import org.multipaz.cbor.Cbor
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.cose.CoseSign1
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X509CertChain
import org.multipaz.crypto.javaPublicKey
import org.multipaz.mdoc.issuersigned.IssuerNamespaces
import org.multipaz.mdoc.mso.MobileSecurityObject
import java.security.interfaces.ECPublicKey
import java.util.Base64

/**
 * Lit un credential reçu d'un émetteur (OpenID4VCI) et le transforme en [WalletCredential] présentable.
 *
 * Formats : `dc+sd-jwt` (sérialisation compacte `<jwt>~<disclosure>~…~`) et `mso_mdoc` (`IssuerSigned` CBOR en
 * base64url, OpenID4VCI 1.0 annexe A.2). Une structure illisible lève [IllegalArgumentException] ; les contrôles
 * qui n'empêchent pas de présenter le credential (signature, lien avec la clé du porteur…) sont rendus comme
 * avertissements : le wallet sert aussi à tester ce qu'un verifier fait d'un credential défectueux.
 *
 * Kotlin : la vérification SD-JWT et le décodage COSE/MSO passent par des API `suspend` et des `Result` Kotlin.
 */
class ReceivedCredentialReader {

    /** Credential lu et anomalies relevées. */
    class Read(val credential: WalletCredential, val warnings: List<String>)

    /**
     * @param id        identifiant du credential dans le wallet
     * @param issuer    `credential_issuer` qui l'a délivré
     * @param holderKey clé dont le proof a été signé, qui doit être celle liée au credential
     */
    fun read(id: String, format: String, credential: String, issuer: String, holderKey: EcPrivateKey): Read = runBlocking {
        when (format) {
            SdJwtVcCredential.FORMAT, LEGACY_SD_JWT_FORMAT -> sdJwt(id, credential, issuer, holderKey)
            MdocCredential.FORMAT -> mdoc(id, credential, issuer, holderKey)
            else -> throw IllegalArgumentException("unsupported credential format '$format'")
        }
    }

    // ---------------------------------------------------------------- SD-JWT VC

    private suspend fun sdJwt(id: String, serialized: String, issuer: String, holderKey: EcPrivateKey): Read {
        val warnings = mutableListOf<String>()
        val jwt = try {
            SignedJWT.parse(serialized.substringBefore('~'))
        } catch (e: Exception) {
            throw IllegalArgumentException("credential is not an SD-JWT: ${e.message}", e)
        }
        val x5c = jwt.header.x509CertChain
        val verifier: JwtSignatureVerifier<SignedJWT> = if (!x5c.isNullOrEmpty()) {
            val leaf = X509CertUtils.parse(x5c.first().decode())
                ?: throw IllegalArgumentException("unreadable x5c certificate in the SD-JWT header")
            with(NimbusSdJwtOps) { ECDSAVerifier(leaf.publicKey as ECPublicKey).asJwtVerifier() }
        } else {
            warnings += "issuer signature not verified: no x5c in the SD-JWT header"
            object : JwtSignatureVerifier<SignedJWT> {
                override suspend fun checkSignature(jwt: String): SignedJWT = SignedJWT.parse(jwt)
            }
        }
        val sdJwt = with(NimbusSdJwtOps) { verify(verifier, serialized) }
            .getOrElse { throw IllegalArgumentException("invalid SD-JWT (signature or disclosures): ${it.message}", it) }

        val type = jwt.header.type?.type
        if (type != SdJwtVcCredential.FORMAT) warnings += "SD-JWT typ is '$type', expected '${SdJwtVcCredential.FORMAT}'"
        val claims = with(NimbusSdJwtOps) { sdJwt.recreateClaimsAndDisclosuresPerClaim().first }.toPlainMap()
        val vct = claims["vct"] as? String ?: throw IllegalArgumentException("SD-JWT VC without vct claim")
        if (claims["iss"] != null && claims["iss"] != issuer) warnings += "iss '${claims["iss"]}' differs from credential_issuer '$issuer'"

        val cnfJwk = (claims["cnf"] as? Map<*, *>)?.get("jwk") as? Map<*, *>
        if (cnfJwk == null) {
            warnings += "no cnf.jwk: the credential is not bound to the wallet key"
        } else if (ECKey.parse(cnfJwk.mapKeys { it.key.toString() }).toECPublicKey() != holderKey.publicKey.javaPublicKey) {
            warnings += "cnf.jwk is not the key of the proof"
        }
        return Read(SdJwtVcCredential(id, vct, sdJwt, serialized, claims, issuer, holderKey), warnings)
    }

    private fun JsonObject.toPlainMap(): Map<String, Any?> = mapValues { (_, v) -> v.toPlain() }

    private fun JsonElement.toPlain(): Any? = when (this) {
        JsonNull -> null
        is JsonObject -> toPlainMap()
        is JsonArray -> map { it.toPlain() }
        is JsonPrimitive -> if (isString) content else booleanOrNull ?: longOrNull ?: content
    }

    // ---------------------------------------------------------------- mdoc

    private suspend fun mdoc(id: String, encoded: String, issuer: String, holderKey: EcPrivateKey): Read {
        val warnings = mutableListOf<String>()
        val (namespaces, issuerAuth, mso) = try {
            val issuerSigned = Cbor.decode(Base64.getUrlDecoder().decode(encoded))
            val ns = IssuerNamespaces.fromDataItem(issuerSigned["nameSpaces"])
            val auth = CoseSign1.fromDataItem(issuerSigned["issuerAuth"])
            Triple(ns, auth, MobileSecurityObject.fromDataItem(Cbor.decode(auth.payload!!).asTaggedEncodedCbor))
        } catch (e: Exception) {
            throw IllegalArgumentException("credential is not a base64url IssuerSigned structure: ${e.message}", e)
        }

        val chain = issuerAuth.unprotectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN)]
        if (chain == null) {
            warnings += "issuer signature not verified: no x5chain in issuerAuth"
        } else {
            try {
                val alg = Algorithm.fromCoseAlgorithmIdentifier(
                    issuerAuth.protectedHeaders.getValue(CoseNumberLabel(Cose.COSE_LABEL_ALG)).asNumber.toInt(),
                )
                Cose.coseSign1Check(X509CertChain.fromDataItem(chain).certificates.first().ecPublicKey, null, issuerAuth, alg)
            } catch (e: Exception) {
                warnings += "invalid issuerAuth signature: ${e.message}"
            }
        }
        val digests = namespaces.validateAgainstMso(mso)
        if (digests.hasErrors) warnings += "digests do not match the MSO: ${digests.errors}"
        if (mso.deviceKey != holderKey.publicKey) warnings += "MSO deviceKey is not the key of the proof"

        val claims = namespaces.data.mapValues { (_, items) ->
            items.mapValues { (_, item) -> Cbor.toDiagnostics(item.dataElementValue) }
        }
        return Read(MdocCredential(id, mso.docType, issuerAuth, namespaces, claims, issuer, holderKey), warnings)
    }

    private companion object {
        /** Identifiant de format SD-JWT VC des brouillons OpenID4VCI, encore servi par certains émetteurs. */
        const val LEGACY_SD_JWT_FORMAT = "vc+sd-jwt"
    }
}
