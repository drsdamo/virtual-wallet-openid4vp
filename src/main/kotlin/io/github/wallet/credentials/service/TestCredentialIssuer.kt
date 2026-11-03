package io.github.wallet.credentials.service

import io.github.wallet.identity.dto.IdentityClaimDTO
import io.github.wallet.identity.support.ClaimType

import io.github.wallet.credentials.support.MdocCredential
import io.github.wallet.credentials.support.SdJwtVcCredential
import io.github.wallet.credentials.support.WalletCredential
import io.github.wallet.credentials.support.WalletKeyMaterial
import io.github.wallet.identity.dto.IdentityDTO
import io.github.wallet.identity.support.ClaimScope

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.cnf
import eu.europa.ec.eudi.sdjwt.dsl.values.sdJwt
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObjectBuilder
import kotlinx.coroutines.runBlocking
import org.apache.logging.log4j.LogManager
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.buildCborArray
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.toDataItem
import org.multipaz.cbor.toDataItemFullDate
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseLabel
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.cose.toCoseLabel
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.javaPrivateKey
import org.multipaz.crypto.javaPublicKey
import org.multipaz.mdoc.issuersigned.IssuerNamespaces
import org.multipaz.mdoc.issuersigned.buildIssuerNamespaces
import org.multipaz.mdoc.mso.MobileSecurityObject
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import javax.imageio.ImageIO
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/**
 * Émet les credentials de test du wallet, signés par la fausse autorité de [WalletKeyMaterial] :
 *
 * - PID en SD-JWT VC (`urn:eudi:pid:1`) ;
 * - PID en mdoc (`eu.europa.ec.eudi.pid.1`) ;
 * - mDL en mdoc (`org.iso.18013.5.1.mDL`).
 *
 * Tous sont liés à la clé du porteur ([WalletKeyMaterial.devicePublicKey]) : `cnf` en SD-JWT, `deviceKey` dans le MSO.
 */
class TestCredentialIssuer(private val keys: WalletKeyMaterial) {

    /** Émet le PID (SD-JWT VC et mdoc) et le mDL de [identity]. Identifiants : `<id identité>:<type>`. */
    fun issueFor(identity: IdentityDTO): List<WalletCredential> = runBlocking {
        // ISO 18013-5 interdit les fractions de seconde dans les dates du MSO.
        val now = Instant.fromEpochSeconds(Clock.System.now().epochSeconds)
        val subject = Subject(identity)
        listOf(issuePidSdJwt(subject, now), issuePidMdoc(subject, now), issueMdl(subject, now)).also { issued ->
            log.info("Issued {} credentials for identity {}", issued.size, identity.id())
            issued.forEach { log.debug("Issued {} ({} {}) claims={}", it.id, it.format, it.type, it.claims) }
        }
    }

    /** Champs de l'identité convertis pour l'émission. */
    private class Subject(val identity: IdentityDTO) {
        val id: String = identity.id()
        val birthDate = LocalDate.parse(identity.birthDate().toString())
        val documentNumber = "TEST-" + id.take(8).uppercase()
        /** Claims additionnels destinés à [scope] (ceux en `ALL` compris). */
        fun claims(scope: ClaimScope) = identity.claims().filter { it.scope() == ClaimScope.ALL || it.scope() == scope }
    }

    // ---------------------------------------------------------------- SD-JWT VC

    /** PID SD-JWT VC signé par l'émetteur de test, avec la chaîne `x5c` dans l'en-tête. */
    private suspend fun issuePidSdJwt(subject: Subject, now: Instant): SdJwtVcCredential {
        val holderJwk = ECKey.Builder(Curve.P_256, keys.devicePublicKey.javaPublicKey as ECPublicKey).build()
        val identity = subject.identity
        val spec = sdJwt {
            claim("iss", ISSUER_URL)
            claim("vct", PID_VCT)
            claim("iat", now.epochSeconds)
            claim("exp", (now + VALIDITY).epochSeconds)
            cnf(holderJwk)
            // Les métadonnées du type PID (urn:eudi:pid:1) marquent tous les autres claims "sd": "always" : jamais en clair.
            sdClaim("issuing_authority", ISSUING_AUTHORITY)
            sdClaim("issuing_country", ISSUING_COUNTRY)
            sdClaim("family_name", identity.familyName())
            sdClaim("given_name", identity.givenName())
            sdClaim("birthdate", subject.birthDate.toString())
            sdClaim("personal_administrative_number", subject.documentNumber)
            sdObjClaim("age_equal_or_over") {
                sdClaim("18", subject.birthDate.isAtLeast(18, now))
            }
            sdClaim("age_in_years", subject.birthDate.ageAt(now))
            addClaimTree(this, subject.claims(ClaimScope.SD_JWT).map { it.name().split('.') to it.toJson() })
        }

        val signerKey = (keys.sdJwtIssuer as AsymmetricKey.X509CertifiedExplicit).privateKey as EcPrivateKey
        val x5c = keys.sdJwtIssuer.certChain.certificates
            .dropLast(1) // la racine n'est pas envoyée : le verifier doit déjà lui faire confiance
            .map { Base64.encode(it.encoded.toByteArray()) }
        val issued = with(NimbusSdJwtOps) {
            issuer(
                signer = ECDSASigner(signerKey.javaPrivateKey as ECPrivateKey),
                signAlgorithm = JWSAlgorithm.ES256,
            ) {
                type(JOSEObjectType(SdJwtVcCredential.FORMAT))
                x509CertChain(x5c)
            }.issue(spec).getOrThrow()
        }
        val serialized = with(NimbusSdJwtOps) { issued.serialize() }
        val claims = with(NimbusSdJwtOps) { issued.recreateClaimsAndDisclosuresPerClaim().first }
        return SdJwtVcCredential("${subject.id}:pid-sd-jwt", PID_VCT, issued, serialized, claims.toPlainMap())
    }

    /** Les noms pointés deviennent des objets imbriqués, chaque niveau étant divulgable séparément. */
    private fun addClaimTree(builder: SdJwtObjectBuilder, claims: List<Pair<List<String>, JsonElement>>) {
        claims.filter { it.first.size == 1 }.forEach { (path, value) -> builder.sdClaim(path[0], value) }
        claims.filter { it.first.size > 1 }.groupBy { it.first[0] }.forEach { (name, children) ->
            builder.sdObjClaim(name) { addClaimTree(this, children.map { it.first.drop(1) to it.second }) }
        }
    }

    // ---------------------------------------------------------------- mdoc

    /** PID mdoc : éléments obligatoires du namespace PID, puis claims additionnels `MDOC`/`ALL`. */
    private suspend fun issuePidMdoc(subject: Subject, now: Instant): MdocCredential {
        val identity = subject.identity
        val ns = buildIssuerNamespaces {
            addNamespace(PID_DOCTYPE) {
                addDataElement("family_name", identity.familyName().toDataItem())
                addDataElement("given_name", identity.givenName().toDataItem())
                addDataElement("birth_date", subject.birthDate.toDataItemFullDate())
                addDataElement("age_over_18", subject.birthDate.isAtLeast(18, now).toDataItem())
                addDataElement("age_in_years", subject.birthDate.ageAt(now).toDataItem())
                addDataElement("personal_administrative_number", subject.documentNumber.toDataItem())
                addDataElement("issuing_authority", ISSUING_AUTHORITY.toDataItem())
                addDataElement("issuing_country", ISSUING_COUNTRY.toDataItem())
                addDataElement("date_of_issuance", now.date().toDataItemFullDate())
                addDataElement("date_of_expiry", (now + VALIDITY).date().toDataItemFullDate())
                subject.claims(ClaimScope.MDOC).forEach { addDataElement(it.name(), it.toDataItem()) }
            }
        }
        return mdoc("${subject.id}:pid-mdoc", PID_DOCTYPE, ns, now)
    }

    /** mDL ISO 18013-5 : champs de base seulement (les claims additionnels ne s'y appliquent pas). */
    private suspend fun issueMdl(subject: Subject, now: Instant): MdocCredential {
        val identity = subject.identity
        val ns = buildIssuerNamespaces {
            addNamespace(MDL_NAMESPACE) {
                addDataElement("family_name", identity.familyName().toDataItem())
                addDataElement("given_name", identity.givenName().toDataItem())
                addDataElement("birth_date", subject.birthDate.toDataItemFullDate())
                addDataElement("issue_date", now.date().toDataItemFullDate())
                addDataElement("expiry_date", (now + VALIDITY).date().toDataItemFullDate())
                addDataElement("issuing_country", ISSUING_COUNTRY.toDataItem())
                addDataElement("issuing_authority", ISSUING_AUTHORITY.toDataItem())
                addDataElement("document_number", subject.documentNumber.toDataItem())
                addDataElement("portrait", Bstr(placeholderPortrait()))
                addDataElement(
                    "driving_privileges",
                    buildCborArray {
                        add(
                            buildCborMap {
                                put("vehicle_category_code", "B")
                                put("issue_date", LocalDate(2010, 7, 1).toDataItemFullDate())
                                put("expiry_date", (now + VALIDITY).date().toDataItemFullDate())
                            },
                        )
                    },
                )
                addDataElement("un_distinguishing_sign", "F".toDataItem())
                addDataElement("age_over_18", subject.birthDate.isAtLeast(18, now).toDataItem())
            }
        }
        return mdoc("${subject.id}:mdl-mdoc", MDL_DOCTYPE, ns, now)
    }

    /** Signe le MSO (empreintes des éléments + clé du porteur) et assemble le credential mdoc. */
    private suspend fun mdoc(id: String, docType: String, ns: IssuerNamespaces, now: Instant): MdocCredential {
        val mso = MobileSecurityObject(
            version = "1.0",
            docType = docType,
            signedAt = now,
            validFrom = now,
            validUntil = now + VALIDITY,
            expectedUpdate = null,
            digestAlgorithm = Algorithm.SHA256,
            valueDigests = ns.getValueDigests(Algorithm.SHA256),
            deviceKey = keys.devicePublicKey,
        )
        // IssuerAuth = COSE_Sign1 sur MobileSecurityObjectBytes = #6.24(bstr .cbor MSO)
        val taggedMso = Cbor.encode(Tagged(Tagged.ENCODED_CBOR, Bstr(Cbor.encode(mso.toDataItem()))))
        val ds = keys.documentSigner
        // ISO 18013-5 attend l'algorithme non « fully-specified » (-7 plutôt que ESP256).
        val alg = ds.algorithm.curve?.defaultSigningAlgorithm ?: ds.algorithm
        val issuerAuth = Cose.coseSign1Sign(
            signingKey = ds,
            message = taggedMso,
            includeMessageInPayload = true,
            protectedHeaders = mapOf<CoseLabel, DataItem>(
                CoseNumberLabel(Cose.COSE_LABEL_ALG) to alg.coseAlgorithmIdentifier!!.toDataItem(),
            ),
            unprotectedHeaders = mapOf<CoseLabel, DataItem>(
                Cose.COSE_LABEL_X5CHAIN.toCoseLabel to ds.certChain.toCoseX5Chain(),
            ),
        )
        val claims = ns.data.mapValues { (_, items) ->
            items.mapValues { (_, item) -> Cbor.toDiagnostics(item.dataElementValue) }
        }
        return MdocCredential(id, docType, issuerAuth, ns, claims)
    }


    /** Valeur du claim en JSON, selon son type. */
    private fun IdentityClaimDTO.toJson(): JsonElement = when (type()) {
        ClaimType.STRING, ClaimType.DATE -> JsonPrimitive(value())
        ClaimType.NUMBER -> JsonPrimitive(value().toBigDecimal())
        ClaimType.BOOLEAN -> JsonPrimitive(value().toBoolean())
    }

    /** Valeur du claim en CBOR ; un nombre entier reste entier, sinon double. */
    private fun IdentityClaimDTO.toDataItem(): DataItem = when (type()) {
        ClaimType.STRING -> value().toDataItem()
        ClaimType.DATE -> LocalDate.parse(value()).toDataItemFullDate()
        ClaimType.NUMBER -> value().toBigDecimal().let { n ->
            if (n.scale() <= 0 || n.stripTrailingZeros().scale() <= 0) n.toLong().toDataItem() else n.toDouble().toDataItem()
        }
        ClaimType.BOOLEAN -> value().toBoolean().toDataItem()
    }

    private fun Instant.date(): LocalDate = toLocalDateTime(TimeZone.UTC).date

    /** Âge révolu à la date [now] (UTC). */
    private fun LocalDate.ageAt(now: Instant): Int {
        val today = now.date()
        val hadBirthday = today.month > month || (today.month == month && today.day >= day)
        return today.year - year - if (hadBirthday) 0 else 1
    }

    private fun LocalDate.isAtLeast(years: Int, now: Instant) = ageAt(now) >= years

    /** JPEG gris 64x80 : l'élément `portrait` du mDL est obligatoire. */
    private fun placeholderPortrait(): ByteArray {
        val img = BufferedImage(64, 80, BufferedImage.TYPE_INT_RGB)
        val g = img.createGraphics()
        g.color = java.awt.Color.LIGHT_GRAY
        g.fillRect(0, 0, 64, 80)
        g.dispose()
        return ByteArrayOutputStream().use { ImageIO.write(img, "jpg", it); it.toByteArray() }
    }

    /** JSON → valeurs Java simples (Map, List, String, Boolean, Long), pour l'affichage et le matching DCQL. */
    private fun JsonObject.toPlainMap(): Map<String, Any?> = mapValues { (_, v) -> v.toPlain() }

    private fun JsonElement.toPlain(): Any? = when (this) {
        JsonNull -> null
        is JsonObject -> toPlainMap()
        is JsonArray -> map { it.toPlain() }
        is JsonPrimitive -> if (isString) content else booleanOrNull ?: longOrNull ?: content
    }

    companion object {
        private val log = LogManager.getLogger(TestCredentialIssuer::class.java)

        const val ISSUER_URL = "https://issuer.virtual-wallet.test"
        const val PID_VCT = "urn:eudi:pid:1"
        const val PID_DOCTYPE = "eu.europa.ec.eudi.pid.1"
        const val MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
        const val MDL_NAMESPACE = "org.iso.18013.5.1"
        const val ISSUING_AUTHORITY = "Virtual Wallet Test Authority"
        const val ISSUING_COUNTRY = "FR"
        private val VALIDITY = 365.days
    }
}
