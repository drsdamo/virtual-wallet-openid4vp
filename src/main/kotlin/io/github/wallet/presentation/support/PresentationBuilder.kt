package io.github.wallet.presentation.support

import io.github.wallet.credentials.support.MdocCredential
import io.github.wallet.credentials.support.SdJwtVcCredential
import io.github.wallet.credentials.support.WalletCredential

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.ResponseMode
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.vc.ClaimPath as SdClaimPath
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.cbor.buildCborArray
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.cbor.Tstr
import org.multipaz.mdoc.issuersigned.IssuerSignedItem
import org.multipaz.crypto.javaPrivateKey
import org.multipaz.crypto.javaPublicKey
import org.multipaz.mdoc.devicesigned.DeviceNamespaces
import org.multipaz.mdoc.issuersigned.IssuerNamespaces
import org.multipaz.mdoc.response.DeviceResponse
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.response.buildDeviceResponse
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.Base64
import java.util.Date
import kotlinx.coroutines.runBlocking

/**
 * Construit les entrées du `vp_token` : SD-JWT VC + KB-JWT, ou DeviceResponse mdoc en base64url.
 * Chaque présentation est signée par la clé du porteur liée au credential ([WalletCredential.getHolderKey]).
 */
class PresentationBuilder {

    /** Présentation du credential retenu pour [match], avec les [faults] demandés. */
    @JvmOverloads
    fun build(request: ResolvedRequestObject, match: QueryMatch, faults: Set<Fault> = emptySet()): String = runBlocking {
        val credential = requireNotNull(match.credential) { "query ${match.queryId} is not satisfiable" }
        val paths = if (Fault.OVER_DISCLOSURE in faults) null else match.disclosedPaths
        when (credential) {
            is SdJwtVcCredential -> sdJwt(request, credential, paths, faults)
            is MdocCredential -> mdoc(request, credential, paths, faults)
        }
    }

    // ---------------------------------------------------------------- SD-JWT VC

    /** Présentation SD-JWT : disclosures demandées puis KB-JWT lié au nonce et au client_id de la requête. */
    private suspend fun sdJwt(
        request: ResolvedRequestObject,
        credential: SdJwtVcCredential,
        paths: List<List<Any?>>?,
        faults: Set<Fault>,
    ): String {
        val serialized = with(NimbusSdJwtOps) {
            val presented = if (paths == null) {
                credential.sdJwt
            } else {
                requireNotNull(credential.sdJwt.present(paths.map(::toSdJwtPath).toSet())) { "cannot disclose $paths" }
            }
            if (Fault.SD_JWT_NO_KB in faults) {
                presented.serialize()
            } else {
                val signingKey = if (Fault.SD_JWT_KB_WRONG_KEY in faults) {
                    Crypto.createEcPrivateKey(EcCurve.P256)
                } else {
                    credential.holderKey
                }
                val holderJwk = ECKey.Builder(Curve.P_256, signingKey.publicKey.javaPublicKey as ECPublicKey).build()
                val kbJwt = kbJwtIssuer(
                    signer = ECDSASigner(signingKey.javaPrivateKey as ECPrivateKey),
                    signAlgorithm = JWSAlgorithm.ES256,
                    publicKey = holderJwk,
                ) {
                    audience(if (Fault.SD_JWT_WRONG_AUDIENCE in faults) "https://not-the-verifier.example" else request.client.id.clientId)
                    claim("nonce", if (Fault.SD_JWT_WRONG_NONCE in faults) request.nonce + "-tampered" else request.nonce)
                    issueTime(if (Fault.SD_JWT_STALE_KB in faults) Date(System.currentTimeMillis() - 86_400_000) else Date())
                }
                presented.serializeWithKeyBinding(kbJwt).getOrThrow()
            }
        }
        return tamperSdJwt(serialized, faults)
    }

    /** Altère la sérialisation `<jwt-émetteur>~<disclosure>~...~<kb-jwt?>` selon les défauts demandés. */
    private fun tamperSdJwt(serialized: String, faults: Set<Fault>): String {
        val parts = serialized.split("~").toMutableList()
        if (Fault.SD_JWT_BAD_ISSUER_SIGNATURE in faults) {
            val jws = parts[0].split(".")
            parts[0] = listOf(jws[0], jws[1], flip(jws[2])).joinToString(".")
        }
        if (Fault.SD_JWT_FORGED_DISCLOSURE in faults && parts.size > 2) {
            parts[1] = flip(parts[1])
        }
        if (Fault.SD_JWT_BAD_KB_SIGNATURE in faults && parts.last().isNotEmpty()) {
            val jws = parts.last().split(".")
            parts[parts.lastIndex] = listOf(jws[0], jws[1], flip(jws[2])).joinToString(".")
        }
        return parts.joinToString("~")
    }

    /** Chemin DCQL → chemin de claim de la lib SD-JWT. */
    private fun toSdJwtPath(path: List<Any?>): SdClaimPath {
        var result: SdClaimPath? = null
        for (element in path) {
            result = when (element) {
                is String -> result?.claim(element) ?: SdClaimPath.claim(element)
                is Int -> requireNotNull(result).arrayElement(element)
                null -> requireNotNull(result).allArrayElements()
                else -> error("unexpected path element $element")
            }
        }
        return requireNotNull(result) { "empty claim path" }
    }

    // ---------------------------------------------------------------- mdoc

    /** DeviceResponse mdoc : éléments demandés, signée par la clé du porteur sur le SessionTranscript OpenID4VP. */
    private suspend fun mdoc(
        request: ResolvedRequestObject,
        credential: MdocCredential,
        paths: List<List<Any?>>?,
        faults: Set<Fault>,
    ): String {
        val sessionTranscript = sessionTranscript(
            request,
            nonce = if (Fault.MDOC_WRONG_NONCE in faults) request.nonce + "-tampered" else request.nonce,
            clientId = if (Fault.MDOC_WRONG_CLIENT_ID in faults) "x509_san_dns:not-the-verifier.example" else request.client.id.clientId,
        )
        val disclosed = if (paths == null) {
            credential.issuerNamespaces
        } else {
            val wanted = paths.groupBy({ it[0] as String }, { it[1] as String })
            IssuerNamespaces(
                credential.issuerNamespaces.data
                    .filterKeys { it in wanted }
                    .mapValues { (ns, items) -> items.filterKeys { it in wanted.getValue(ns) } },
            )
        }
        val issuerNamespaces = if (Fault.MDOC_TAMPERED_ELEMENT in faults) tamperFirstElement(disclosed) else disclosed
        val issuerAuth = if (Fault.MDOC_BAD_ISSUER_SIGNATURE in faults) {
            credential.issuerAuth.copy(signature = credential.issuerAuth.signature.copyOf().also { it[it.size / 2] = (it[it.size / 2] + 1).toByte() })
        } else {
            credential.issuerAuth
        }
        val deviceKey = if (Fault.MDOC_DEVICE_KEY_MISMATCH in faults) {
            AsymmetricKey.anonymous(Crypto.createEcPrivateKey(EcCurve.P256))
        } else {
            AsymmetricKey.anonymous(credential.holderKey)
        }
        val document = MdocDocument.fromNamespaces(
            sessionTranscript = sessionTranscript,
            docType = credential.type,
            issuerAuth = issuerAuth,
            issuerNamespaces = issuerNamespaces,
            deviceNamespaces = DeviceNamespaces(emptyMap()),
            deviceKey = deviceKey,
        )
        val response = buildDeviceResponse(sessionTranscript, DeviceResponse.STATUS_OK) { addDocument(document) }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Cbor.encode(response.toDataItem()))
    }

    /** Remplace la valeur du premier élément divulgué en gardant digestID et random : l'empreinte du MSO ne correspond plus. */
    private fun tamperFirstElement(ns: IssuerNamespaces): IssuerNamespaces {
        val (nsName, items) = ns.data.entries.first { it.value.isNotEmpty() }
        val (name, item) = items.entries.first()
        val forged = IssuerSignedItem.fromValues(
            digestId = item.digestId,
            random = item.random,
            dataElementIdentifier = name,
            dataElementValue = Tstr("TAMPERED"),
        )
        return IssuerNamespaces(ns.data + (nsName to (items + (name to forged))))
    }

    /**
     * SessionTranscript d'une présentation mdoc, OpenID4VP 1.0 annexe B.2.6.1 :
     * `SessionTranscript = [null, null, ["OpenID4VPHandover", sha256(cbor([client_id, nonce, jwk_thumbprint, response_uri]))]]`
     */
    suspend fun sessionTranscript(
        request: ResolvedRequestObject,
        nonce: String = request.nonce,
        clientId: String = request.client.id.clientId,
    ): DataItem {
        val responseUri = when (val mode = request.responseMode) {
            is ResponseMode.DirectPost -> mode.responseURI.toString()
            is ResponseMode.DirectPostJwt -> mode.responseURI.toString()
            else -> error("mdoc presentation requires direct_post or direct_post.jwt, got $mode")
        }
        val thumbprint: DataItem = request.responseEncryptionSpecification
            ?.recipientKey?.computeThumbprint("SHA-256")?.decode()
            ?.let { Bstr(it) } ?: Simple.NULL
        val handoverInfo = Cbor.encode(
            buildCborArray {
                add(clientId)
                add(nonce)
                add(thumbprint)
                add(responseUri)
            },
        )
        return buildCborArray {
            add(Simple.NULL)
            add(Simple.NULL)
            add(
                buildCborArray {
                    add("OpenID4VPHandover")
                    add(Crypto.digest(Algorithm.SHA256, handoverInfo))
                },
            )
        }
    }

    /** Change un caractère au milieu d'un segment base64url, qui reste décodable. */
    private fun flip(segment: String): String {
        val i = segment.length / 2
        val c = if (segment[i] == 'A') 'B' else 'A'
        return segment.substring(0, i) + c + segment.substring(i + 1)
    }
}
