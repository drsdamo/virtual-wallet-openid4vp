package io.github.wallet.presentation.service

import io.github.wallet.credentials.support.WalletKeyMaterial
import io.github.wallet.presentation.support.PresentationBuilder

import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.sdjwt.KeyBindingVerifier
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.multipaz.cbor.Cbor
import org.multipaz.crypto.javaPublicKey
import org.multipaz.mdoc.response.DeviceResponse
import java.security.interfaces.ECPublicKey
import java.util.Base64
import kotlin.math.abs

/** Contrôles qu'effectue un verifier correct, écrits avec le code de vérification de la lib SD-JWT EUDI et de Multipaz. */
class TestVerifier(private val keys: WalletKeyMaterial) {

    suspend fun verifySdJwt(request: ResolvedRequestObject, presentation: String) {
        val issuerKey = keys.sdJwtIssuer.certChain.certificates.first().ecPublicKey.javaPublicKey as ECPublicKey
        with(NimbusSdJwtOps) {
            val challenge = buildJsonObject {
                put("aud", JsonPrimitive(request.client.id.clientId))
                put("nonce", JsonPrimitive(request.nonce))
            }
            verify(
                ECDSAVerifier(issuerKey).asJwtVerifier(),
                KeyBindingVerifier.mustBePresentAndValid(challenge = challenge),
                null,
                presentation,
            ).getOrThrow()
        }
        val iat = SignedJWT.parse(presentation.substringAfterLast("~")).jwtClaimsSet.issueTime.time
        check(abs(System.currentTimeMillis() - iat) < 5 * 60_000) { "KB-JWT iat is not fresh" }
    }

    suspend fun verifyMdoc(request: ResolvedRequestObject, presentation: String) {
        val response = DeviceResponse.fromDataItem(Cbor.decode(Base64.getUrlDecoder().decode(presentation)))
        response.verify(PresentationBuilder().sessionTranscript(request))
        check(response.documents.isNotEmpty())
    }
}
