package io.github.wallet.presentation.service

import io.github.wallet.credentials.support.WalletKeyMaterialLoader
import io.github.wallet.credentials.service.CredentialStore
import io.github.wallet.credentials.service.TestCredentialIssuer
import io.github.wallet.credentials.support.TestPersona
import io.github.wallet.credentials.support.WalletKeyMaterial
import io.github.wallet.presentation.support.openid4vp.OpenId4VpWalletClient
import io.github.wallet.presentation.support.openid4vp.WalletConfigFactory

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.http.parseQueryString
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.io.TempDir
import java.net.URLEncoder
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** direct_post.jwt avec une clé ECDH-ES du verifier, comme le demande le verifier de référence EUDI. */
class EncryptedResponseTest {

    @TempDir
    lateinit var dir: Path

    private val responseUri = "https://verifier.example/response"
    private val verifierKey = ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).algorithm(JWEAlgorithm.ECDH_ES).keyID("enc-1").generate()

    private fun requestUri(): String {
        val dcql = """{"credentials":[
            {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]},
            {"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","family_name"]}]}]}"""
        val metadata = """{"jwks":{"keys":[${verifierKey.toPublicJWK().toJSONString()}]},
            "encrypted_response_enc_values_supported":["A128GCM","A256GCM"],
            "vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]},"mso_mdoc":{}}}"""
        fun enc(s: String) = URLEncoder.encode(s, Charsets.UTF_8)
        return "openid4vp://?client_id=${enc("redirect_uri:$responseUri")}&response_type=vp_token&response_mode=direct_post.jwt" +
            "&response_uri=${enc(responseUri)}&nonce=nonce-enc&state=st-enc&dcql_query=${enc(dcql)}&client_metadata=${enc(metadata)}"
    }

    @Test
    fun `encrypts the response with ECDH-ES and the mdoc transcript includes the key thumbprint`() = runBlocking {
        val keys = WalletKeyMaterialLoader().loadOrCreate(dir)
        val store = CredentialStore(TestCredentialIssuer(keys)).apply { issue(TestPersona().identity()) }
        var jwe: String? = null
        val engine = MockEngine { req ->
            jwe = parseQueryString(req.body.toByteArray().decodeToString())["response"]
            respond("{}", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
        }
        val service = PresentationService(OpenId4VpWalletClient(WalletConfigFactory().create(false), engine), store)

        val pending = assertIs<PendingPresentation.Valid>(service.resolve(requestUri(), "trace-enc"))
        assertTrue(pending.verifier.encryptedResponse)
        assertTrue(service.accept(pending).accepted)

        val decrypted = JWEObject.parse(requireNotNull(jwe) { "no encrypted response posted" }).apply { decrypt(ECDHDecrypter(verifierKey)) }
        assertEquals("enc-1", decrypted.header.keyID)
        val payload = Json.parseToJsonElement(decrypted.payload.toString()).jsonObject
        val vpToken = payload.getValue("vp_token").jsonObject

        val verifier = TestVerifier(keys)
        verifier.verifySdJwt(pending.request, vpToken.getValue("pid").jsonArray.single().jsonPrimitive.content)
        verifier.verifyMdoc(pending.request, vpToken.getValue("mdl").jsonArray.single().jsonPrimitive.content)
    }
}
