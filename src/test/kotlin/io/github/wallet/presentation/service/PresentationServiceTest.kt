package io.github.wallet.presentation.service

import io.github.wallet.credentials.support.WalletKeyMaterialLoader
import io.github.wallet.credentials.service.CredentialStore
import io.github.wallet.credentials.service.TestCredentialIssuer
import io.github.wallet.credentials.support.TestPersona
import io.github.wallet.credentials.support.WalletKeyMaterial
import io.github.wallet.presentation.support.PresentationBuilder
import io.github.wallet.presentation.support.openid4vp.OpenId4VpWalletClient
import io.github.wallet.presentation.support.openid4vp.WalletConfigFactory

import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jwt.SignedJWT
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
import org.multipaz.cbor.Cbor
import org.multipaz.crypto.javaPublicKey
import org.multipaz.mdoc.response.DeviceResponse
import java.net.URLEncoder
import java.nio.file.Path
import java.security.interfaces.ECPublicKey
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Flux complet contre un verifier simulé : résolution, matching DCQL, présentations SD-JWT VC et mdoc. */
class PresentationServiceTest {

    @TempDir
    lateinit var dir: Path

    private val responseUri = "https://verifier.example/response"
    private val clientId = "redirect_uri:$responseUri"
    private val nonce = "n-0S6_WzA2Mj"

    private val dcql = """
        {"credentials":[
          {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
           "claims":[{"path":["family_name"]},{"path":["address","locality"]}]},
          {"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
           "claims":[{"path":["org.iso.18013.5.1","given_name"]},{"path":["org.iso.18013.5.1","age_over_18"],"values":[true]}]},
          {"id":"unknown","format":"dc+sd-jwt","meta":{"vct_values":["urn:example:diploma"]}}
        ]}
    """.trimIndent()

    private fun requestUri(): String {
        fun enc(s: String) = URLEncoder.encode(s, Charsets.UTF_8)
        return "openid4vp://?client_id=${enc(clientId)}&response_type=vp_token&response_mode=direct_post" +
            "&response_uri=${enc(responseUri)}&nonce=$nonce&state=st-1&dcql_query=${enc(dcql)}"
    }

    @Test
    fun `answers a DCQL request with SD-JWT VC and mdoc presentations`() = runBlocking {
        val keys = WalletKeyMaterialLoader().loadOrCreate(dir)
        val store = CredentialStore(TestCredentialIssuer(keys)).apply { issue(TestPersona().identity()) }
        var posted: Map<String, String> = emptyMap()
        val engine = MockEngine { req ->
            val form = parseQueryString(req.body.toByteArray().decodeToString())
            posted = form.names().associateWith { form[it]!! }
            respond("{}", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
        }
        val client = OpenId4VpWalletClient(WalletConfigFactory().create(false), engine)
        val service = PresentationService(client, store)

        val pending = assertIs<PendingPresentation.Valid>(service.resolve(requestUri(), "trace-1"))
        assertEquals(clientId, pending.verifier.clientId)
        assertTrue(pending.matches.single { it.queryId == "pid" }.credential!!.id.endsWith(":pid-sd-jwt"))
        assertTrue(pending.matches.single { it.queryId == "mdl" }.credential!!.id.endsWith(":mdl-mdoc"))
        assertNull(pending.matches.single { it.queryId == "unknown" }.credential)

        assertTrue(service.accept(pending).accepted)
        val vpToken = Json.parseToJsonElement(posted.getValue("vp_token")).jsonObject
        assertEquals(setOf("pid", "mdl"), vpToken.keys)

        // SD-JWT VC : seulement les disclosures demandées + un KB-JWT lié à cette requête
        val sdJwt = vpToken.getValue("pid").jsonArray.single().jsonPrimitive.content
        val parts = sdJwt.split("~")
        val disclosedNames = parts.drop(1).dropLast(1).map {
            Json.parseToJsonElement(Base64.getUrlDecoder().decode(it).decodeToString()).jsonArray
        }.filter { it.size == 3 }.map { it[1].jsonPrimitive.content }.toSet()
        assertEquals(setOf("family_name", "address", "locality"), disclosedNames)
        val kb = SignedJWT.parse(parts.last())
        assertTrue(kb.verify(ECDSAVerifier(keys.devicePublicKey.javaPublicKey as ECPublicKey)))
        assertEquals(nonce, kb.jwtClaimsSet.getStringClaim("nonce"))
        assertEquals(listOf(clientId), kb.jwtClaimsSet.audience)

        // mdoc : la DeviceResponse se vérifie sur le SessionTranscript OpenID4VP, avec seulement les éléments demandés
        val encoded = vpToken.getValue("mdl").jsonArray.single().jsonPrimitive.content
        val response = DeviceResponse.fromDataItem(Cbor.decode(Base64.getUrlDecoder().decode(encoded)))
        response.verify(PresentationBuilder().sessionTranscript(pending.request))
        val doc = response.documents.single()
        assertEquals(TestCredentialIssuer.MDL_DOCTYPE, doc.docType)
        assertEquals(setOf("given_name", "age_over_18"), doc.issuerNamespaces.data.getValue(TestCredentialIssuer.MDL_NAMESPACE).keys)
    }
}
