package io.github.wallet.presentation.support.openid4vp

import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.http.parseQueryString
import io.ktor.client.engine.mock.toByteArray
import java.net.URLEncoder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Adaptateur Kotlin autour de la lib EUDI : résolution, envoi et journal des échanges, sur un MockEngine. */
class OpenId4VpWalletClientTest {

    private val responseUri = "https://verifier.example/response"

    private val dcql = """
        {"credentials":[{"id":"pid","format":"dc+sd-jwt",
          "meta":{"vct_values":["urn:eudi:pid:1"]},
          "claims":[{"path":["family_name"]}]}]}
    """.trimIndent()

    private fun requestUri(): String {
        fun enc(s: String) = URLEncoder.encode(s, Charsets.UTF_8)
        return "openid4vp://?client_id=${enc("redirect_uri:$responseUri")}" +
            "&response_type=vp_token&response_mode=direct_post" +
            "&response_uri=${enc(responseUri)}&nonce=n-0S6_WzA2Mj&state=st-1" +
            "&dcql_query=${enc(dcql)}"
    }

    @Test
    fun `resolves an unsigned request and posts the vp_token to the verifier`() {
        val posted = mutableListOf<Map<String, String>>()
        val engine = MockEngine { req ->
            assertEquals(responseUri, req.url.toString())
            val form = parseQueryString(req.body.toByteArray().decodeToString())
            posted += form.names().associateWith { form[it]!! }
            respond(
                """{"redirect_uri":"https://verifier.example/done"}""",
                HttpStatusCode.OK,
                headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()),
            )
        }
        OpenId4VpWalletClient(WalletConfigFactory().create(false), engine).use { client ->
            val resolution = assertIs<WalletResolution.Valid>(client.resolve(requestUri()))
            assertEquals("n-0S6_WzA2Mj", resolution.request.nonce)

            val result = client.submit(resolution.request, mapOf("pid" to listOf("eyJ...~kb")))

            assertTrue(result.accepted)
            assertEquals("https://verifier.example/done", result.redirectUri.toString())
            assertEquals("st-1", posted.single()["state"])
            assertTrue(posted.single()["vp_token"]!!.contains("\"pid\""))
            // Le journal montre le formulaire réellement posté, pas le toString() de l'objet corps
            assertTrue(client.exchangeLog.all().last().requestBody!!.startsWith("vp_token="))
        }
    }

    @Test
    fun `reports an invalid request`() {
        val engine = MockEngine { error("no HTTP call expected") }
        OpenId4VpWalletClient(WalletConfigFactory().create(false), engine).use { client ->
            assertIs<WalletResolution.Invalid>(client.resolve("openid4vp://?client_id=x"))
        }
    }
}
