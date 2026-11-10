package io.github.wallet.presentation.service

import io.github.wallet.credentials.support.WalletKeyMaterialLoader
import io.github.wallet.credentials.service.TestCredentialIssuer
import io.github.wallet.credentials.support.TestPersona
import io.github.wallet.credentials.support.WalletKeyMaterial
import io.github.wallet.presentation.support.DcqlMatcher
import io.github.wallet.presentation.support.Fault
import io.github.wallet.presentation.support.PresentationBuilder
import io.github.wallet.presentation.support.openid4vp.OpenId4VpWalletClient
import io.github.wallet.presentation.support.openid4vp.WalletConfigFactory
import io.github.wallet.presentation.support.openid4vp.WalletResolution

import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import io.ktor.client.engine.mock.MockEngine
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import java.net.URLEncoder
import java.nio.file.Path
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Chaque [Fault] doit être détecté par [TestVerifier].
 * Une seule instance pour toute la classe : les clés et la requête ne sont construites qu'une fois.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FaultInjectionTest {

    @TempDir
    lateinit var dir: Path

    private val keys by lazy { WalletKeyMaterialLoader().loadOrCreate(dir) }
    private val credentials by lazy { TestCredentialIssuer(keys).issueFor(TestPersona().identity()) }
    private val builder by lazy { PresentationBuilder() }
    private val verifier by lazy { TestVerifier(keys) }

    private val request: ResolvedRequestObject by lazy {
        val responseUri = "https://verifier.example/response"
        val dcql = """{"credentials":[
            {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]},
            {"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","given_name"]}]}]}"""
        fun enc(s: String) = URLEncoder.encode(s, Charsets.UTF_8)
        val uri = "openid4vp://?client_id=${enc("redirect_uri:$responseUri")}&response_type=vp_token" +
            "&response_mode=direct_post&response_uri=${enc(responseUri)}&nonce=nonce-123&dcql_query=${enc(dcql)}"
        val client = OpenId4VpWalletClient(WalletConfigFactory().create(false), MockEngine { error("offline") })
        (client.resolve(uri) as WalletResolution.Valid).request
    }

    private fun match(queryId: String) = DcqlMatcher(credentials).match(request.query).single { it.queryId == queryId }

    @Test
    fun `correct presentations pass the test verifier`() = runBlocking {
        verifier.verifySdJwt(request, builder.build(request, match("pid")))
        verifier.verifyMdoc(request, builder.build(request, match("mdl")))
    }

    @ParameterizedTest
    @EnumSource(Fault::class, names = ["OVER_DISCLOSURE", "VP_TOKEN_WRONG_QUERY_ID"], mode = EnumSource.Mode.EXCLUDE)
    fun `each fault is detected by the test verifier`(fault: Fault) = runBlocking {
        val sdJwt = fault.format == "dc+sd-jwt"
        val presentation = builder.build(request, match(if (sdJwt) "pid" else "mdl"), setOf(fault))
        assertFailsWith<Throwable>("$fault must be rejected") {
            if (sdJwt) verifier.verifySdJwt(request, presentation) else verifier.verifyMdoc(request, presentation)
        }
        Unit
    }

    @Test
    fun `over-disclosure stays valid but reveals more claims`() = runBlocking {
        val minimal = builder.build(request, match("pid"))
        val full = builder.build(request, match("pid"), setOf(Fault.OVER_DISCLOSURE))
        verifier.verifySdJwt(request, full)
        assertTrue(full.count { it == '~' } > minimal.count { it == '~' })
    }
}
