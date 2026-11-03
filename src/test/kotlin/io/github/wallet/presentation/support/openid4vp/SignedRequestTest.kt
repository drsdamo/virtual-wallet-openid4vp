package io.github.wallet.presentation.support.openid4vp

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.net.URLEncoder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Verifier qui utilise une requête signée (JAR) récupérée par référence, avec un client_id x509_san_dns. */
class SignedRequestTest {

    private val host = "verifier.example"
    private val clientId = "x509_san_dns:$host"
    private val requestUri = "https://$host/request.jwt"
    private val keyPair: KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val cert: X509Certificate = selfSigned(keyPair, host)

    private fun selfSigned(kp: KeyPair, dns: String): X509Certificate {
        val name = X500Name("CN=Test Verifier")
        val now = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(name, BigInteger.ONE, Date(now - 60_000), Date(now + 86_400_000), name, kp.public)
            .addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, dns)))
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(kp.private))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    private fun requestObject(): String {
        val dcql = """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}"""
        val claims = JWTClaimsSet.Builder()
            .claim("client_id", clientId)
            .claim("response_type", "vp_token")
            .claim("response_mode", "direct_post")
            .claim("response_uri", "https://$host/response")
            .claim("nonce", "nonce-jar")
            .claim("state", "state-jar")
            .claim("dcql_query", Json.parseToJsonElement(dcql).jsonObject.toPlain())
            .audience("https://self-issued.me/v2")
            .issueTime(Date())
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("oauth-authz-req+jwt"))
            .x509CertChain(listOf(Base64.encode(cert.encoded)))
            .build()
        return SignedJWT(header, claims).apply { sign(ECDSASigner(keyPair.private as ECPrivateKey)) }.serialize()
    }

    private fun client(trust: VerifierTrust) = OpenId4VpWalletClient(
        WalletConfigFactory().create(trust),
        MockEngine { req ->
            assertEquals(requestUri, req.url.toString())
            respond(requestObject(), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/oauth-authz-req+jwt"))
        },
    )

    private val authorizationRequest =
        "openid4vp://?client_id=${URLEncoder.encode(clientId, Charsets.UTF_8)}&request_uri=${URLEncoder.encode(requestUri, Charsets.UTF_8)}"

    @Test
    fun `trusts a verifier whose certificate is a configured anchor, and logs the exchange`() {
        client(VerifierTrust(listOf(cert), trustAll = false)).use { client ->
            val valid = assertIs<WalletResolution.Valid>(client.resolve(authorizationRequest, "trace-jar"))
            assertEquals(clientId, valid.request.client.id.clientId)
            assertEquals("nonce-jar", valid.request.nonce)

            val exchange = client.exchangeLog.forTrace("trace-jar").single()
            assertEquals("GET", exchange.method)
            assertEquals(200, exchange.status)
            assertTrue(exchange.responseBody!!.count { it == '.' } == 2, "the JAR is logged")
        }
    }

    @Test
    fun `rejects a verifier that is not in the trust store`() {
        val other = selfSigned(KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair(), host)
        client(VerifierTrust(listOf(other), trustAll = false)).use { client ->
            assertIs<WalletResolution.Invalid>(client.resolve(authorizationRequest))
        }
    }

    @Test
    fun `trust-all accepts any verifier`() {
        client(VerifierTrust(emptyList(), trustAll = true)).use { client ->
            assertIs<WalletResolution.Valid>(client.resolve(authorizationRequest))
        }
    }

    private fun kotlinx.serialization.json.JsonElement.toPlain(): Any? = when (this) {
        is kotlinx.serialization.json.JsonObject -> mapValues { it.value.toPlain() }
        is kotlinx.serialization.json.JsonArray -> map { it.toPlain() }
        is kotlinx.serialization.json.JsonNull -> null
        is kotlinx.serialization.json.JsonPrimitive -> if (isString) content else content.toBooleanStrictOrNull() ?: content.toLongOrNull() ?: content
    }
}
