package io.github.wallet.credentials.service

import io.github.wallet.credentials.support.WalletKeyMaterialLoader
import io.github.wallet.credentials.support.MdocCredential
import io.github.wallet.credentials.support.SdJwtVcCredential
import io.github.wallet.credentials.support.TestPersona
import io.github.wallet.credentials.support.WalletKeyMaterial

import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.io.TempDir
import org.multipaz.cbor.Cbor
import org.multipaz.cose.Cose
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.javaPublicKey
import org.multipaz.mdoc.mso.MobileSecurityObject
import java.nio.file.Path
import java.security.interfaces.ECPublicKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Clés persistées, chaînes de certificats et contenu des credentials émis. */
class TestCredentialIssuerTest {

    @TempDir
    lateinit var dir: Path

    private val keys by lazy { WalletKeyMaterialLoader().loadOrCreate(dir) }
    private val credentials by lazy { TestCredentialIssuer(keys).issueFor(TestPersona().identity()) }

    @Test
    fun `keys are persisted and reused`() {
        val first = keys.iacaCertificatePem()
        assertEquals(first, WalletKeyMaterialLoader().loadOrCreate(dir).iacaCertificatePem())
    }

    @Test
    fun `issuer certificate chains validate up to the test IACA`() = runBlocking {
        keys.documentSigner.certChain.validate()
        keys.sdJwtIssuer.certChain.validate()
    }

    @Test
    fun `SD-JWT VC PID is signed by the issuer and bound to the device key`() = runBlocking {
        val pid = credentials.filterIsInstance<SdJwtVcCredential>().single()
        val issuerKey = keys.sdJwtIssuer.certChain.certificates.first().ecPublicKey.javaPublicKey as ECPublicKey

        val verified = with(NimbusSdJwtOps) {
            verify(ECDSAVerifier(issuerKey).asJwtVerifier(), pid.serialized).getOrThrow()
        }
        val jwt = verified.jwt
        assertEquals("dc+sd-jwt", jwt.header.type.type)
        assertEquals(1, jwt.header.x509CertChain.size)
        val cnf = ECKey.parse(jwt.jwtClaimsSet.getJSONObjectClaim("cnf")["jwk"] as Map<String, Any>)
        assertEquals(keys.devicePublicKey.javaPublicKey, cnf.toECPublicKey())

        assertEquals(TestPersona.FAMILY_NAME, pid.claims["family_name"])
        assertEquals(true, (pid.claims["age_equal_or_over"] as Map<*, *>)["18"])
        assertTrue(verified.disclosures.size > 10, "claims must be selectively disclosable")
        // Les métadonnées du type PID EUDI exigent que tout claim, hors claims JWT/VC enregistrés, soit divulgable
        val clear = jwt.jwtClaimsSet.claims.keys - setOf("iss", "vct", "iat", "exp", "cnf", "_sd", "_sd_alg", "status")
        assertTrue(clear.isEmpty(), "claims in clear: $clear")
        assertTrue(with(NimbusSdJwtOps) { verified.recreateClaimsAndDisclosuresPerClaim().first }.containsKey("address"))
    }

    @Test
    fun `mdoc credentials have a valid issuerAuth and matching digests`() = runBlocking {
        val mdocs = credentials.filterIsInstance<MdocCredential>()
        assertEquals(setOf(TestCredentialIssuer.PID_DOCTYPE, TestCredentialIssuer.MDL_DOCTYPE), mdocs.map { it.type }.toSet())
        val dsKey = keys.documentSigner.certChain.certificates.first().ecPublicKey

        for (mdoc in mdocs) {
            Cose.coseSign1Check(dsKey, null, mdoc.issuerAuth, Algorithm.ES256)
            val mso = MobileSecurityObject.fromDataItem(Cbor.decode(mdoc.issuerAuth.payload!!).asTaggedEncodedCbor)
            assertEquals(mdoc.type, mso.docType)
            assertEquals(keys.devicePublicKey, mso.deviceKey)
            val result = mdoc.issuerNamespaces.validateAgainstMso(mso)
            assertTrue(!result.hasErrors, "digests of ${mdoc.id}: ${result.errors}")
        }
        val mdl = mdocs.single { it.type == TestCredentialIssuer.MDL_DOCTYPE }
        assertTrue((mdl.claims[TestCredentialIssuer.MDL_NAMESPACE] as Map<*, *>).containsKey("portrait"))
    }
}
