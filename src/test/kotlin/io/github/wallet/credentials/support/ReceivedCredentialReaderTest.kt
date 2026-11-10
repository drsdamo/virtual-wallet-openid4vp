package io.github.wallet.credentials.support

import io.github.wallet.credentials.service.TestCredentialIssuer

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.io.TempDir
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.buildCborMap
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import java.nio.file.Path
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Relecture des credentials tels qu'un émetteur les envoie, à partir de ceux de l'autorité de test (x5c, x5chain). */
class ReceivedCredentialReaderTest {

    @TempDir
    lateinit var dir: Path

    private val keys by lazy { WalletKeyMaterialLoader().loadOrCreate(dir) }
    private val issued by lazy { TestCredentialIssuer(keys).issueFor(TestPersona().identity()) }
    private val reader = ReceivedCredentialReader()

    /** IssuerSigned en base64url, forme d'un credential mdoc dans la réponse credential. */
    private fun issuerSigned(mdoc: MdocCredential): String = runBlocking {
        val item = buildCborMap {
            put("nameSpaces", mdoc.issuerNamespaces.toDataItem())
            put("issuerAuth", mdoc.issuerAuth.toDataItem())
        }
        Base64.getUrlEncoder().withoutPadding().encodeToString(Cbor.encode(item))
    }

    @Test
    fun `a well-formed SD-JWT VC bound to the proof key reads without warnings`() {
        val pid = issued.filterIsInstance<SdJwtVcCredential>().single()

        val read = reader.read("i:vci-1", "dc+sd-jwt", pid.serialized, TestCredentialIssuer.ISSUER_URL, keys.devicePrivateKey)

        assertEquals(emptyList(), read.warnings)
        assertEquals(TestCredentialIssuer.PID_VCT, read.credential.type)
        assertEquals(pid.claims["family_name"], read.credential.claims["family_name"])
    }

    @Test
    fun `an SD-JWT VC bound to another key is flagged`() = runBlocking {
        val pid = issued.filterIsInstance<SdJwtVcCredential>().single()

        val read = reader.read("i:vci-1", "dc+sd-jwt", pid.serialized, "https://other.example", Crypto.createEcPrivateKey(EcCurve.P256))

        assertTrue(read.warnings.any { "cnf.jwk" in it }, read.warnings.toString())
        assertTrue(read.warnings.any { "iss" in it }, read.warnings.toString())
    }

    @Test
    fun `an mdoc IssuerSigned reads with verified signature and digests`() {
        val mdl = issued.filterIsInstance<MdocCredential>().single { it.type == TestCredentialIssuer.MDL_DOCTYPE }

        val read = reader.read("i:vci-2", "mso_mdoc", issuerSigned(mdl), TestCredentialIssuer.ISSUER_URL, keys.devicePrivateKey)

        assertEquals(emptyList(), read.warnings)
        val mdoc = assertIs<MdocCredential>(read.credential)
        assertEquals(TestCredentialIssuer.MDL_DOCTYPE, mdoc.type)
        assertEquals(mdl.claims.keys, mdoc.claims.keys)
    }

    @Test
    fun `an mdoc bound to another device key is flagged`() = runBlocking {
        val mdl = issued.filterIsInstance<MdocCredential>().single { it.type == TestCredentialIssuer.MDL_DOCTYPE }

        val read = reader.read("i:vci-2", "mso_mdoc", issuerSigned(mdl), TestCredentialIssuer.ISSUER_URL, Crypto.createEcPrivateKey(EcCurve.P256))

        assertTrue(read.warnings.any { "deviceKey" in it }, read.warnings.toString())
    }

    @Test
    fun `unreadable credentials and unknown formats are rejected`() {
        assertFailsWith<IllegalArgumentException> { reader.read("x", "dc+sd-jwt", "not-a-jwt", "i", keys.devicePrivateKey) }
        assertFailsWith<IllegalArgumentException> { reader.read("x", "mso_mdoc", "AAAA", "i", keys.devicePrivateKey) }
        assertFailsWith<IllegalArgumentException> { reader.read("x", "jwt_vc_json", "{}", "i", keys.devicePrivateKey) }
    }
}
