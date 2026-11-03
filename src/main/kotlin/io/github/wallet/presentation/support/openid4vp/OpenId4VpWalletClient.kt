package io.github.wallet.presentation.support.openid4vp

import eu.europa.ec.eudi.openid4vp.Client
import eu.europa.ec.eudi.openid4vp.Consensus
import eu.europa.ec.eudi.openid4vp.ResponseMode
import eu.europa.ec.eudi.openid4vp.legalName
import io.github.wallet.presentation.dto.VerifierInfoDTO
import eu.europa.ec.eudi.openid4vp.DispatchOutcome
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.OpenId4Vp
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.Resolution
import eu.europa.ec.eudi.openid4vp.VerifiablePresentation
import eu.europa.ec.eudi.openid4vp.VerifiablePresentations
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import java.security.SecureRandom
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.openid4vp.EncryptionParameters
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionSpecification
import kotlin.coroutines.EmptyCoroutineContext

/**
 * Façade utilisable depuis Java de la lib wallet OpenID4VP de l'EUDI.
 *
 * La lib expose des fonctions `suspend` et des value classes Kotlin, inutilisables en Java.
 * Cette classe fait le pont avec [runBlocking] : acceptable ici car l'application tourne sur des threads virtuels.
 *
 * @param config configuration EUDI (préfixes de client_id, formats, chiffrement), voir [WalletConfigFactory]
 * @param engine moteur HTTP Ktor ; le client HTTP du JDK par défaut, un `MockEngine` en test
 */
class OpenId4VpWalletClient @JvmOverloads constructor(
    config: OpenId4VPConfig,
    engine: HttpClientEngine = Java.create(),
) : AutoCloseable {

    private val httpClient = HttpClient(engine) {
        install(ContentNegotiation) { json() }
        expectSuccess = true
    }

    /** Tous les appels HTTP faits aux verifiers, marqués du `traceId` passé à chaque méthode. */
    val exchangeLog: ExchangeLog = ExchangeLog().also { it.install(httpClient) }

    private val openId4Vp: OpenId4Vp.OverRedirects = OpenId4Vp.overRedirects(config, httpClient)

    /** Source de l'`apu` aléatoire des réponses chiffrées. */
    private val random = SecureRandom()

    /** Résout et valide une requête d'autorisation `openid4vp://` (ou `haip-vp://`, `https://`). */
    @JvmOverloads
    fun resolve(authorizationRequestUri: String, traceId: String? = null): WalletResolution =
        when (val resolution = traced(traceId) { openId4Vp.resolveRequestUri(authorizationRequestUri) }) {
            is Resolution.Success -> WalletResolution.Valid(resolution.requestObject)
            is Resolution.Invalid -> WalletResolution.Invalid(resolution)
        }

    /**
     * Envoie une réponse positive.
     *
     * @param presentations id de requête de credential DCQL → présentations sérialisées
     *                      (SD-JWT VC avec KB-JWT, ou DeviceResponse mdoc en base64url)
     */
    @JvmOverloads
    fun submit(request: ResolvedRequestObject, presentations: Map<String, List<String>>, traceId: String? = null): DispatchResult {
        val vps = VerifiablePresentations(
            presentations.entries.associate { (id, values) ->
                QueryId(id) to values.map { VerifiablePresentation.Generic(it) }
            },
        )
        return dispatch(request, Consensus.PositiveConsensus(vps), traceId)
    }

    /**
     * Résume le verifier d'une requête résolue : client_id, mode de réponse, CN du certificat.
     * Fait ici, en Kotlin, car `ResponseMode` et `Client` sont des hiérarchies scellées et `legalName()` une
     * fonction d'extension de la lib.
     */
    fun describe(request: ResolvedRequestObject): VerifierInfoDTO {
        val (mode, uri) = when (val m = request.responseMode) {
            is ResponseMode.DirectPost -> "direct_post" to m.responseURI.toString()
            is ResponseMode.DirectPostJwt -> "direct_post.jwt" to m.responseURI.toString()
            is ResponseMode.Query -> "query" to m.redirectUri.toString()
            is ResponseMode.QueryJwt -> "query.jwt" to m.redirectUri.toString()
            is ResponseMode.Fragment -> "fragment" to m.redirectUri.toString()
            is ResponseMode.FragmentJwt -> "fragment.jwt" to m.redirectUri.toString()
            else -> m.toString() to null
        }
        val cert = when (val c = request.client) {
            is Client.X509SanDns -> c.cert
            is Client.X509Hash -> c.cert
            else -> null
        }
        return VerifierInfoDTO(
            request.client.id.clientId,
            request.client.id.prefix.name,
            cert?.legalName() ?: (request.client as? Client.Preregistered)?.legalName,
            mode,
            uri,
            request.responseEncryptionSpecification != null,
        )
    }

    /** Envoie une réponse `access_denied` (le porteur a refusé). */
    @JvmOverloads
    fun decline(request: ResolvedRequestObject, traceId: String? = null): DispatchResult =
        dispatch(request, Consensus.NegativeConsensus, traceId)

    /**
     * Renvoie une erreur de résolution au verifier, quand la lib le permet
     * (assez d'informations ont été résolues pour savoir où l'envoyer).
     *
     * @return l'issue, ou `null` si l'erreur ne peut pas être envoyée
     */
    @JvmOverloads
    fun reportError(invalid: WalletResolution.Invalid, traceId: String? = null): DispatchResult? {
        val details = invalid.resolution.dispatchDetails ?: return null
        return traced(traceId) {
            openId4Vp.dispatchError(invalid.resolution.error, details, encryptionParameters(details.responseEncryptionSpecification))
        }.toResult()
    }

    /** Envoie la réponse (positive ou négative) selon le mode de réponse de la requête. */
    private fun dispatch(request: ResolvedRequestObject, consensus: Consensus, traceId: String?): DispatchResult =
        traced(traceId) { openId4Vp.dispatch(request, consensus, encryptionParameters(request.responseEncryptionSpecification)) }.toResult()

    /** Exécute [block] en bloquant, avec le [TraceId] dans le contexte pour l'ExchangeLog. */
    private fun <T> traced(traceId: String?, block: suspend () -> T): T =
        runBlocking(traceId?.let(::TraceId) ?: EmptyCoroutineContext) { block() }

    override fun close() = httpClient.close()

    /** Issue EUDI → résultat utilisable depuis Java. */
    private fun DispatchOutcome.toResult(): DispatchResult = when (this) {
        is DispatchOutcome.VerifierResponse.Accepted -> DispatchResult(true, redirectURI)
        is DispatchOutcome.VerifierResponse.Rejected -> DispatchResult(false, redirectURI)
        is DispatchOutcome.RedirectURI -> DispatchResult(true, value)
    }

    /**
     * La lib EUDI exige un Agreement PartyUInfo (`apu`) pour les réponses chiffrées ECDH-ES (direct_post.jwt) :
     * une valeur aléatoire neuve par réponse. Sans lui, l'envoi échoue avant tout appel HTTP.
     */
    internal fun encryptionParameters(spec: ResponseEncryptionSpecification?): EncryptionParameters? {
        val alg = spec?.encryptionAlgorithm ?: return null
        if (alg !in JWEAlgorithm.Family.ECDH_ES) return null
        return EncryptionParameters.DiffieHellman(Base64URL.encode(ByteArray(16).also(random::nextBytes)))
    }
}
