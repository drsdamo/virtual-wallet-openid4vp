package io.github.wallet.presentation.support.openid4vp

import io.github.wallet.presentation.dto.HttpExchangeDTO

import io.ktor.client.HttpClient
import io.ktor.client.call.save
import io.ktor.client.plugins.HttpSend
import io.ktor.client.plugins.plugin
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.statement.bodyAsText
import io.ktor.http.Headers
import io.ktor.http.content.OutgoingContent
import io.ktor.http.content.TextContent
import io.ktor.client.request.forms.FormDataContent
import io.ktor.http.formUrlEncode
import kotlinx.coroutines.currentCoroutineContext
import org.apache.logging.log4j.LogManager
import java.time.Instant
import java.util.concurrent.ConcurrentLinkedDeque
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext

/** Élément de contexte de coroutine : rattache les appels HTTP à leur présentation. */
class TraceId(val value: String) : AbstractCoroutineContextElement(Key) {
    companion object Key : CoroutineContext.Key<TraceId>
}

/** Tampon circulaire en mémoire des [capacity] derniers échanges HTTP avec des verifiers (ou des émetteurs OpenID4VCI). */
class ExchangeLog(private val capacity: Int = 500) {

    private companion object {
        /** Catégorie dédiée, pour activer ou couper les traces sortantes indépendamment. */
        val log = LogManager.getLogger("io.github.wallet.http.out")
    }

    private val entries = ConcurrentLinkedDeque<HttpExchangeDTO>()

    /** Tous les échanges, du plus ancien au plus récent. */
    fun all(): List<HttpExchangeDTO> = entries.toList()

    /** Échanges d'une présentation. */
    fun forTrace(traceId: String): List<HttpExchangeDTO> = entries.filter { it.traceId == traceId }

    fun clear() = entries.clear()

    /** Trace et enregistre l'échange ; les plus anciens sont évincés au-delà de [capacity]. */
    fun add(exchange: HttpExchangeDTO) {
        trace(exchange)
        entries.addLast(exchange)
        while (entries.size > capacity) entries.pollFirst()
    }

    /** Enregistre chaque appel de [client], y compris ceux en échec. */
    internal fun install(client: HttpClient) {
        client.plugin(HttpSend).intercept { request ->
            val traceId = currentCoroutineContext()[TraceId]?.value
            val start = System.nanoTime()
            val requestBody = request.bodyText()
            val requestHeaders = request.headers.build().toMap()
            val method = request.method.value
            val url = request.url.buildString()
            try {
                // save() met le corps en mémoire : il peut être lu ici puis par la lib EUDI.
                val call = execute(request).save()
                add(
                    HttpExchangeDTO(
                        traceId, Instant.now(), method, url, requestHeaders, requestBody,
                        call.response.status.value, call.response.headers.toMap(),
                        call.response.bodyAsText(), elapsed(start), null,
                    ),
                )
                call
            } catch (e: Exception) {
                add(HttpExchangeDTO(traceId, Instant.now(), method, url, requestHeaders, requestBody, null, emptyMap(), null, elapsed(start), e.toString()))
                throw e
            }
        }
    }

    /** INFO : une ligne par appel. DEBUG : en-têtes et corps (ils portent le vp_token : données de test uniquement). */
    private fun trace(e: HttpExchangeDTO) {
        val outcome = e.status?.toString() ?: "FAILED (${e.error})"
        log.info("[{}] OUT {} {} -> {} ({} ms)", e.traceId ?: "-", e.method, e.url, outcome, e.durationMs)
        if (log.isDebugEnabled) {
            log.debug("[{}] OUT request headers={} body={}", e.traceId ?: "-", e.requestHeaders, e.requestBody)
            log.debug("[{}] OUT response headers={} body={}", e.traceId ?: "-", e.responseHeaders, e.responseBody)
        }
    }

    private fun elapsed(start: Long) = (System.nanoTime() - start) / 1_000_000

    private fun Headers.toMap(): Map<String, List<String>> = names().associateWith { getAll(it).orEmpty() }

    /** Corps de la requête en texte, quel que soit son type de contenu. */
    private fun HttpRequestBuilder.bodyText(): String? = when (val b = body) {
        is FormDataContent -> b.formData.formUrlEncode()
        is TextContent -> b.text
        // Couvre aussi le formulaire propre à la lib EUDI (internal.response.FormData)
        is OutgoingContent.ByteArrayContent -> b.bytes().decodeToString()
        is OutgoingContent.NoContent -> null
        else -> b.toString()
    }
}
