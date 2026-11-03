package io.github.wallet.presentation.support

import io.github.wallet.credentials.support.MdocCredential
import io.github.wallet.credentials.support.SdJwtVcCredential
import io.github.wallet.credentials.support.WalletCredential

import eu.europa.ec.eudi.openid4vp.dcql.ClaimPath
import eu.europa.ec.eudi.openid4vp.dcql.ClaimPathElement
import eu.europa.ec.eudi.openid4vp.dcql.ClaimsQuery
import eu.europa.ec.eudi.openid4vp.dcql.CredentialQuery
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import eu.europa.ec.eudi.openid4vp.dcql.metaMsoMdoc
import eu.europa.ec.eudi.openid4vp.dcql.metaSdJwtVc
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tstr

/**
 * Moteur DCQL minimal (OpenID4VP 1.0 §6).
 *
 * Pris en charge : format + `vct_values` / `doctype_value`, `claims` avec chemins et `values`, `claim_sets`
 * (la première option satisfaisable l'emporte). Les `credential_sets` ne sont pas évalués : chaque requête reçoit
 * une réponse quand c'est possible.
 */
class DcqlMatcher(private val credentials: List<WalletCredential>) {

    /** Une correspondance par requête de credential, dans l'ordre de la requête DCQL. */
    fun match(dcql: DCQL): List<QueryMatch> = dcql.credentials.value.map(::match)

    private fun match(query: CredentialQuery): QueryMatch {
        val types = requestedTypes(query)
        val candidates = credentials.filter { it.format == query.format.value && (types.isEmpty() || it.type in types) }
        if (candidates.isEmpty()) {
            return QueryMatch(query.id.value, query.format.value, types, null, null, "no ${query.format.value} credential of type $types")
        }
        val claims = query.claims
        if (claims == null) {
            return QueryMatch(query.id.value, query.format.value, types, candidates.first(), null, null)
        }
        val options: List<List<ClaimsQuery>> = query.claimSets
            ?.map { set -> set.value.map { id -> claims.first { it.id == id } } }
            ?: listOf(claims)

        for (credential in candidates) {
            val option = options.firstOrNull { option -> option.all { satisfies(credential, it) } } ?: continue
            return QueryMatch(query.id.value, query.format.value, types, credential, option.map { it.path.toList() }, null)
        }
        val missing = claims.filterNot { c -> candidates.any { satisfies(it, c) } }.map { it.path.toList() }
        return QueryMatch(query.id.value, query.format.value, types, null, null, "missing claims $missing")
    }

    private fun requestedTypes(query: CredentialQuery): List<String> = when (query.format.value) {
        SdJwtVcCredential.FORMAT -> query.metaSdJwtVc?.vctValues.orEmpty()
        MdocCredential.FORMAT -> listOfNotNull(query.metaMsoMdoc?.doctypeValue?.value)
        else -> emptyList()
    }

    /** Le credential contient-il le claim, avec l'une des `values` attendues si la requête en précise ? */
    private fun satisfies(credential: WalletCredential, claim: ClaimsQuery): Boolean {
        val found = when (credential) {
            is SdJwtVcCredential -> select(credential.claims, claim.path.value)
            is MdocCredential -> mdocValue(credential, claim.path)?.let(::listOf).orEmpty()
        }
        if (found.isEmpty()) return false
        val expected = claim.values ?: return true
        return found.any { value -> expected.any { (it as? JsonPrimitive)?.toPlain() == value } }
    }

    /** Valeur d'un élément mdoc ; le chemin d'un claim mdoc est toujours `[namespace, élément]`. */
    private fun mdocValue(credential: MdocCredential, path: ClaimPath): Any? {
        val (ns, element) = path.value.mapNotNull { (it as? ClaimPathElement.Claim)?.name }.takeIf { it.size == 2 } ?: return null
        val item = credential.issuerNamespaces.data[ns]?.get(element) ?: return null
        return when (val v = item.dataElementValue) {
            is Tstr -> v.value
            Simple.TRUE -> true
            Simple.FALSE -> false
            else -> Cbor.toDiagnostics(v)
        }
    }

    /** Applique un chemin de claim à des valeurs JSON simples ; renvoie toutes les valeurs sélectionnées. */
    private fun select(root: Any?, path: List<ClaimPathElement>): List<Any?> {
        var current = listOf(root)
        for (element in path) {
            current = current.flatMap { node ->
                when (element) {
                    is ClaimPathElement.Claim -> (node as? Map<*, *>)?.takeIf { element.name in it }?.let { listOf(it[element.name]) }.orEmpty()
                    is ClaimPathElement.ArrayElement -> (node as? List<*>)?.getOrNull(element.index)?.let(::listOf).orEmpty()
                    ClaimPathElement.AllArrayElements -> (node as? List<*>).orEmpty()
                }
            }
        }
        return current
    }

    /** Chemin DCQL → liste (nom, index, ou `null` pour « tous les éléments »). */
    private fun ClaimPath.toList(): List<Any?> = value.map {
        when (it) {
            is ClaimPathElement.Claim -> it.name
            is ClaimPathElement.ArrayElement -> it.index
            ClaimPathElement.AllArrayElements -> null
        }
    }

    private fun JsonPrimitive.toPlain(): Any = if (isString) content else booleanOrNull ?: longOrNull ?: content
}
