package io.github.wallet.presentation.support;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Lit dans les claims lisibles d'un credential la valeur désignée par un chemin DCQL.
 * <p>
 * Un élément de chemin est un nom (objet), un entier (index de tableau) ou {@code null} (tous les éléments
 * du tableau). Pour un mdoc, le chemin est {@code [namespace, élément]}, ce qui correspond à la structure
 * namespace → élément → valeur des claims.
 */
public class ClaimValueReader {

    /** Valeur au bout du chemin ; {@code null} si le chemin ne mène à rien. */
    public Object read(Map<String, Object> claims, List<Object> path) {
        return read(claims, path, 0);
    }

    private Object read(Object node, List<Object> path, int index) {
        if (index == path.size() || node == null) {
            return node;
        }
        Object step = path.get(index);
        return switch (node) {
            case Map<?, ?> map when step instanceof String name -> read(map.get(name), path, index + 1);
            case List<?> list when step instanceof Number n ->
                    n.intValue() >= 0 && n.intValue() < list.size() ? read(list.get(n.intValue()), path, index + 1) : null;
            case List<?> list when step == null -> {
                List<Object> values = new ArrayList<>();
                list.forEach(item -> values.add(read(item, path, index + 1)));
                yield values;
            }
            default -> null;
        };
    }
}
