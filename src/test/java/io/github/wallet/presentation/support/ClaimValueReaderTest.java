package io.github.wallet.presentation.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Lecture des valeurs de claims par chemin DCQL. */
class ClaimValueReaderTest {

    private final ClaimValueReader reader = new ClaimValueReader();
    private final Map<String, Object> claims = Map.of(
            "family_name", "MARTIN",
            "address", Map.of("locality", "Nantes"),
            "nationalities", List.of("FR", "DE"),
            "org.iso.18013.5.1", Map.of("age_over_18", true));

    @Test
    void readsNestedObjectsAndMdocElements() {
        assertThat(reader.read(claims, List.of("family_name"))).isEqualTo("MARTIN");
        assertThat(reader.read(claims, List.of("address", "locality"))).isEqualTo("Nantes");
        assertThat(reader.read(claims, List.of("org.iso.18013.5.1", "age_over_18"))).isEqualTo(true);
    }

    @Test
    void readsArrayElements() {
        assertThat(reader.read(claims, List.of("nationalities", 1))).isEqualTo("DE");
        assertThat(reader.read(claims, Arrays.asList("nationalities", null))).isEqualTo(List.of("FR", "DE"));
    }

    @Test
    void missingPathGivesNull() {
        assertThat(reader.read(claims, List.of("birth_place"))).isNull();
        assertThat(reader.read(claims, List.of("nationalities", 5))).isNull();
        assertThat(reader.read(claims, List.of("family_name", "x"))).isNull();
    }
}
