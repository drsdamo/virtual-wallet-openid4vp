package io.github.wallet.credentials.support;

import io.github.wallet.identity.dto.IdentityClaimDTO;
import io.github.wallet.identity.dto.IdentityDTO;
import io.github.wallet.identity.support.ClaimScope;
import io.github.wallet.identity.support.ClaimType;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

/** Porteur fictif créé quand la base est vide, avec les claims PID habituels (adresse, lieu de naissance…). */
public class TestPersona {

    public static final String FAMILY_NAME = "MARTIN";
    public static final String GIVEN_NAME = "Camille";
    public static final LocalDate BIRTH_DATE = LocalDate.of(1990, 5, 12);

    /** Nouvelle identité (identifiants aléatoires) pour ce porteur. */
    public IdentityDTO identity() {
        Instant now = Instant.now();
        return new IdentityDTO(UUID.randomUUID().toString(), FAMILY_NAME, GIVEN_NAME, BIRTH_DATE, List.of(
                claim("sex", "2", ClaimScope.ALL, ClaimType.NUMBER), // ISO/IEC 5218 : féminin
                claim("birth_family_name", FAMILY_NAME, ClaimScope.ALL),
                claim("place_of_birth.locality", "Lyon", ClaimScope.SD_JWT),
                claim("place_of_birth.country", "FR", ClaimScope.SD_JWT),
                claim("address.formatted", "12 rue de la Paix, 75002 Paris, France", ClaimScope.SD_JWT),
                claim("address.street_address", "rue de la Paix", ClaimScope.SD_JWT),
                claim("address.house_number", "12", ClaimScope.SD_JWT),
                claim("address.postal_code", "75002", ClaimScope.SD_JWT),
                claim("address.locality", "Paris", ClaimScope.SD_JWT),
                claim("address.country", "FR", ClaimScope.SD_JWT),
                claim("birth_place", "Lyon", ClaimScope.MDOC),
                claim("nationality", "FR", ClaimScope.MDOC),
                claim("resident_address", "12 rue de la Paix, 75002 Paris", ClaimScope.MDOC),
                claim("resident_city", "Paris", ClaimScope.MDOC),
                claim("resident_postal_code", "75002", ClaimScope.MDOC),
                claim("resident_country", "FR", ClaimScope.MDOC)),
                now, now);
    }

    private IdentityClaimDTO claim(String name, String value, ClaimScope scope) {
        return claim(name, value, scope, ClaimType.STRING);
    }

    private IdentityClaimDTO claim(String name, String value, ClaimScope scope, ClaimType type) {
        return new IdentityClaimDTO(UUID.randomUUID().toString(), name, type, value, scope);
    }
}
