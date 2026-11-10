package io.github.wallet.credentials.web;

import io.github.wallet.credentials.dto.CredentialViewDTO;
import io.github.wallet.credentials.service.CredentialStore;
import io.github.wallet.credentials.support.WalletKeyMaterial;

import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Consultation des credentials émis et du certificat racine de l'autorité de test. */
@RestController
@RequestMapping("/api")
class CredentialsController {

    private static final Logger log = LogManager.getLogger(CredentialsController.class);

    private final CredentialStore store;
    private final WalletKeyMaterial keys;

    CredentialsController(CredentialStore store, WalletKeyMaterial keys) {
        this.store = store;
        this.keys = keys;
    }

    /** Tous les credentials du wallet, avec leurs claims. */
    @GetMapping("/credentials")
    List<CredentialViewDTO> credentials() {
        List<CredentialViewDTO> credentials = store.all().stream()
                .map(c -> new CredentialViewDTO(c.getId(), c.getFormat(), c.getType(), c.getIssuer(), c.getClaims()))
                .toList();
        log.debug("Listing {} credentials", credentials.size());
        return credentials;
    }

    /** Certificat racine (IACA) de la fausse autorité, à ajouter à la liste de confiance du verifier. */
    @GetMapping(value = "/trust/iaca.pem", produces = "application/x-pem-file")
    String iacaCertificate() {
        return keys.iacaCertificatePem();
    }
}
