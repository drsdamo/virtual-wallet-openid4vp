package io.github.wallet.presentation.support.openid4vp;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Charge les ancres de confiance de {@code VerifierTrust} depuis des fichiers PEM (ou DER). */
public class TrustAnchorLoader {

    private static final Logger log = LogManager.getLogger(TrustAnchorLoader.class);

    /** Lit tous les certificats des fichiers donnés. */
    public List<X509Certificate> load(List<Path> files) {
        List<X509Certificate> anchors = new ArrayList<>();
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (Path file : files) {
                try (InputStream input = Files.newInputStream(file)) {
                    factory.generateCertificates(input).forEach(c -> anchors.add((X509Certificate) c));
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (CertificateException e) {
            throw new IllegalStateException("invalid verifier trust anchor", e);
        }
        log.info("Loaded {} verifier trust anchor(s) from {}", anchors.size(), files);
        return anchors;
    }
}
