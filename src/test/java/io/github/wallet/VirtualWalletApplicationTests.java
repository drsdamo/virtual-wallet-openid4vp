package io.github.wallet;

import io.github.wallet.presentation.support.openid4vp.OpenId4VpWalletClient;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

/** Le contexte Spring démarre et le client OpenID4VP est créé. */
@SpringBootTest(properties = "wallet.data-dir=target/test-wallet-data")
class VirtualWalletApplicationTests {

    @Autowired
    OpenId4VpWalletClient client;

    @Test
    void contextLoads() {
        assertThat(client).isNotNull();
    }
}
