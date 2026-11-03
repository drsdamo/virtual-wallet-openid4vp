package io.github.wallet.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/** Enregistre le filtre de trace des requêtes entrantes. */
@Configuration(proxyBeanMethods = false)
class HttpTraceConfiguration {

    /** Premier filtre de la chaîne : le statut et la durée tracés couvrent tout le traitement. */
    @Bean
    FilterRegistrationBean<HttpTraceFilter> httpTraceFilter() {
        var registration = new FilterRegistrationBean<>(new HttpTraceFilter());
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
