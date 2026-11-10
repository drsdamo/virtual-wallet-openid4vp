package io.github.wallet.issuance.dto;

import io.github.wallet.issuance.support.IssuanceFault;

/** Défaut injectable dans une émission. */
public record IssuanceFaultViewDTO(IssuanceFault name, String description) {
}
