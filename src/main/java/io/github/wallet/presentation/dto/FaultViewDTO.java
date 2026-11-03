package io.github.wallet.presentation.dto;

import io.github.wallet.presentation.support.Fault;

/** Défaut injectable, avec le format de credential concerné ({@code null} : tous). */
public record FaultViewDTO(Fault name, String format, String description) {
}
