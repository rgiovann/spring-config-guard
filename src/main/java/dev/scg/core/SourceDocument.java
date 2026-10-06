package dev.scg.core;

import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * A ConfigDocument with the file it comes from and that file's profile: {@code prod} for
 * {@code application-prod.yml}, empty for {@code application.yml}. The file's profile is a
 * condition of its own, combined with the document's {@code on-profile}: Spring Boot applies a
 * document of {@code application-prod.yml} only when {@code prod} is active, and, if the document
 * has an {@code on-profile}, only when that matches too (VALIDATION.md, "Profile expressions in
 * {@code on-profile}", P12).
 */
public record SourceDocument(Path file, Optional<String> fileProfile, ConfigDocument document) {

    /** Whether Spring Boot applies this document when exactly these profiles are active. */
    public boolean appliesTo(Set<String> activeProfiles) {
        return fileProfile.map(activeProfiles::contains).orElse(true)
                && document.activation().map(expression -> expression.matches(activeProfiles)).orElse(true);
    }

    /** Whether the document has any condition: a file profile or an {@code on-profile}. */
    public boolean isConditional() {
        return fileProfile.isPresent() || document.activation().isPresent();
    }

    /** Every profile name its conditions refer to, the file's profile first. */
    public Set<String> profileNames() {
        Set<String> names = new LinkedHashSet<>();
        fileProfile.ifPresent(names::add);
        document.activation().ifPresent(expression -> names.addAll(expression.profileNames()));
        return names;
    }
}
