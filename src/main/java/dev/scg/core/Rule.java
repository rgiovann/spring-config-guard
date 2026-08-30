package dev.scg.core;

import java.util.List;

/**
 * Contract that every validation rule implements.
 * <p>
 * Receives the entire EffectiveConfig (rather than separate parameters) for two
 * reasons: (1) it avoids a Long Parameter List as the context grows
 * (there are already 3 pieces of information today: file, profile, properties);
 * (2) Open/Closed — adding a new field to EffectiveConfig in the future
 * does not require changing this method's signature, nor recompiling or touching
 * rules that do not use the new field.
 */
public interface Rule {

    String id();

    String description();

    List<Finding> check(EffectiveConfig config);
}