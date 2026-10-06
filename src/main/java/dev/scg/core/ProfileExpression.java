package dev.scg.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * The value of {@code spring.config.activate.on-profile}, read as Spring Boot reads it: a
 * comma-separated list of profile expressions, any of which activates the document (a YAML list is
 * the same list, joined with commas). Each expression combines profile names with {@code !},
 * {@code &}, {@code |} and parentheses.
 * <p>
 * The parsing follows Spring Framework's {@code ProfilesParser} step by step, quirks included,
 * because what matters is which documents Spring applies, not a cleaner grammar. Measured against
 * Spring Boot 4.1.1 (VALIDATION.md, "Profile expressions in {@code on-profile}"):
 * <ul>
 *   <li>Spaces around a list item or a name are ignored, but a space inside a name is part of it:
 *       {@code 'a b'} is one profile named {@code a b}, not two.</li>
 *   <li>{@code &} and {@code |} mixed without parentheses ({@code 'a & b | c'}), an operator with
 *       nothing to apply to ({@code '!'}) and an empty item ({@code 'a,,b'}) are malformed: the
 *       application doesn't start.</li>
 *   <li>A stray parenthesis or a dangling {@code &}/{@code |} is tolerated: {@code 'a)'},
 *       {@code '(a'}, {@code '&a'} and {@code 'a&'} all mean {@code a}.</li>
 * </ul>
 * {@link #matches} takes the active profiles as Spring sees them: with none active, the caller
 * passes the default profile ({@code default}), which is then active.
 */
public final class ProfileExpression {

    private final String text;
    private final List<Node> items;

    private ProfileExpression(String text, List<Node> items) {
        this.text = text;
        this.items = List.copyOf(items);
    }

    /**
     * Parses an {@code on-profile} value as written.
     *
     * @throws IllegalArgumentException when Spring would reject the value: an empty item, or a
     *                                  malformed expression
     */
    public static ProfileExpression parse(String value) {
        Objects.requireNonNull(value, "value");
        List<Node> items = new ArrayList<>();
        // Spring Boot binds the value to a String[]: split on commas, each item trimmed.
        for (String item : value.split(",", -1)) {
            String expression = item.strip();
            if (expression.isEmpty()) {
                throw new IllegalArgumentException(
                        "Invalid profile expression [] in '%s': must contain text".formatted(value));
            }
            items.add(parseExpression(expression));
        }
        return new ProfileExpression(value, items);
    }

    /** Whether the document applies when exactly these profiles are active. */
    public boolean matches(Set<String> activeProfiles) {
        Objects.requireNonNull(activeProfiles, "activeProfiles");
        return items.stream().anyMatch(item -> item.matches(activeProfiles));
    }

    /** Every profile name the expression refers to, in the order written. */
    public Set<String> profileNames() {
        Set<String> names = new LinkedHashSet<>();
        items.forEach(item -> item.collectNames(names));
        return Collections.unmodifiableSet(names);
    }

    /** The value as written, for messages. */
    public String text() {
        return text;
    }

    @Override
    public String toString() {
        return text;
    }

    private enum Context { NONE, NEGATE, PARENTHESIS }

    private enum Operator { AND, OR }

    private static Node parseExpression(String expression) {
        StringTokenizer tokens = new StringTokenizer(expression, "()&|!", true);
        return parseTokens(expression, tokens, Context.NONE);
    }

    // Spring's ProfilesParser.parseTokens: a NEGATE context returns after one operand, a
    // PARENTHESIS context returns at its ')', and a ')' with no '(' merges what came before it.
    private static Node parseTokens(String expression, StringTokenizer tokens, Context context) {
        List<Node> elements = new ArrayList<>();
        Operator operator = null;
        while (tokens.hasMoreTokens()) {
            String token = tokens.nextToken().strip();
            if (token.isEmpty()) {
                continue;
            }
            switch (token) {
                case "(" -> {
                    Node contents = parseTokens(expression, tokens, Context.PARENTHESIS);
                    if (context == Context.NEGATE) {
                        return contents;
                    }
                    elements.add(contents);
                }
                case "&" -> {
                    assertWellFormed(expression, operator == null || operator == Operator.AND);
                    operator = Operator.AND;
                }
                case "|" -> {
                    assertWellFormed(expression, operator == null || operator == Operator.OR);
                    operator = Operator.OR;
                }
                case "!" -> elements.add(new Not(parseTokens(expression, tokens, Context.NEGATE)));
                case ")" -> {
                    Node merged = merge(expression, elements, operator);
                    if (context == Context.PARENTHESIS) {
                        return merged;
                    }
                    elements.clear();
                    elements.add(merged);
                    operator = null;
                }
                default -> {
                    Node name = new Name(token);
                    if (context == Context.NEGATE) {
                        return name;
                    }
                    elements.add(name);
                }
            }
        }
        return merge(expression, elements, operator);
    }

    private static Node merge(String expression, List<Node> elements, Operator operator) {
        assertWellFormed(expression, !elements.isEmpty());
        if (elements.size() == 1) {
            return elements.getFirst();
        }
        // As in Spring, names side by side with no operator combine as OR.
        return operator == Operator.AND ? new And(List.copyOf(elements)) : new Or(List.copyOf(elements));
    }

    private static void assertWellFormed(String expression, boolean wellFormed) {
        if (!wellFormed) {
            throw new IllegalArgumentException("Malformed profile expression [%s]".formatted(expression));
        }
    }

    private sealed interface Node permits Name, Not, And, Or {
        boolean matches(Set<String> activeProfiles);

        void collectNames(Set<String> names);
    }

    private record Name(String profile) implements Node {
        public boolean matches(Set<String> activeProfiles) {
            return activeProfiles.contains(profile);
        }

        public void collectNames(Set<String> names) {
            names.add(profile);
        }
    }

    private record Not(Node operand) implements Node {
        public boolean matches(Set<String> activeProfiles) {
            return !operand.matches(activeProfiles);
        }

        public void collectNames(Set<String> names) {
            operand.collectNames(names);
        }
    }

    private record And(List<Node> operands) implements Node {
        public boolean matches(Set<String> activeProfiles) {
            return operands.stream().allMatch(operand -> operand.matches(activeProfiles));
        }

        public void collectNames(Set<String> names) {
            operands.forEach(operand -> operand.collectNames(names));
        }
    }

    private record Or(List<Node> operands) implements Node {
        public boolean matches(Set<String> activeProfiles) {
            return operands.stream().anyMatch(operand -> operand.matches(activeProfiles));
        }

        public void collectNames(Set<String> names) {
            operands.forEach(operand -> operand.collectNames(names));
        }
    }
}
