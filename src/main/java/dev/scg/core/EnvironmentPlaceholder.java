package dev.scg.core;

import java.util.Optional;

public final class EnvironmentPlaceholder {

    private static final String PREFIX = "${";
    private static final char SUFFIX = '}';
    private static final char DEFAULT_SEPARATOR = ':';

    private EnvironmentPlaceholder() {}

    public static Optional<String> resolve(String rawValue) {
        if (rawValue == null) {
            return Optional.empty();
        }
        return resolveSegment(rawValue);
    }

    private static Optional<String> resolveSegment(String text) {
        StringBuilder result = new StringBuilder();
        int i = 0;
        while (i < text.length()) {
            int start = text.indexOf(PREFIX, i);
            if (start < 0) {
                result.append(text, i, text.length());
                return Optional.of(result.toString());
            }
            result.append(text, i, start);

            int end = findMatchingBrace(text, start + PREFIX.length());
            if (end < 0) {
                // "${" without a corresponding closing delimiter: treat the remainder as
                // literal; it is not valid placeholder syntax.
                result.append(text, start, text.length());
                return Optional.of(result.toString());
            }

            String body = text.substring(start + PREFIX.length(), end);
            Optional<String> resolvedPlaceholder = resolvePlaceholderBody(body);
            if (resolvedPlaceholder.isEmpty()) {
                return Optional.empty(); // any placeholder without a default -> indeterminate value
            }
            result.append(resolvedPlaceholder.get());
            i = end + 1;
        }
        return Optional.of(result.toString());
    }

    private static Optional<String> resolvePlaceholderBody(String body) {
        int separatorIndex = findTopLevelSeparator(body);
        if (separatorIndex < 0) {
            return Optional.empty(); // no default -> cannot be determined statically
        }
        String defaultExpression = body.substring(separatorIndex + 1);
        return resolveSegment(defaultExpression); // default may contain a nested placeholder
    }

    /** Key depth: only count '{' as opening a new placeholder if it immediately follows '$'. */
    private static int findMatchingBrace(String text, int fromIndex) {
        int depth = 1;
        for (int i = fromIndex; i < text.length(); i++) {
            char c = text.charAt(i);
            //We are already inside a placeholder (${), so any '{' opens a new level.
            if (c == '{') {
                depth++;
            } else if (c == SUFFIX) {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    private static int findTopLevelSeparator(String body) {
        int depth = 0;
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            // Any '{' increments the level within the body to protect the separator ':'
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
            } else if (c == DEFAULT_SEPARATOR && depth == 0) {
                return i;
            }
        }
        return -1;
    }
}