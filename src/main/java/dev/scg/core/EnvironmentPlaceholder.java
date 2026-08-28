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
                // "${" sem fechamento correspondente: trata o restante como
                // literal, não é sintaxe de placeholder válida.
                result.append(text, start, text.length());
                return Optional.of(result.toString());
            }

            String body = text.substring(start + PREFIX.length(), end);
            Optional<String> resolvedPlaceholder = resolvePlaceholderBody(body);
            if (resolvedPlaceholder.isEmpty()) {
                return Optional.empty(); // qualquer placeholder sem default -> valor indeterminado
            }
            result.append(resolvedPlaceholder.get());
            i = end + 1;
        }
        return Optional.of(result.toString());
    }

    private static Optional<String> resolvePlaceholderBody(String body) {
        int separatorIndex = findTopLevelSeparator(body);
        if (separatorIndex < 0) {
            return Optional.empty(); // sem default -> não determinável estaticamente
        }
        String defaultExpression = body.substring(separatorIndex + 1);
        return resolveSegment(defaultExpression); // default pode conter placeholder aninhado
    }

    /** Profundidade de chaves: só conta '{' como abertura de novo placeholder se vier logo após '$'. */
    private static int findMatchingBrace(String text, int fromIndex) {
        int depth = 1;
        for (int i = fromIndex; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '{' && i > 0 && text.charAt(i - 1) == '$') {
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
            if (c == '{' && i > 0 && body.charAt(i - 1) == '$') {
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