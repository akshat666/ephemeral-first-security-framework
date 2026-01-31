package app.hideit.record;

import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses human-readable TTL strings into Duration objects.
 * Supports formats like "30s", "5m", "2h", "7d".
 */
public final class TTLParser {

    private static final Pattern TTL_PATTERN = Pattern.compile("^(\\d+)([smhdw])$");

    private TTLParser() {
        // Utility class
    }

    /**
     * Parses a TTL string into a Duration.
     *
     * @param ttl the TTL string (e.g., "30s", "5m", "2h", "7d", "1w")
     * @return the parsed Duration
     * @throws IllegalArgumentException if the format is invalid
     */
    public static Duration parse(String ttl) {
        if (ttl == null || ttl.isBlank()) {
            throw new IllegalArgumentException("TTL cannot be null or empty");
        }

        Matcher matcher = TTL_PATTERN.matcher(ttl.trim().toLowerCase());
        if (!matcher.matches()) {
            throw new IllegalArgumentException(
                "Invalid TTL format: " + ttl + ". Expected format: <number><unit> where unit is s, m, h, d, or w"
            );
        }

        long value = Long.parseLong(matcher.group(1));
        String unit = matcher.group(2);

        return switch (unit) {
            case "s" -> Duration.ofSeconds(value);
            case "m" -> Duration.ofMinutes(value);
            case "h" -> Duration.ofHours(value);
            case "d" -> Duration.ofDays(value);
            case "w" -> Duration.ofDays(value * 7);
            default -> throw new IllegalArgumentException("Unknown time unit: " + unit);
        };
    }

    /**
     * Formats a Duration into a human-readable TTL string.
     *
     * @param duration the Duration to format
     * @return the formatted TTL string
     */
    public static String format(Duration duration) {
        if (duration == null) {
            throw new IllegalArgumentException("Duration cannot be null");
        }

        long seconds = duration.getSeconds();

        if (seconds % (7 * 24 * 60 * 60) == 0) {
            return (seconds / (7 * 24 * 60 * 60)) + "w";
        }
        if (seconds % (24 * 60 * 60) == 0) {
            return (seconds / (24 * 60 * 60)) + "d";
        }
        if (seconds % (60 * 60) == 0) {
            return (seconds / (60 * 60)) + "h";
        }
        if (seconds % 60 == 0) {
            return (seconds / 60) + "m";
        }
        return seconds + "s";
    }
}
