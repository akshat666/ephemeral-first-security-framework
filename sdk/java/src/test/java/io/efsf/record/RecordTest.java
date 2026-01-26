package io.efsf.record;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Record Tests")
class RecordTest {

    @Test
    @DisplayName("TTLParser parses seconds correctly")
    void testParseTTLSeconds() {
        assertEquals(Duration.ofSeconds(30), TTLParser.parse("30s"));
        assertEquals(Duration.ofSeconds(1), TTLParser.parse("1s"));
        assertEquals(Duration.ofSeconds(3600), TTLParser.parse("3600s"));
    }

    @Test
    @DisplayName("TTLParser parses minutes correctly")
    void testParseTTLMinutes() {
        assertEquals(Duration.ofMinutes(5), TTLParser.parse("5m"));
        assertEquals(Duration.ofMinutes(30), TTLParser.parse("30m"));
    }

    @Test
    @DisplayName("TTLParser parses hours correctly")
    void testParseTTLHours() {
        assertEquals(Duration.ofHours(1), TTLParser.parse("1h"));
        assertEquals(Duration.ofHours(24), TTLParser.parse("24h"));
    }

    @Test
    @DisplayName("TTLParser parses days correctly")
    void testParseTTLDays() {
        assertEquals(Duration.ofDays(7), TTLParser.parse("7d"));
        assertEquals(Duration.ofDays(30), TTLParser.parse("30d"));
    }

    @Test
    @DisplayName("TTLParser parses weeks correctly")
    void testParseTTLWeeks() {
        assertEquals(Duration.ofDays(7), TTLParser.parse("1w"));
        assertEquals(Duration.ofDays(14), TTLParser.parse("2w"));
    }

    @Test
    @DisplayName("TTLParser throws on invalid format")
    void testParseTTLInvalid() {
        assertThrows(IllegalArgumentException.class, () -> TTLParser.parse("invalid"));
        assertThrows(IllegalArgumentException.class, () -> TTLParser.parse("30x"));
        assertThrows(IllegalArgumentException.class, () -> TTLParser.parse(""));
        assertThrows(IllegalArgumentException.class, () -> TTLParser.parse(null));
    }

    @Test
    @DisplayName("TTLParser formats duration correctly")
    void testFormatTTL() {
        assertEquals("30s", TTLParser.format(Duration.ofSeconds(30)));
        assertEquals("5m", TTLParser.format(Duration.ofMinutes(5)));
        assertEquals("2h", TTLParser.format(Duration.ofHours(2)));
        assertEquals("3d", TTLParser.format(Duration.ofDays(3)));
        assertEquals("1w", TTLParser.format(Duration.ofDays(7)));
        assertEquals("2w", TTLParser.format(Duration.ofDays(14)));
    }

    @Test
    @DisplayName("EphemeralRecord creates with TTL string")
    void testRecordCreate() {
        EphemeralRecord record = EphemeralRecord.create("30m");

        assertNotNull(record.getId());
        assertNotNull(record.getCreatedAt());
        assertNotNull(record.getExpiresAt());
        assertEquals(Duration.ofMinutes(30), record.getTtl());
        assertEquals(DataClassification.TRANSIENT, record.getClassification());
        assertFalse(record.isExpired());
    }

    @Test
    @DisplayName("EphemeralRecord creates with classification")
    void testRecordCreateWithClassification() {
        EphemeralRecord record = EphemeralRecord.create("7d", DataClassification.SHORT_LIVED);

        assertEquals(DataClassification.SHORT_LIVED, record.getClassification());
        assertEquals(Duration.ofDays(7), record.getTtl());
    }

    @Test
    @DisplayName("EphemeralRecord builder works correctly")
    void testRecordBuilder() {
        EphemeralRecord record = new EphemeralRecord.Builder()
            .id("test-id")
            .ttl("1h")
            .classification(DataClassification.RETENTION_BOUND)
            .metadata(Map.of("key", "value"))
            .build();

        assertEquals("test-id", record.getId());
        assertEquals(Duration.ofHours(1), record.getTtl());
        assertEquals(DataClassification.RETENTION_BOUND, record.getClassification());
        assertEquals("value", record.getMetadata().get("key"));
    }

    @Test
    @DisplayName("EphemeralRecord serializes to/from Map")
    void testRecordSerialization() {
        EphemeralRecord original = EphemeralRecord.create("2h", DataClassification.SHORT_LIVED);

        Map<String, Object> map = original.toMap();
        EphemeralRecord restored = EphemeralRecord.fromMap(map);

        assertEquals(original.getId(), restored.getId());
        assertEquals(original.getClassification(), restored.getClassification());
    }

    @Test
    @DisplayName("EphemeralRecord detects expiration")
    void testRecordExpiration() {
        EphemeralRecord expired = new EphemeralRecord.Builder()
            .ttl(Duration.ofSeconds(1))
            .createdAt(Instant.now().minusSeconds(10))
            .expiresAt(Instant.now().minusSeconds(5))
            .build();

        assertTrue(expired.isExpired());
        assertEquals(Duration.ZERO, expired.getRemainingTTL());
    }

    @Test
    @DisplayName("DataClassification validates TTL ranges")
    void testClassificationValidation() {
        // TRANSIENT: seconds to hours
        assertTrue(DataClassification.TRANSIENT.isValidTTL(Duration.ofMinutes(30)));
        assertTrue(DataClassification.TRANSIENT.isValidTTL(Duration.ofHours(1)));
        assertFalse(DataClassification.TRANSIENT.isValidTTL(Duration.ofDays(30)));

        // SHORT_LIVED: hours to days
        assertTrue(DataClassification.SHORT_LIVED.isValidTTL(Duration.ofHours(2)));
        assertTrue(DataClassification.SHORT_LIVED.isValidTTL(Duration.ofDays(7)));

        // PERSISTENT allows null TTL
        assertTrue(DataClassification.PERSISTENT.isValidTTL(null));
    }
}
