package io.efsf.certificate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

/**
 * A tamper-evident chain of custody for tracking data handling.
 * Each entry includes a hash of the previous entry, forming a chain.
 */
public final class ChainOfCustody {

    private final List<Entry> entries;

    public ChainOfCustody() {
        this.entries = new ArrayList<>();
    }

    private ChainOfCustody(List<Entry> entries) {
        this.entries = new ArrayList<>(entries);
    }

    /**
     * Adds a new entry to the chain.
     *
     * @param action the action performed
     * @param actor the actor who performed the action
     * @param details additional details (optional)
     * @return this ChainOfCustody for chaining
     */
    public ChainOfCustody addEntry(String action, String actor, String details) {
        String previousHash = entries.isEmpty() ? null : entries.get(entries.size() - 1).getHash();
        Entry entry = new Entry(action, actor, details, Instant.now(), previousHash);
        entries.add(entry);
        return this;
    }

    /**
     * Adds a new entry to the chain.
     *
     * @param action the action performed
     * @param actor the actor who performed the action
     * @return this ChainOfCustody for chaining
     */
    public ChainOfCustody addEntry(String action, String actor) {
        return addEntry(action, actor, null);
    }

    /**
     * Gets all entries in the chain.
     *
     * @return an unmodifiable list of entries
     */
    public List<Entry> getEntries() {
        return Collections.unmodifiableList(entries);
    }

    /**
     * Verifies the integrity of the chain.
     *
     * @return true if the chain is valid
     */
    public boolean verify() {
        String previousHash = null;
        for (Entry entry : entries) {
            if (!Objects.equals(entry.getPreviousHash(), previousHash)) {
                return false;
            }
            previousHash = entry.getHash();
        }
        return true;
    }

    /**
     * Converts this chain to a list of maps.
     *
     * @return a list of entry maps
     */
    public List<Map<String, Object>> toList() {
        return entries.stream()
            .map(Entry::toMap)
            .toList();
    }

    /**
     * Creates a ChainOfCustody from a list of maps.
     *
     * @param list the list of entry maps
     * @return a new ChainOfCustody
     */
    public static ChainOfCustody fromList(List<Map<String, Object>> list) {
        List<Entry> entries = list.stream()
            .map(Entry::fromMap)
            .toList();
        return new ChainOfCustody(entries);
    }

    /**
     * An entry in the chain of custody.
     */
    public static final class Entry {
        private final String action;
        private final String actor;
        private final String details;
        private final Instant timestamp;
        private final String previousHash;
        private final String hash;

        public Entry(String action, String actor, String details, Instant timestamp, String previousHash) {
            this.action = Objects.requireNonNull(action);
            this.actor = Objects.requireNonNull(actor);
            this.details = details;
            this.timestamp = Objects.requireNonNull(timestamp);
            this.previousHash = previousHash;
            this.hash = computeHash();
        }

        private String computeHash() {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                String content = action + "|" + actor + "|" + (details != null ? details : "") + "|" + timestamp + "|" + (previousHash != null ? previousHash : "");
                byte[] hashBytes = digest.digest(content.getBytes(StandardCharsets.UTF_8));
                return Base64.getEncoder().encodeToString(hashBytes);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("SHA-256 not available", e);
            }
        }

        public String getAction() {
            return action;
        }

        public String getActor() {
            return actor;
        }

        public String getDetails() {
            return details;
        }

        public Instant getTimestamp() {
            return timestamp;
        }

        public String getPreviousHash() {
            return previousHash;
        }

        public String getHash() {
            return hash;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("action", action);
            map.put("actor", actor);
            if (details != null) {
                map.put("details", details);
            }
            map.put("timestamp", timestamp.toString());
            if (previousHash != null) {
                map.put("previous_hash", previousHash);
            }
            map.put("hash", hash);
            return map;
        }

        public static Entry fromMap(Map<String, Object> map) {
            return new Entry(
                (String) map.get("action"),
                (String) map.get("actor"),
                (String) map.get("details"),
                Instant.parse((String) map.get("timestamp")),
                (String) map.get("previous_hash")
            );
        }
    }
}
