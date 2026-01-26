package io.efsf.examples;

import io.efsf.EphemeralStore;
import io.efsf.certificate.AttestationAuthority;
import io.efsf.certificate.DestructionCertificate;
import io.efsf.exception.RecordNotFoundException;
import io.efsf.record.DataClassification;
import io.efsf.record.EphemeralRecord;
import io.efsf.store.MemoryBackend;

import java.util.Map;
import java.util.Optional;

/**
 * Example showing how EFSF could be integrated with Spring Boot.
 *
 * This is a standalone simulation - in a real Spring Boot app, you would:
 * 1. Create EphemeralStore as a @Bean
 * 2. Inject it into your services
 * 3. Use it in your REST controllers
 *
 * Dependencies needed in pom.xml for actual Spring Boot:
 * - spring-boot-starter-web
 * - spring-boot-starter-data-redis (for Redis backend)
 */
public class SpringBootExample {

    public static void main(String[] args) {
        System.out.println("=== EFSF Spring Boot Integration Example ===\n");

        // Simulate Spring Boot context
        EphemeralStoreConfig config = new EphemeralStoreConfig();
        EphemeralStore store = config.ephemeralStore();
        AttestationAuthority authority = config.attestationAuthority();

        // Simulate services
        SessionService sessionService = new SessionService(store);
        UserDataService userDataService = new UserDataService(store, authority);

        // Simulate REST controller operations
        simulateLoginFlow(sessionService);
        simulateUserDataFlow(userDataService);

        // Cleanup
        store.close();
        System.out.println("\n=== Example completed ===");
    }

    static void simulateLoginFlow(SessionService sessionService) {
        System.out.println("--- Simulating Login Flow ---");

        // POST /api/auth/login
        String sessionId = sessionService.createSession("user-123", "192.168.1.1");
        System.out.println("Created session: " + sessionId);

        // GET /api/auth/session/{id}
        Optional<Map<String, Object>> session = sessionService.getSession(sessionId);
        System.out.println("Session data: " + session.orElse(Map.of()));

        // DELETE /api/auth/logout
        boolean loggedOut = sessionService.invalidateSession(sessionId);
        System.out.println("Logged out: " + loggedOut);

        System.out.println();
    }

    static void simulateUserDataFlow(UserDataService userDataService) {
        System.out.println("--- Simulating User Data Flow ---");

        // POST /api/users/{id}/sensitive-data
        String recordId = userDataService.storeTemporaryPII("user-456", Map.of(
            "ssn", "123-45-6789",
            "dob", "1990-01-15"
        ));
        System.out.println("Stored PII with record: " + recordId);

        // GET /api/users/{id}/sensitive-data/{recordId}
        Optional<Map<String, Object>> data = userDataService.retrievePII(recordId);
        System.out.println("Retrieved PII: " + data.map(d -> "[REDACTED]").orElse("not found"));

        // DELETE /api/users/{id}/sensitive-data/{recordId} (with GDPR compliance)
        DestructionCertificate cert = userDataService.deletePII(recordId);
        System.out.println("Deletion certificate: " + cert.getId());
        System.out.println("  Signed: " + cert.isSigned());
        System.out.println("  Method: " + cert.getMethod());

        System.out.println();
    }

    // ========== Configuration (would be @Configuration in Spring Boot) ==========

    static class EphemeralStoreConfig {

        // @Bean
        public EphemeralStore ephemeralStore() {
            // In production, use Redis:
            // return EphemeralStore.builder()
            //     .backend("redis://localhost:6379")
            //     .defaultTTL("1h")
            //     .authority(attestationAuthority())
            //     .build();

            return EphemeralStore.builder()
                .backend(new MemoryBackend())
                .defaultTTL("1h")
                .authority(attestationAuthority())
                .build();
        }

        // @Bean
        public AttestationAuthority attestationAuthority() {
            // In production, load from secure storage:
            // String privateKey = secretsManager.getSecret("efsf-attestation-key");
            // return AttestationAuthority.fromBase64PrivateKey("prod-authority", privateKey);

            return AttestationAuthority.create("dev-authority");
        }
    }

    // ========== Services (would be @Service in Spring Boot) ==========

    static class SessionService {
        private final EphemeralStore store;

        // @Autowired
        public SessionService(EphemeralStore store) {
            this.store = store;
        }

        public String createSession(String userId, String ipAddress) {
            Map<String, Object> sessionData = Map.of(
                "user_id", userId,
                "ip_address", ipAddress,
                "created_at", System.currentTimeMillis()
            );

            EphemeralRecord record = store.put(sessionData, "30m", DataClassification.TRANSIENT);
            return record.getId();
        }

        public Optional<Map<String, Object>> getSession(String sessionId) {
            return store.getOptional(sessionId);
        }

        public boolean invalidateSession(String sessionId) {
            try {
                store.destroy(sessionId);
                return true;
            } catch (RecordNotFoundException e) {
                return false;
            }
        }
    }

    static class UserDataService {
        private final EphemeralStore store;
        private final AttestationAuthority authority;

        // @Autowired
        public UserDataService(EphemeralStore store, AttestationAuthority authority) {
            this.store = store;
            this.authority = authority;
        }

        public String storeTemporaryPII(String userId, Map<String, Object> pii) {
            Map<String, Object> data = Map.of(
                "user_id", userId,
                "pii", pii,
                "purpose", "verification",
                "stored_at", System.currentTimeMillis()
            );

            // Store with SHORT_LIVED classification - auto-expires in 24h
            EphemeralRecord record = store.put(data, "24h", DataClassification.SHORT_LIVED);
            return record.getId();
        }

        public Optional<Map<String, Object>> retrievePII(String recordId) {
            return store.getOptional(recordId);
        }

        public DestructionCertificate deletePII(String recordId) {
            // Returns signed certificate for GDPR/compliance audit trail
            return store.destroy(recordId);
        }
    }

    // ========== REST Controller Example (would be @RestController) ==========
    /*
    @RestController
    @RequestMapping("/api/auth")
    public class AuthController {

        @Autowired
        private SessionService sessionService;

        @PostMapping("/login")
        public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request,
                                                   HttpServletRequest httpRequest) {
            // Authenticate user...
            String sessionId = sessionService.createSession(
                user.getId(),
                httpRequest.getRemoteAddr()
            );
            return ResponseEntity.ok(new LoginResponse(sessionId));
        }

        @GetMapping("/session/{id}")
        public ResponseEntity<SessionResponse> getSession(@PathVariable String id) {
            return sessionService.getSession(id)
                .map(data -> ResponseEntity.ok(new SessionResponse(data)))
                .orElse(ResponseEntity.notFound().build());
        }

        @DeleteMapping("/logout")
        public ResponseEntity<Void> logout(@RequestHeader("X-Session-Id") String sessionId) {
            sessionService.invalidateSession(sessionId);
            return ResponseEntity.noContent().build();
        }
    }

    @RestController
    @RequestMapping("/api/gdpr")
    public class GDPRController {

        @Autowired
        private UserDataService userDataService;

        @DeleteMapping("/users/{userId}/data")
        public ResponseEntity<DeletionResponse> deleteUserData(@PathVariable String userId,
                                                               @RequestParam List<String> recordIds) {
            List<DestructionCertificate> certificates = recordIds.stream()
                .map(userDataService::deletePII)
                .toList();

            return ResponseEntity.ok(new DeletionResponse(
                certificates.size(),
                certificates.stream().map(c -> c.toMap()).toList()
            ));
        }
    }
    */
}
