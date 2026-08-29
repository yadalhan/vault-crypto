package com.xaan.vault.crypto.mybatis;

import com.xaan.vault.crypto.envelope.DekProvider;
import com.xaan.vault.crypto.envelope.EnvelopeCryptoService;
import com.xaan.vault.crypto.envelope.KekService;
import com.xaan.vault.crypto.envelope.WrappedDek;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.TypeHandlerRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Exercises the handler against a real JDBC connection (H2 in-memory) rather than mocks,
 * so it's actually verifying what a MyBatis mapper would see: the raw column holds
 * ciphertext, and reading it back through the handler yields the original plaintext.
 */
class EnvelopeCryptoTypeHandlerTest {

    private Connection connection;
    private TestTypeHandler handler;

    @BeforeEach
    void setUp() throws Exception {
        connection = DriverManager.getConnection("jdbc:h2:mem:typehandler-test-" + java.util.UUID.randomUUID());
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("CREATE TABLE secrets (id INT PRIMARY KEY, secret_value VARCHAR(500))");
        }

        KekService kek = new KekService(randomBytes(32));
        InMemoryDekProvider dekProvider = new InMemoryDekProvider();
        byte[] plaintextDek = randomBytes(32);
        dekProvider.store("board", new WrappedDek("board", 1, kek.wrap(plaintextDek)), 1);
        EnvelopeCryptoService cryptoService = EnvelopeCryptoService.forDomain((byte) 1, "board", kek, dekProvider);
        handler = new TestTypeHandler(cryptoService);
    }

    @AfterEach
    void tearDown() throws Exception {
        connection.close();
    }

    @Test
    void writingThroughTheHandlerStoresCiphertextNotPlaintext() throws Exception {
        try (PreparedStatement ps = connection.prepareStatement("INSERT INTO secrets (id, secret_value) VALUES (?, ?)")) {
            ps.setInt(1, 1);
            handler.setParameter(ps, 2, "s3cret-password", JdbcType.VARCHAR);
            ps.executeUpdate();
        }

        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT secret_value FROM secrets WHERE id = 1")) {
            rs.next();
            String stored = rs.getString("secret_value");
            assertNotEquals("s3cret-password", stored);
        }
    }

    @Test
    void readingThroughTheHandlerRecoversTheOriginalPlaintext() throws Exception {
        try (PreparedStatement ps = connection.prepareStatement("INSERT INTO secrets (id, secret_value) VALUES (?, ?)")) {
            ps.setInt(1, 2);
            handler.setParameter(ps, 2, "another-secret", JdbcType.VARCHAR);
            ps.executeUpdate();
        }

        try (PreparedStatement ps = connection.prepareStatement("SELECT secret_value FROM secrets WHERE id = 2");
             ResultSet rs = ps.executeQuery()) {
            rs.next();
            assertEquals("another-secret", handler.getResult(rs, "secret_value"));
        }
    }

    @Test
    void nullValuesPassThroughWithoutDecrypting() throws Exception {
        try (PreparedStatement ps = connection.prepareStatement("INSERT INTO secrets (id, secret_value) VALUES (?, ?)")) {
            ps.setInt(1, 3);
            ps.setNull(2, java.sql.Types.VARCHAR);
            ps.executeUpdate();
        }

        try (PreparedStatement ps = connection.prepareStatement("SELECT secret_value FROM secrets WHERE id = 3");
             ResultSet rs = ps.executeQuery()) {
            rs.next();
            assertNull(handler.getResult(rs, "secret_value"));
        }
    }

    @Test
    void emptyStringIsStoredAsEmptyNotAsCiphertext() throws Exception {
        try (PreparedStatement ps = connection.prepareStatement("INSERT INTO secrets (id, secret_value) VALUES (?, ?)")) {
            ps.setInt(1, 4);
            handler.setParameter(ps, 2, "", JdbcType.VARCHAR);
            ps.executeUpdate();
        }

        try (PreparedStatement ps = connection.prepareStatement("SELECT secret_value FROM secrets WHERE id = 4");
             ResultSet rs = ps.executeQuery()) {
            rs.next();
            assertEquals("", rs.getString("secret_value"));
            assertEquals("", handler.getResult(rs, "secret_value"));
        }
    }

    /**
     * Regression test for the exact bug that shipped once: registering this handler the
     * same way Spring Boot's MyBatis auto-configuration does ({@code TypeHandlerRegistry
     * .register(TypeHandler)}, applied to every {@code TypeHandler} bean found in the
     * context) must NOT make it MyBatis's default handler for every plain {@code String}
     * column - only for columns that reference it explicitly by class. A
     * {@code BaseTypeHandler}-based version of this class silently became the app-wide
     * default String handler (via TypeReference auto-discovery) and started encrypting
     * unrelated columns like a username or post title that had no {@code typeHandler=}
     * attribute at all.
     */
    @Test
    void registeringTheHandlerDoesNotMakeItTheDefaultHandlerForString() {
        TypeHandlerRegistry registry = new TypeHandlerRegistry();

        registry.register(handler);

        // MyBatis always has a built-in default handler for String - the point is that
        // registering ours must not replace it.
        assertNotEquals(handler, registry.getTypeHandler(String.class));
        assertEquals(handler, registry.getMappingTypeHandler(TestTypeHandler.class));
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static final class TestTypeHandler extends EnvelopeCryptoTypeHandler {
        TestTypeHandler(EnvelopeCryptoService cryptoService) {
            super(cryptoService);
        }
    }

    private static final class InMemoryDekProvider implements DekProvider {
        private final Map<String, List<WrappedDek>> versionsByDomain = new HashMap<>();
        private final Map<String, Integer> currentVersionByDomain = new HashMap<>();

        @Override
        public List<WrappedDek> loadAll(String domain) {
            return versionsByDomain.getOrDefault(domain, List.of());
        }

        @Override
        public int loadCurrentVersion(String domain) {
            return currentVersionByDomain.get(domain);
        }

        @Override
        public void store(String domain, WrappedDek newVersion, int newCurrentVersion) {
            versionsByDomain.computeIfAbsent(domain, d -> new ArrayList<>()).add(newVersion);
            currentVersionByDomain.put(domain, newCurrentVersion);
        }

        @Override
        public void retire(String domain, int version) {
            List<WrappedDek> versions = versionsByDomain.get(domain);
            if (versions != null) {
                versions.removeIf(wrapped -> wrapped.version() == version);
            }
        }
    }
}
