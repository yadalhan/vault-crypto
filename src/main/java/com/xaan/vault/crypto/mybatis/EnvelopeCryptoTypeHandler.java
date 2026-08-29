package com.xaan.vault.crypto.mybatis;

import com.xaan.vault.crypto.envelope.EnvelopeCryptoService;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.TypeHandler;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Makes a single MyBatis-mapped column transparently AES-GCM-encrypted: application
 * code sets/gets the plaintext Java field as normal, and this handler encrypts on the
 * way into a {@code PreparedStatement} parameter and decrypts on the way out of a
 * {@code ResultSet} - so a mapper's SQL and the service code that calls it never touch
 * {@link EnvelopeCryptoService} directly.
 *
 * <p>One instance is scoped to exactly one {@link EnvelopeCryptoService} (i.e. one
 * domain), since a stored ciphertext can only be decrypted by the domain that encrypted
 * it. A project with more than one domain needs one subclass per domain - MyBatis
 * references a type handler by class in {@code #{prop,typeHandler=...}} or
 * {@code @Result(typeHandler=...)}, so there's no way to parameterize a single class
 * with a different {@code EnvelopeCryptoService} per column at the SQL-annotation level:
 *
 * <pre>{@code
 * @Component
 * public class UserPiiTypeHandler extends EnvelopeCryptoTypeHandler {
 *     public UserPiiTypeHandler(@Qualifier("userPiiCryptoService") EnvelopeCryptoService cryptoService) {
 *         super(cryptoService);
 *     }
 * }
 * }</pre>
 *
 * <p>Implements {@link TypeHandler} directly rather than extending MyBatis's usual
 * {@code BaseTypeHandler} - deliberately. {@code BaseTypeHandler<T>} also extends
 * {@code TypeReference<T>}, which MyBatis's {@code TypeHandlerRegistry.register(TypeHandler)}
 * uses to auto-discover a handler's mapped Java type when no {@code @MappedTypes} is
 * present. Since Spring Boot's MyBatis auto-configuration registers every
 * {@code TypeHandler} bean this way, a {@code BaseTypeHandler<String>} subclass would get
 * silently auto-registered as the *default* handler for every plain {@code String}
 * column/parameter in the whole application - not just the one column it's meant for -
 * encrypting things like a username or post title that never had an explicit
 * {@code typeHandler=} attribute. Implementing the bare {@link TypeHandler} interface
 * instead (no {@code TypeReference}) makes that auto-discovery a no-op, so this handler
 * is only ever used where a mapper names it explicitly.
 *
 * <p><b>Only use this on a column that is always in this library's envelope format.</b>
 * A read that hits a row predating envelope encryption, or written by something else
 * entirely, throws {@code CryptoException} out of {@code getResult(...)} - which will
 * surface on every query that touches the row, not just a deliberate password-check
 * call. For a column where legacy/foreign data might still be present, keep decrypting
 * explicitly and selectively via {@link EnvelopeCryptoService} in application code
 * instead of wiring this handler onto the read path (it's still fine to use it
 * write-side only, on just the {@code #{...}} parameter in `@Insert`/`@Update`, leaving
 * `@Select` queries returning the column as a plain, undecrypted `String`).
 */
public abstract class EnvelopeCryptoTypeHandler implements TypeHandler<String> {

    private final EnvelopeCryptoService cryptoService;

    protected EnvelopeCryptoTypeHandler(EnvelopeCryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @Override
    public void setParameter(PreparedStatement ps, int i, String parameter, JdbcType jdbcType) throws SQLException {
        if (parameter == null) {
            ps.setString(i, null);
            return;
        }
        // Empty string is treated the same as null (encrypting "" would turn "no value" into
        // non-empty ciphertext, which breaks any `value != null && !value.isEmpty()`-style
        // check elsewhere in the application - e.g. "is this row password-protected at all").
        ps.setString(i, parameter.isEmpty() ? parameter : cryptoService.encrypt(parameter));
    }

    @Override
    public String getResult(ResultSet rs, String columnName) throws SQLException {
        return decryptIfPresent(rs.getString(columnName));
    }

    @Override
    public String getResult(ResultSet rs, int columnIndex) throws SQLException {
        return decryptIfPresent(rs.getString(columnIndex));
    }

    @Override
    public String getResult(CallableStatement cs, int columnIndex) throws SQLException {
        return decryptIfPresent(cs.getString(columnIndex));
    }

    private String decryptIfPresent(String stored) {
        if (stored == null || stored.isEmpty()) {
            return stored;
        }
        return cryptoService.decrypt(stored);
    }
}
