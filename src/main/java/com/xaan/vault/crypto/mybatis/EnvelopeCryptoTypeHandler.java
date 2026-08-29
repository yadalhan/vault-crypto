package com.xaan.vault.crypto.mybatis;

import com.xaan.vault.crypto.envelope.EnvelopeCryptoService;
import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;

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
 * <p><b>Only use this on a column that is always in this library's envelope format.</b>
 * A read that hits a row predating envelope encryption, or written by something else
 * entirely, throws {@code CryptoException} out of {@code getNullableResult(...)} -
 * which will surface on every query that touches the row, not just a deliberate
 * password-check call. For a column where legacy/foreign data might still be present,
 * keep decrypting explicitly and selectively via {@link EnvelopeCryptoService} in
 * application code instead of wiring this handler onto the read path (it's still fine
 * to use it write-side only, on just the {@code #{...}} parameter in `@Insert`/`@Update`,
 * leaving `@Select` queries returning the column as a plain, undecrypted `String`).
 */
public abstract class EnvelopeCryptoTypeHandler extends BaseTypeHandler<String> {

    private final EnvelopeCryptoService cryptoService;

    protected EnvelopeCryptoTypeHandler(EnvelopeCryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @Override
    public void setNonNullParameter(PreparedStatement ps, int i, String parameter, JdbcType jdbcType) throws SQLException {
        // Empty string is treated the same as null (encrypting "" would turn "no value" into
        // non-empty ciphertext, which breaks any `value != null && !value.isEmpty()`-style
        // check elsewhere in the application - e.g. "is this row password-protected at all").
        // BaseTypeHandler only special-cases true null before calling this method, so the
        // empty-string case has to be handled here to stay symmetric with getNullableResult().
        ps.setString(i, parameter.isEmpty() ? parameter : cryptoService.encrypt(parameter));
    }

    @Override
    public String getNullableResult(ResultSet rs, String columnName) throws SQLException {
        return decryptIfPresent(rs.getString(columnName));
    }

    @Override
    public String getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
        return decryptIfPresent(rs.getString(columnIndex));
    }

    @Override
    public String getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
        return decryptIfPresent(cs.getString(columnIndex));
    }

    private String decryptIfPresent(String stored) {
        if (stored == null || stored.isEmpty()) {
            return stored;
        }
        return cryptoService.decrypt(stored);
    }
}
