/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.oracle;

import com.google.common.collect.Iterables;
import io.trino.plugin.base.authentication.CachingKerberosAuthentication;
import io.trino.plugin.jdbc.ConnectionFactory;
import io.trino.plugin.jdbc.JdbcErrorCode;
import io.trino.spi.TrinoException;
import io.trino.spi.connector.ConnectorSession;
import oracle.jdbc.datasource.impl.OracleDataSource;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import javax.security.auth.Subject;

import java.security.Principal;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

import static com.google.common.base.Preconditions.checkState;
import static java.util.Objects.requireNonNull;

/**
 * Oracle-specific {@link ConnectionFactory} for Kerberos authentication.
 *
 * <p>Unlike the generic {@link io.trino.plugin.jdbc.kerberos.KerberosConnectionFactory},
 * this implementation explicitly extracts a {@link GSSCredential} from the Kerberos
 * {@link Subject} and passes it to Oracle's connection builder via
 * {@code OracleConnectionBuilder.gssCredential()}. This is required because Oracle's
 * JDBC driver does not automatically pick up credentials from the active Subject when
 * using standard {@code driver.connect(url, properties)}.
 *
 * <p>Connection pooling is not supported with this factory. Use it with
 * {@code oracle.connection-pool.enabled=false}.
 *
 * <p>Note: OpenTelemetry tracing is not applied to connections created by this factory.
 * This can be added in a future improvement.
 */
public class OracleKerberosConnectionFactory
        implements ConnectionFactory
{
    // Standard Kerberos OID: 1.2.840.113554.1.2.2
    private static final Oid KERBEROS_OID;
    // SPNEGO OID: 1.3.6.1.5.5.2
    private static final Oid SPNEGO_OID;

    static {
        try {
            KERBEROS_OID = new Oid("1.2.840.113554.1.2.2");
            SPNEGO_OID = new Oid("1.3.6.1.5.5.2");
        }
        catch (GSSException e) {
            throw new RuntimeException("Failed to initialize Kerberos OIDs", e);
        }
    }

    private final CachingKerberosAuthentication kerberosAuthentication;
    private final OracleDataSource dataSource;
    private final String connectionUrl;

    public OracleKerberosConnectionFactory(
            CachingKerberosAuthentication kerberosAuthentication,
            String connectionUrl,
            Properties connectionProperties)
            throws SQLException
    {
        this.kerberosAuthentication = requireNonNull(kerberosAuthentication, "kerberosAuthentication is null");
        this.connectionUrl = requireNonNull(connectionUrl, "connectionUrl is null");

        this.dataSource = new OracleDataSource();
        this.dataSource.setURL(connectionUrl);
        this.dataSource.setConnectionProperties(requireNonNull(connectionProperties, "connectionProperties is null"));
    }

    @Override
    public Connection openConnection(ConnectorSession session)
            throws SQLException
    {
        Subject subject = kerberosAuthentication.getSubject();
        try {
            return Subject.callAs(subject, () -> {
                GSSCredential gssCredential = getGssCredentialFromSubject(subject);
                Connection connection = dataSource.createConnectionBuilder()
                        .gssCredential(gssCredential)
                        .build();
                checkState(connection != null, "Oracle driver returned null connection for URL: %s", connectionUrl);
                return connection;
            });
        }
        catch (Exception e) {
            // Subject.callAs() declares `throws Exception`, so we must catch Exception
            // and re-throw the specific exception types if that is what was thrown.
            if (e instanceof SQLException sqlException) {
                throw sqlException;
            }
            if (e instanceof TrinoException trinoException) {
                throw trinoException;
            }
            throw new RuntimeException("Failed to open Oracle Kerberos connection", e);
        }
    }

    /**
     * Extracts a {@link GSSCredential} from the principals and private credentials
     * in the given Kerberos {@link Subject}.
     *
     * <p>Must be called from within a {@link Subject#callAs} context so that
     * {@link Subject#current()} returns the subject and the JGSS provider can
     * access the Kerberos service tickets stored in its private credentials.
     */
    private static GSSCredential getGssCredentialFromSubject(Subject subject)
    {
        try {
            return Subject.callAs(subject, () -> {
                try {
                    GSSManager gssManager = GSSManager.getInstance();
                    Principal clientPrincipal = Iterables.getOnlyElement(subject.getPrincipals());
                    GSSName gssName = gssManager.createName(clientPrincipal.getName(), GSSName.NT_USER_NAME);
                    return gssManager.createCredential(
                            gssName,
                            Integer.MAX_VALUE,
                            new Oid[] {KERBEROS_OID, SPNEGO_OID},
                            GSSCredential.INITIATE_ONLY);
                }
                catch (GSSException e) {
                    throw new TrinoException(JdbcErrorCode.JDBC_ERROR, "Failed to create GSS credential from Kerberos subject", e);
                }
            });
        }
        catch (TrinoException e) {
            throw e;
        }
        catch (Exception e) {
            throw new TrinoException(JdbcErrorCode.JDBC_ERROR, "Unexpected error extracting GSS credential", e);
        }
    }
}
