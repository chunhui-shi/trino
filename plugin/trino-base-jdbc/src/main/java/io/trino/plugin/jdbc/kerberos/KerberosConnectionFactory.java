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
package io.trino.plugin.jdbc.kerberos;

import io.trino.plugin.base.authentication.CachingKerberosAuthentication;
import io.trino.plugin.jdbc.ConnectionFactory;
import io.trino.spi.connector.ConnectorSession;

import javax.security.auth.Subject;

import java.sql.Connection;
import java.sql.SQLException;

import static java.util.Objects.requireNonNull;

/**
 * A generic {@link ConnectionFactory} decorator that runs the delegate's
 * {@link #openConnection} call within a Kerberos {@link Subject} context
 * established by {@link Subject#callAs}.
 *
 * <p>This works for JDBC drivers that are JGSS-aware and pick up the active
 * Subject automatically (e.g. PostgreSQL with {@code gssEncMode}). For Oracle,
 * use a connector-specific factory that explicitly extracts and passes a
 * {@code GSSCredential} to the Oracle connection builder, because Oracle's
 * driver requires it to be provided explicitly.
 */
public class KerberosConnectionFactory
        implements ConnectionFactory
{
    private final ConnectionFactory delegate;
    private final CachingKerberosAuthentication kerberosAuthentication;

    public KerberosConnectionFactory(ConnectionFactory delegate, CachingKerberosAuthentication kerberosAuthentication)
    {
        this.delegate = requireNonNull(delegate, "delegate is null");
        this.kerberosAuthentication = requireNonNull(kerberosAuthentication, "kerberosAuthentication is null");
    }

    @Override
    public Connection openConnection(ConnectorSession session)
            throws SQLException
    {
        try {
            return Subject.callAs(
                    kerberosAuthentication.getSubject(),
                    () -> delegate.openConnection(session));
        }
        catch (Exception e) {
            // Subject.callAs() declares `throws Exception`, so we must catch Exception
            // and re-throw the original SQLException if that is what the delegate threw.
            if (e instanceof SQLException sqlException) {
                throw sqlException;
            }
            throw new RuntimeException("Failed to open Kerberos connection", e);
        }
    }

    @Override
    public void close()
            throws SQLException
    {
        delegate.close();
    }
}
