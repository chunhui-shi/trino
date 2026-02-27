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
package io.trino.plugin.postgresql;

import com.google.inject.Binder;
import com.google.inject.Provides;
import com.google.inject.Singleton;
import com.google.inject.multibindings.OptionalBinder;
import io.airlift.configuration.AbstractConfigurationAwareModule;
import io.opentelemetry.api.OpenTelemetry;
import io.trino.plugin.base.authentication.CachingKerberosAuthentication;
import io.trino.plugin.jdbc.BaseJdbcConfig;
import io.trino.plugin.jdbc.ConnectionFactory;
import io.trino.plugin.jdbc.DriverConnectionFactory;
import io.trino.plugin.jdbc.ForBaseJdbc;
import io.trino.plugin.jdbc.credential.CredentialProvider;
import io.trino.plugin.jdbc.kerberos.KerberosAuthenticationModule;
import io.trino.plugin.jdbc.kerberos.KerberosConnectionFactory;
import org.postgresql.Driver;

import java.util.Optional;
import java.util.Properties;

import static io.trino.plugin.jdbc.JdbcAuthenticationType.KERBEROS;
import static org.postgresql.PGProperty.REWRITE_BATCHED_INSERTS;

public class PostgreSqlConnectionFactoryModule
        extends AbstractConfigurationAwareModule
{
    @Override
    protected void setup(Binder binder)
    {
        // Declare the optional slot so Guice can inject Optional.empty() in PASSWORD mode.
        OptionalBinder.newOptionalBinder(binder, CachingKerberosAuthentication.class);
        if (buildConfigObject(PostgreSqlConfig.class).getAuthenticationType() == KERBEROS) {
            install(new KerberosAuthenticationModule());
        }
    }

    /**
     * Provides the {@link ConnectionFactory} for both PASSWORD and KERBEROS modes.
     *
     * <p>In KERBEROS mode {@link KerberosAuthenticationModule} binds a
     * {@link CachingKerberosAuthentication} and the factory is wrapped in
     * {@link KerberosConnectionFactory}.  {@code jaasLogin=false} prevents pgjdbc
     * from launching its own {@code LoginContext("pgjdbc")} — it uses the active
     * {@link javax.security.auth.Subject} established by {@link KerberosConnectionFactory}
     * instead.
     */
    @Provides
    @Singleton
    @ForBaseJdbc
    public ConnectionFactory connectionFactory(
            BaseJdbcConfig config,
            CredentialProvider credentialProvider,
            OpenTelemetry openTelemetry,
            Optional<CachingKerberosAuthentication> kerberos)
    {
        Properties connectionProperties = new Properties();
        connectionProperties.put(REWRITE_BATCHED_INSERTS.getName(), "true");
        if (kerberos.isPresent()) {
            // Prevent pgjdbc from creating its own LoginContext("pgjdbc").
            connectionProperties.put("jaasLogin", "false");
        }
        ConnectionFactory delegate = DriverConnectionFactory.builder(new Driver(), config.getConnectionUrl(), credentialProvider)
                .setConnectionProperties(connectionProperties)
                .setOpenTelemetry(openTelemetry)
                .build();
        return kerberos.<ConnectionFactory>map(k -> new KerberosConnectionFactory(delegate, k))
                .orElse(delegate);
    }
}
