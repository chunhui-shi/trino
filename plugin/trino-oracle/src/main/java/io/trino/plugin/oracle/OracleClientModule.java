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

import com.google.common.base.Throwables;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.inject.Binder;
import com.google.inject.Key;
import com.google.inject.Module;
import com.google.inject.Provides;
import com.google.inject.Scopes;
import com.google.inject.Singleton;
import io.airlift.configuration.AbstractConfigurationAwareModule;
import io.opentelemetry.api.OpenTelemetry;
import io.trino.plugin.base.authentication.CachingKerberosAuthentication;
import io.trino.plugin.jdbc.BaseJdbcConfig;
import io.trino.plugin.jdbc.ConnectionFactory;
import io.trino.plugin.jdbc.DriverConnectionFactory;
import io.trino.plugin.jdbc.ForBaseJdbc;
import io.trino.plugin.jdbc.ForJdbcClient;
import io.trino.plugin.jdbc.JdbcClient;
import io.trino.plugin.jdbc.JdbcMetadataConfig;
import io.trino.plugin.jdbc.MaxDomainCompactionThreshold;
import io.trino.plugin.jdbc.RetryStrategy;
import io.trino.plugin.jdbc.TimestampTimeZoneDomain;
import io.trino.plugin.jdbc.credential.CredentialProvider;
import io.trino.plugin.jdbc.kerberos.KerberosAuthenticationModule;
import io.trino.plugin.jdbc.ptf.Query;
import io.trino.spi.function.table.ConnectorTableFunction;
import oracle.jdbc.OracleConnection;
import oracle.jdbc.OracleDriver;

import java.sql.SQLException;
import java.sql.SQLRecoverableException;
import java.util.Properties;
import java.util.concurrent.ExecutorService;

import static com.google.inject.multibindings.Multibinder.newSetBinder;
import static com.google.inject.multibindings.OptionalBinder.newOptionalBinder;
import static io.airlift.configuration.ConfigBinder.configBinder;
import static io.trino.plugin.jdbc.JdbcModule.bindSessionPropertiesProvider;
import static io.trino.plugin.oracle.OracleClient.ORACLE_MAX_LIST_EXPRESSIONS;

public class OracleClientModule
        extends AbstractConfigurationAwareModule
{
    @Override
    protected void setup(Binder binder)
    {
        binder.bind(JdbcClient.class).annotatedWith(ForBaseJdbc.class).to(OracleClient.class).in(Scopes.SINGLETON);
        newOptionalBinder(binder, TimestampTimeZoneDomain.class).setBinding().toInstance(TimestampTimeZoneDomain.ANY);
        bindSessionPropertiesProvider(binder, OracleSessionProperties.class);
        configBinder(binder).bindConfig(OracleConfig.class);
        newOptionalBinder(binder, Key.get(int.class, MaxDomainCompactionThreshold.class)).setBinding().toInstance(ORACLE_MAX_LIST_EXPRESSIONS);
        configBinder(binder).bindConfigDefaults(JdbcMetadataConfig.class, config -> config.setBulkListColumns(true));
        newSetBinder(binder, ConnectorTableFunction.class).addBinding().toProvider(Query.class).in(Scopes.SINGLETON);
        newSetBinder(binder, RetryStrategy.class).addBinding().to(OracleRetryStrategy.class).in(Scopes.SINGLETON);
        newOptionalBinder(binder, Key.get(ExecutorService.class, ForJdbcClient.class))
                .setBinding()
                .toInstance(MoreExecutors.newDirectExecutorService());

        OracleConfig oracleConfig = buildConfigObject(OracleConfig.class);
        switch (oracleConfig.getAuthenticationType()) {
            case PASSWORD -> install(new OraclePasswordModule());
            case KERBEROS -> {
                if (oracleConfig.isConnectionPoolEnabled()) {
                    binder.addError(
                            "Kerberos authentication does not support connection pooling. " +
                            "Set oracle.connection-pool.enabled=false.");
                }
                // KerberosAuthenticationModule is installed here (not from a child module)
                // because AbstractConfigurationAwareModule.setup() forbids binder.install().
                // Use this.install() to bypass the ForbidInstallBinder restriction.
                install(new KerberosAuthenticationModule());
                install(new OracleKerberosModule());
            }
        }
    }

    /**
     * Handles standard username/password authentication. Preserves the original
     * connection factory behavior including optional Oracle UCP connection pooling.
     */
    private static class OraclePasswordModule
            implements Module
    {
        @Override
        public void configure(Binder binder) {}

        @Provides
        @Singleton
        @ForBaseJdbc
        public static ConnectionFactory connectionFactory(
                BaseJdbcConfig config,
                CredentialProvider credentialProvider,
                OracleConfig oracleConfig,
                OpenTelemetry openTelemetry)
                throws SQLException
        {
            Properties connectionProperties = buildBaseConnectionProperties(oracleConfig);

            if (oracleConfig.isConnectionPoolEnabled()) {
                return new OraclePoolConnectionFactory(
                        config.getConnectionUrl(),
                        connectionProperties,
                        credentialProvider,
                        oracleConfig.getConnectionPoolMinSize(),
                        oracleConfig.getConnectionPoolMaxSize(),
                        oracleConfig.getInactiveConnectionTimeout(),
                        openTelemetry);
            }

            return DriverConnectionFactory.builder(new OracleDriver(), config.getConnectionUrl(), credentialProvider)
                    .setConnectionProperties(connectionProperties)
                    .setOpenTelemetry(openTelemetry)
                    .build();
        }
    }

    /**
     * Provides the Oracle Kerberos {@link ConnectionFactory}. The companion
     * {@link KerberosAuthenticationModule} (which supplies the injected
     * {@link CachingKerberosAuthentication}) is installed by the parent
     * {@link OracleClientModule#setup} so that it participates in airlift's
     * configuration tracking correctly.
     */
    private static class OracleKerberosModule
            implements Module
    {
        @Override
        public void configure(Binder binder) {}

        @Provides
        @Singleton
        @ForBaseJdbc
        public static ConnectionFactory connectionFactory(
                BaseJdbcConfig config,
                OracleConfig oracleConfig,
                CachingKerberosAuthentication kerberosAuthentication)
                throws SQLException
        {
            Properties connectionProperties = buildBaseConnectionProperties(oracleConfig);
            connectionProperties.setProperty("oracle.net.authentication_services", "(KERBEROS5)");

            return new OracleKerberosConnectionFactory(
                    kerberosAuthentication,
                    config.getConnectionUrl(),
                    connectionProperties);
        }
    }

    /**
     * Builds the Oracle connection properties common to all authentication types:
     * synonym visibility and remarks reporting.
     */
    private static Properties buildBaseConnectionProperties(OracleConfig oracleConfig)
    {
        Properties properties = new Properties();
        properties.setProperty(OracleConnection.CONNECTION_PROPERTY_INCLUDE_SYNONYMS, String.valueOf(oracleConfig.isSynonymsEnabled()));
        properties.setProperty(OracleConnection.CONNECTION_PROPERTY_REPORT_REMARKS, String.valueOf(oracleConfig.isRemarksReportingEnabled()));
        return properties;
    }

    private static class OracleRetryStrategy
            implements RetryStrategy
    {
        @Override
        public boolean isExceptionRecoverable(Throwable exception)
        {
            return Throwables.getCausalChain(exception).stream()
                    .anyMatch(SQLRecoverableException.class::isInstance);
        }
    }
}
