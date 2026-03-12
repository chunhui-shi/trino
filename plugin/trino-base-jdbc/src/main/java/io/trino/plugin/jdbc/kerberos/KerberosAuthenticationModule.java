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

import com.google.inject.Binder;
import com.google.inject.Module;
import com.google.inject.Provides;
import com.google.inject.Singleton;
import io.trino.plugin.base.authentication.CachingKerberosAuthentication;
import io.trino.plugin.base.authentication.KerberosAuthentication;
import io.trino.plugin.base.authentication.KerberosConfiguration;

import static io.airlift.configuration.ConfigBinder.configBinder;

/**
 * Guice module that binds {@link KerberosConfig} and provides a
 * {@link CachingKerberosAuthentication} singleton built from that config.
 *
 * <p>Install this module from any JDBC connector module that needs Kerberos
 * authentication. The connector is then responsible for using the provided
 * {@link CachingKerberosAuthentication} to open connections (e.g. via
 * {@link KerberosConnectionFactory} for standard JGSS-aware drivers, or a
 * connector-specific factory for drivers like Oracle that need an explicit
 * {@code GSSCredential}).
 *
 * <p>Uses the standard JAAS {@link KerberosAuthentication} with
 * {@code Krb5LoginModule}, reading the keytab from a file path and
 * discovering the KDC via the JVM {@code java.security.krb5.conf} property.
 */
public class KerberosAuthenticationModule
        implements Module
{
    @Override
    public void configure(Binder binder)
    {
        configBinder(binder).bindConfig(KerberosConfig.class);
    }

    @Provides
    @Singleton
    public CachingKerberosAuthentication cachingKerberosAuthentication(KerberosConfig config)
    {
        KerberosConfiguration.Builder builder = new KerberosConfiguration.Builder()
                .withKerberosPrincipal(config.getClientPrincipal());
        config.getClientKeytab().ifPresent(builder::withKeytabLocation);
        config.getClientCredentialCacheLocation().ifPresent(builder::withCredentialCacheLocation);
        return new CachingKerberosAuthentication(new KerberosAuthentication(builder.build()));
    }
}
