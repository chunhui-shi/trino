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
import io.trino.plugin.base.authentication.KerberosAuthenticationProvider;
import io.trino.plugin.base.authentication.KerberosConfiguration;
import io.trino.plugin.base.authentication.KerbyKerberosAuthentication;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

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
 * <p>When {@code kerberos.client.keytab-base64} is present in the connector
 * properties, {@link KerbyKerberosAuthentication} is used: the keytab is
 * decoded from base64 and the KDC configuration is read from the
 * {@code kerberos.client.krb5-config} string, with no files on disk and no
 * JVM-global {@code java.security.krb5.conf} system property required.
 *
 * <p>Otherwise the standard JAAS {@link KerberosAuthentication} is used,
 * preserving backwards compatibility.
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
        KerberosAuthenticationProvider provider;
        if (config.getClientKeytabBase64().isPresent()) {
            // Kerby path: keytab is loaded from base64 in-memory; no keytab file on disk needed.
            // krb5-config-base64 is optional: when absent Kerby falls back to the file
            // referenced by the java.security.krb5.conf JVM system property.
            byte[] keytabBytes = Base64.getDecoder().decode(config.getClientKeytabBase64().get());
            String krb5Config = config.getClientKrb5ConfigBase64()
                    .map(b64 -> new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8))
                    .orElse(null);
            provider = new KerbyKerberosAuthentication(config.getClientPrincipal(), keytabBytes, krb5Config);
        }
        else {
            // Standard JAAS / Krb5LoginModule path — unchanged behaviour.
            KerberosConfiguration.Builder builder = new KerberosConfiguration.Builder()
                    .withKerberosPrincipal(config.getClientPrincipal());
            config.getClientKeytab().ifPresent(builder::withKeytabLocation);
            config.getClientCredentialCacheLocation().ifPresent(builder::withCredentialCacheLocation);
            provider = new KerberosAuthentication(builder.build());
        }
        return new CachingKerberosAuthentication(provider);
    }
}
