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

import io.airlift.configuration.Config;
import io.airlift.configuration.ConfigDescription;
import io.airlift.configuration.ConfigSecuritySensitive;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;

import java.util.Optional;

public class KerberosConfig
{
    @Nullable
    private String clientPrincipal;
    @Nullable
    private String clientKeytab;
    @Nullable
    private String clientCredentialCacheLocation;
    @Nullable
    private String clientKeytabBase64;
    @Nullable
    private String clientKrb5ConfigBase64;

    @NotNull
    public String getClientPrincipal()
    {
        return clientPrincipal;
    }

    @Config("kerberos.client.principal")
    @ConfigDescription("Kerberos client principal (e.g. primary/instance@REALM)")
    public KerberosConfig setClientPrincipal(String clientPrincipal)
    {
        this.clientPrincipal = clientPrincipal;
        return this;
    }

    public Optional<String> getClientKeytab()
    {
        return Optional.ofNullable(clientKeytab);
    }

    @Config("kerberos.client.keytab")
    @ConfigDescription("Path to the Kerberos client keytab file")
    public KerberosConfig setClientKeytab(String clientKeytab)
    {
        this.clientKeytab = clientKeytab;
        return this;
    }

    public Optional<String> getClientCredentialCacheLocation()
    {
        return Optional.ofNullable(clientCredentialCacheLocation);
    }

    @Config("kerberos.client.credential-cache.location")
    @ConfigDescription("Path to the Kerberos client credential cache file")
    public KerberosConfig setClientCredentialCacheLocation(String clientCredentialCacheLocation)
    {
        this.clientCredentialCacheLocation = clientCredentialCacheLocation;
        return this;
    }

    public Optional<String> getClientKeytabBase64()
    {
        return Optional.ofNullable(clientKeytabBase64);
    }

    @Config("kerberos.client.keytab-base64")
    @ConfigDescription("Base64-encoded Kerberos keytab content. Use ${ENV:VAR} to reference an " +
            "environment variable or a secrets-manager provider. When set, Apache Kerby is used " +
            "for authentication. Mutually exclusive with kerberos.client.keytab.")
    @ConfigSecuritySensitive
    public KerberosConfig setClientKeytabBase64(String clientKeytabBase64)
    {
        this.clientKeytabBase64 = clientKeytabBase64;
        return this;
    }

    public Optional<String> getClientKrb5ConfigBase64()
    {
        return Optional.ofNullable(clientKrb5ConfigBase64);
    }

    @Config("kerberos.client.krb5-config-base64")
    @ConfigDescription("Optional base64-encoded Kerberos configuration (krb5.conf) content for use " +
            "with kerberos.client.keytab-base64. When absent, Kerby reads the file referenced by " +
            "the java.security.krb5.conf JVM system property.")
    public KerberosConfig setClientKrb5ConfigBase64(String clientKrb5ConfigBase64)
    {
        this.clientKrb5ConfigBase64 = clientKrb5ConfigBase64;
        return this;
    }

    @AssertTrue(message = "Exactly one keytab source must be specified: " +
            "kerberos.client.keytab (file path), kerberos.client.keytab-base64 (in-memory), " +
            "or kerberos.client.credential-cache.location")
    public boolean isAuthSourceValid()
    {
        long keytabSources = countPresent(getClientKeytab(), getClientKeytabBase64(), getClientCredentialCacheLocation());
        return keytabSources == 1;
    }

    private static long countPresent(Optional<?>... optionals)
    {
        long count = 0;
        for (Optional<?> opt : optionals) {
            if (opt.isPresent()) {
                count++;
            }
        }
        return count;
    }
}
