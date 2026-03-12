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

    @AssertTrue(message = "Exactly one of `kerberos.client.keytab` or `kerberos.client.credential-cache.location` must be specified")
    public boolean isAuthSourceValid()
    {
        return getClientKeytab().isPresent() ^ getClientCredentialCacheLocation().isPresent();
    }
}
