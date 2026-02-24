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

import jakarta.validation.constraints.AssertTrue;
import org.junit.jupiter.api.Test;

import static io.airlift.configuration.testing.ConfigAssertions.assertRecordedDefaults;
import static io.airlift.configuration.testing.ConfigAssertions.recordDefaults;
import static io.airlift.testing.ValidationAssertions.assertFailsValidation;
import static org.assertj.core.api.Assertions.assertThat;

public class TestKerberosConfig
{
    @Test
    public void testDefaults()
    {
        assertRecordedDefaults(recordDefaults(KerberosConfig.class)
                .setClientPrincipal(null)
                .setClientKeytab(null)
                .setClientCredentialCacheLocation(null));
    }

    @Test
    public void testValidationFailsWhenNeitherAuthSourceSet()
    {
        assertFailsValidation(
                new KerberosConfig()
                        .setClientPrincipal("test@REALM.COM"),
                "authSourceValid",
                "Exactly one of `kerberos.client.keytab` or `kerberos.client.credential-cache.location` must be specified",
                AssertTrue.class);
    }

    @Test
    public void testValidationFailsWhenBothAuthSourcesSet()
    {
        assertFailsValidation(
                new KerberosConfig()
                        .setClientPrincipal("test@REALM.COM")
                        .setClientKeytab("/etc/security/keytabs/trino.keytab")
                        .setClientCredentialCacheLocation("/tmp/krb5cc_1000"),
                "authSourceValid",
                "Exactly one of `kerberos.client.keytab` or `kerberos.client.credential-cache.location` must be specified",
                AssertTrue.class);
    }

    @Test
    public void testValidKeytabConfig()
    {
        KerberosConfig config = new KerberosConfig()
                .setClientPrincipal("trino/host@REALM.COM")
                .setClientKeytab("/etc/security/keytabs/trino.keytab");

        assertThat(config.getClientPrincipal()).isEqualTo("trino/host@REALM.COM");
        assertThat(config.getClientKeytab()).contains("/etc/security/keytabs/trino.keytab");
        assertThat(config.getClientCredentialCacheLocation()).isEmpty();
        assertThat(config.isAuthSourceValid()).isTrue();
    }

    @Test
    public void testValidCredentialCacheConfig()
    {
        KerberosConfig config = new KerberosConfig()
                .setClientPrincipal("trino@REALM.COM")
                .setClientCredentialCacheLocation("/tmp/krb5cc_1000");

        assertThat(config.getClientPrincipal()).isEqualTo("trino@REALM.COM");
        assertThat(config.getClientKeytab()).isEmpty();
        assertThat(config.getClientCredentialCacheLocation()).contains("/tmp/krb5cc_1000");
        assertThat(config.isAuthSourceValid()).isTrue();
    }
}
