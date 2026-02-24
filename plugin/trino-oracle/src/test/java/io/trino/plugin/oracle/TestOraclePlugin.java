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

import com.google.common.collect.ImmutableMap;
import io.trino.spi.Plugin;
import io.trino.spi.connector.ConnectorFactory;
import io.trino.testing.TestingConnectorContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.google.common.collect.Iterables.getOnlyElement;

public class TestOraclePlugin
{
    @Test
    public void testCreateConnector()
    {
        Plugin plugin = new OraclePlugin();
        ConnectorFactory factory = getOnlyElement(plugin.getConnectorFactories());
        factory.create(
                "test",
                ImmutableMap.of(
                        "connection-url", "jdbc:oracle:thin//test",
                        "bootstrap.quiet", "true"),
                new TestingConnectorContext()).shutdown();
    }

    @Test
    public void testCreateConnectorWithKerberosKeytab(@TempDir Path tempDir)
            throws IOException
    {
        // The keytab file must exist for KerberosConfiguration.Builder.verifyFile() check,
        // but need not be a real keytab — actual Kerberos login is lazy (on first openConnection).
        Path keytab = Files.createFile(tempDir.resolve("test.keytab"));

        Plugin plugin = new OraclePlugin();
        ConnectorFactory factory = getOnlyElement(plugin.getConnectorFactories());
        factory.create(
                "test",
                ImmutableMap.<String, String>builder()
                        .put("connection-url", "jdbc:oracle:thin//test")
                        .put("oracle.authentication.type", "KERBEROS")
                        .put("oracle.connection-pool.enabled", "false")
                        .put("kerberos.client.principal", "trino@EXAMPLE.COM")
                        .put("kerberos.client.keytab", keytab.toAbsolutePath().toString())
                        .put("bootstrap.quiet", "true")
                        .buildOrThrow(),
                new TestingConnectorContext()).shutdown();
    }

    @Test
    public void testCreateConnectorWithKerberosCredentialCache(@TempDir Path tempDir)
            throws IOException
    {
        Path credentialCache = Files.createFile(tempDir.resolve("krb5cc_test"));

        Plugin plugin = new OraclePlugin();
        ConnectorFactory factory = getOnlyElement(plugin.getConnectorFactories());
        factory.create(
                "test",
                ImmutableMap.<String, String>builder()
                        .put("connection-url", "jdbc:oracle:thin//test")
                        .put("oracle.authentication.type", "KERBEROS")
                        .put("oracle.connection-pool.enabled", "false")
                        .put("kerberos.client.principal", "trino@EXAMPLE.COM")
                        .put("kerberos.client.credential-cache.location", credentialCache.toAbsolutePath().toString())
                        .put("bootstrap.quiet", "true")
                        .buildOrThrow(),
                new TestingConnectorContext()).shutdown();
    }

    @Test
    public void testKerberosWithPoolingEnabledFailsBinding(@TempDir Path tempDir)
            throws IOException
    {
        Path keytab = Files.createFile(tempDir.resolve("test.keytab"));

        Plugin plugin = new OraclePlugin();
        ConnectorFactory factory = getOnlyElement(plugin.getConnectorFactories());
        try {
            factory.create(
                    "test",
                    ImmutableMap.<String, String>builder()
                            .put("connection-url", "jdbc:oracle:thin//test")
                            .put("oracle.authentication.type", "KERBEROS")
                            .put("oracle.connection-pool.enabled", "true")
                            .put("kerberos.client.principal", "trino@EXAMPLE.COM")
                            .put("kerberos.client.keytab", keytab.toAbsolutePath().toString())
                            .put("bootstrap.quiet", "true")
                            .buildOrThrow(),
                    new TestingConnectorContext());
            throw new AssertionError("Expected connector creation to fail when Kerberos is used with connection pooling enabled");
        }
        catch (Exception e) {
            org.assertj.core.api.Assertions.assertThat(e)
                    .hasMessageContaining("Kerberos authentication does not support connection pooling");
        }
    }
}
