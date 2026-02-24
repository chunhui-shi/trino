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

public enum OracleAuthenticationType
{
    /**
     * Standard username/password authentication via the configured
     * {@code connection-user} and {@code connection-password} (or other
     * credential provider types).
     */
    PASSWORD,

    /**
     * Kerberos authentication using a service keytab or credential cache.
     * Requires {@code kerberos.client.principal} and exactly one of
     * {@code kerberos.client.keytab} or
     * {@code kerberos.client.credential-cache.location}.
     * Connection pooling must be disabled ({@code oracle.connection-pool.enabled=false}).
     */
    KERBEROS,
}
