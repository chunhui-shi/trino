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
package io.trino.plugin.base.authentication;

import javax.security.auth.Subject;

/**
 * Strategy interface for obtaining and refreshing a Kerberos {@link Subject}.
 *
 * <p>Implementations are responsible for performing the initial Kerberos login
 * and for re-authenticating when the TGT approaches expiry. Two implementations
 * are provided:
 * <ul>
 *   <li>{@link KerberosAuthentication} – uses the standard JAAS
 *       {@code Krb5LoginModule}, reading the keytab from a file path and
 *       discovering the KDC via the JVM-global
 *       {@code java.security.krb5.conf} system property.</li>
 *   <li>{@code KerbyKerberosAuthentication} – uses Apache Kerby to perform
 *       the AS exchange entirely in-memory, accepting the keytab as raw bytes
 *       and the KDC configuration as a string, without requiring any files on
 *       disk or the global JVM system property.</li>
 * </ul>
 *
 * <p>Implementations are wrapped by {@link CachingKerberosAuthentication},
 * which caches the subject and triggers renewal before the TGT expires.
 */
public interface KerberosAuthenticationProvider
{
    /**
     * Perform a fresh Kerberos login and return the resulting {@link Subject}.
     * The subject's private credentials must contain a TGT
     * ({@code javax.security.auth.kerberos.KerberosTicket} where
     * {@code server.getName()} matches {@code krbtgt/<REALM>@<REALM>}).
     *
     * @return a fully authenticated subject
     */
    Subject getSubject();

    /**
     * Re-authenticate into an existing {@link Subject}, replacing its private
     * credentials with freshly obtained ones. Called by
     * {@link CachingKerberosAuthentication} when the cached TGT approaches
     * its expiry time.
     *
     * @param subject the subject whose credentials should be refreshed
     */
    void attemptLogin(Subject subject);
}
