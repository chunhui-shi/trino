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

import jakarta.annotation.Nullable;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Collections;
import java.util.Date;

import static java.util.Objects.requireNonNull;

/**
 * A {@link KerberosAuthenticationProvider} that uses
 * <a href="https://directory.apache.org/kerby/">Apache Kerby</a> to perform
 * the Kerberos AS exchange entirely in memory.
 *
 * <p>Unlike {@link KerberosAuthentication}, this implementation:
 * <ul>
 *   <li>Accepts the keytab as raw bytes (e.g. decoded from a base64 string
 *       stored in a secrets manager), requiring no keytab file on disk.</li>
 *   <li>Accepts the Kerberos configuration (krb5.conf content) as a
 *       {@link String}, requiring no krb5.conf file on disk.</li>
 *   <li>Does <em>not</em> read or set the JVM-global
 *       {@code java.security.krb5.conf} system property, allowing different
 *       connectors within the same Trino process to use independent Kerberos
 *       realms and KDC addresses.</li>
 * </ul>
 *
 * <p>The resulting {@link Subject} contains a
 * {@link KerberosTicket} TGT in its private credentials, compatible with
 * the standard JGSS API used by {@code OracleKerberosConnectionFactory} and
 * {@code KerberosConnectionFactory}.
 */
public class KerbyKerberosAuthentication
        implements KerberosAuthenticationProvider
{
    private final String principal;
    private final byte[] keytabBytes;
    private final KrbClient krbClient;

    /**
     * Create a new instance.
     *
     * @param principal      the Kerberos client principal, e.g. {@code user@REALM}
     * @param keytabBytes    raw keytab bytes (not base64; decode before passing)
     * @param krb5Config     the full content of a krb5.conf file as a string, or
     *                       {@code null} to fall back to the file referenced by the
     *                       {@code java.security.krb5.conf} JVM system property
     */
    public KerbyKerberosAuthentication(String principal, byte[] keytabBytes, @Nullable String krb5Config)
    {
        this.principal = requireNonNull(principal, "principal is null");
        this.keytabBytes = requireNonNull(keytabBytes, "keytabBytes is null").clone();
        this.krbClient = buildKrbClient(krb5Config);
    }

    @Override
    public Subject getSubject()
    {
        try {
            TgtTicket tgt = requestTgt();
            KerberosTicket ticket = toKerberosTicket(tgt);
            Subject subject = new Subject(
                    false,
                    Collections.singleton(new KerberosPrincipal(principal)),
                    Collections.emptySet(),
                    Collections.emptySet());
            subject.getPrivateCredentials().add(ticket);
            return subject;
        }
        catch (KrbException | IOException e) {
            throw new RuntimeException("Failed to obtain Kerberos TGT for principal: " + principal, e);
        }
    }

    @Override
    public void attemptLogin(Subject subject)
    {
        try {
            KerberosTicket ticket = toKerberosTicket(requestTgt());
            synchronized (subject.getPrivateCredentials()) {
                subject.getPrivateCredentials().clear();
                subject.getPrivateCredentials().add(ticket);
            }
        }
        catch (KrbException | IOException e) {
            throw new RuntimeException("Failed to refresh Kerberos TGT for principal: " + principal, e);
        }
    }

    private TgtTicket requestTgt()
            throws KrbException, IOException
    {
        Keytab keytab = Keytab.loadKeytab(new ByteArrayInputStream(keytabBytes));
        return krbClient.requestTgt(principal, keytab);
    }

    /**
     * Convert a Kerby {@link TgtTicket} to a JDK {@link KerberosTicket} that
     * can be placed into a {@link Subject}'s private credentials and consumed
     * by the standard JGSS API.
     *
     * @param tgt the TGT returned by Kerby's AS exchange
     * @return an equivalent JDK {@link KerberosTicket}
     * @throws IOException if the ticket's ASN.1 encoding fails
     */
    private static KerberosTicket toKerberosTicket(TgtTicket tgt)
            throws IOException
    {
        EncKdcRepPart enc = tgt.getEncKdcRepPart();

        Date startTime = (enc.getStartTime() != null)
                ? enc.getStartTime().getValue()
                : enc.getAuthTime().getValue();

        Date renewTill = (enc.getRenewTill() != null)
                ? enc.getRenewTill().getValue()
                : null;

        return new KerberosTicket(
                tgt.getTicket().encode(),
                new KerberosPrincipal(tgt.getClientPrincipal().getName()),
                new KerberosPrincipal(enc.getSname().getName()),
                enc.getKey().getKeyData(),
                enc.getKey().getKeyType().getValue(),
                toFlags(enc),
                enc.getAuthTime().getValue(),
                startTime,
                enc.getEndTime().getValue(),
                renewTill,
                toInetAddresses(enc));
    }

    /**
     * Convert the Kerby ticket-flags int to the 32-element boolean array
     * expected by the JDK {@link KerberosTicket} constructor, where index
     * {@code i} corresponds to bit {@code i} of the RFC 4120 BIT STRING
     * (bit 0 = MSB = RESERVED, bit 1 = FORWARDABLE, etc.).
     */
    private static boolean[] toFlags(EncKdcRepPart enc)
    {
        boolean[] flags = new boolean[32];
        int bits = enc.getFlags().getFlags();
        for (int i = 0; i < 32; i++) {
            flags[i] = ((bits >>> i) & 1) == 1;
        }
        return flags;
    }

    /**
     * Convert Kerby {@code HostAddresses} to a JDK {@link InetAddress} array,
     * returning {@code null} when no address restriction is present (the common
     * case for service-account keytabs).
     */
    private static InetAddress[] toInetAddresses(EncKdcRepPart enc)
    {
        if (enc.getCaddr() == null
                || enc.getCaddr().getElements() == null
                || enc.getCaddr().getElements().isEmpty()) {
            return null;
        }
        return enc.getCaddr().getElements().stream()
                .map(ha -> {
                    try {
                        return InetAddress.getByAddress(ha.getAddress());
                    }
                    catch (Exception ignored) {
                        return null;
                    }
                })
                .filter(addr -> addr != null)
                .toArray(InetAddress[]::new);
    }

    private static KrbClient buildKrbClient(@Nullable String krb5Config)
    {
        try {
            KrbConfig krbConfig = new KrbConfig();
            if (krb5Config != null) {
                krbConfig.addKrb5Config(krb5Config);
            }
            else {
                String sysKrb5 = System.getProperty("java.security.krb5.conf");
                if (sysKrb5 != null) {
                    krbConfig.addKrb5Config(new File(sysKrb5));
                }
                // else: Kerby uses its built-in defaults (tries /etc/krb5.conf etc.)
            }
            KrbClient client = new KrbClient(krbConfig);
            client.init();
            return client;
        }
        catch (IOException | KrbException e) {
            throw new RuntimeException("Failed to initialize Kerby KrbClient from krb5 config", e);
        }
    }
}
