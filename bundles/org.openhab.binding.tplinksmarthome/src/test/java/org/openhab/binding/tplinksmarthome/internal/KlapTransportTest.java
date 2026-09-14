/*
 * Copyright (c) 2010-2026 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.tplinksmarthome.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;

public class KlapTransportTest {

    @Test
    public void testAuthenticationHashVersions() throws Exception {
        assertEquals("60c1ac5df029534df37f3e036d148af4",
                HexFormat.of().formatHex(KlapTransport.authHash("user@example.com", "password", 1)));
        assertEquals("7c5a94e6c3a98773a333e7c5d2a4755842eec1fcb9ef6ea5d55d185aee69186c",
                HexFormat.of().formatHex(KlapTransport.authHash("user@example.com", "password", 2)));
    }

    @Test
    public void testCipherRoundTrip() throws Exception {
        byte[] local = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");
        byte[] remote = HexFormat.of().parseHex("101112131415161718191a1b1c1d1e1f");
        byte[] auth = KlapTransport.authHash("user@example.com", "password", 2);
        KlapCipher cipher = new KlapCipher(local, remote, auth);
        String json = "{\"system\":{\"get_sysinfo\":{}}}";
        KlapCipher.EncryptedRequest request = cipher.encrypt(json);
        assertEquals(json, cipher.decrypt(request.payload(), request.sequence()));
    }
}
