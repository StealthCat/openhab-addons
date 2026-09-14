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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.openhab.binding.tplinksmarthome.internal.TPLinkModernDiscovery.ModernDiscoveryResult;

public class TPLinkModernDiscoveryTest {

    @Test
    public void testParseIotKlapV2Discovery() {
        String json = """
                {"error_code":0,"result":{"device_id":"0123456789abcdef","device_model":"EP10(US)",
                "device_type":"IOT.SMARTPLUGSWITCH","hw_ver":"2.0","mac":"AA-BB-CC-DD-EE-FF",
                "mgt_encrypt_schm":{"encrypt_type":"KLAP","http_port":80,"lv":2,"is_support_https":false}}}
                """;
        ModernDiscoveryResult result = parse(json);
        assertEquals("EP10(US)", result.model());
        assertEquals("IOT.SMARTPLUGSWITCH", result.deviceType());
        assertEquals("KLAP_V2", result.protocol());
        assertEquals(80, result.httpPort());
        assertTrue(result.isSupportedIotDevice());
    }

    @Test
    public void testEncryptionMetadataFallbacks() {
        String json = """
                {"error_code":0,"result":{"device_id":"1","device_model":"EP10(US)",
                "device_type":"IOT.SMARTPLUGSWITCH","encrypt_type":["1","2"],
                "mgt_encrypt_schm":{"http_port":80,"is_support_https":false},
                "encrypt_info":{"sym_schm":"KLAP","key":"","data":""}}}
                """;
        ModernDiscoveryResult result = parse(json);
        assertEquals("KLAP", result.encryptType());
        assertEquals(2, result.loginVersion());
        assertEquals("KLAP_V2", result.protocol());
        assertTrue(result.isSupportedIotDevice());
    }

    @Test
    public void testSmartFamilyIsNotClaimedByKasaBinding() {
        String json = """
                {"error_code":0,"result":{"device_id":"1","device_model":"P100","device_type":"SMART.TAPOPLUG",
                "mgt_encrypt_schm":{"encrypt_type":"KLAP","http_port":80,"lv":2}}}
                """;
        ModernDiscoveryResult result = parse(json);
        assertFalse(result.isSupportedIotDevice());
    }

    private static ModernDiscoveryResult parse(String json) {
        byte[] jsonBytes = json.getBytes(StandardCharsets.UTF_8);
        byte[] packet = new byte[16 + jsonBytes.length];
        packet[0] = 2;
        System.arraycopy(jsonBytes, 0, packet, 16, jsonBytes.length);
        return TPLinkModernDiscovery.parse(packet, packet.length).orElseThrow();
    }
}
