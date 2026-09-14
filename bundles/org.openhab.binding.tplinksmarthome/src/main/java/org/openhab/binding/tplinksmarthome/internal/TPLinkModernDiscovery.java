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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.zip.CRC32;

import org.eclipse.jdt.annotation.NonNullByDefault;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/** Helpers for TP-Link's TDP v2 discovery on UDP/20002 and UDP/20004. */
@NonNullByDefault
final class TPLinkModernDiscovery {
    static final int DISCOVERY_PORT = 20002;
    static final int DISCOVERY_PORT_ALT = 20004;
    private static final int INITIAL_CRC = 0x5A6B7C8D;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Gson GSON = new Gson();

    private TPLinkModernDiscovery() {
    }

    static byte[] buildDiscoveryPacket() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            byte[] publicKey = generator.generateKeyPair().getPublic().getEncoded();
            String encoded = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(publicKey);
            String pem = "-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----\n";

            JsonObject params = new JsonObject();
            params.addProperty("rsa_key", pem);
            JsonObject root = new JsonObject();
            root.add("params", params);
            byte[] json = GSON.toJson(root).getBytes(StandardCharsets.UTF_8);

            ByteBuffer packet = ByteBuffer.allocate(16 + json.length).order(ByteOrder.BIG_ENDIAN);
            packet.put((byte) 2);
            packet.put((byte) 0);
            packet.putShort((short) 1);
            packet.putShort((short) json.length);
            packet.put((byte) 17);
            packet.put((byte) 0);
            packet.putInt(RANDOM.nextInt());
            packet.putInt(INITIAL_CRC);
            packet.put(json);

            byte[] result = packet.array();
            CRC32 crc = new CRC32();
            crc.update(result);
            ByteBuffer.wrap(result).order(ByteOrder.BIG_ENDIAN).putInt(12, (int) crc.getValue());
            return result;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to build TP-Link TDP discovery packet", e);
        }
    }

    static Optional<ModernDiscoveryResult> parse(byte[] data, int length) {
        if (length <= 16 || data[0] != 2) {
            return Optional.empty();
        }
        try {
            JsonObject root = JsonParser.parseString(new String(data, 16, length - 16, StandardCharsets.UTF_8))
                    .getAsJsonObject();
            JsonObject result = root.getAsJsonObject("result");
            if (result == null) {
                return Optional.empty();
            }
            JsonObject scheme = result.getAsJsonObject("mgt_encrypt_schm");
            String deviceType = string(result, "device_type");
            String model = string(result, "device_model");
            String deviceId = string(result, "device_id");
            String deviceName = string(result, "device_name");
            String mac = string(result, "mac");
            String hardwareVersion = string(result, "hw_ver");
            String encryptType = scheme == null ? "" : string(scheme, "encrypt_type");
            int httpPort = scheme == null ? 80 : integer(scheme, "http_port", 80);
            int loginVersion = scheme == null ? 0 : integer(scheme, "lv", 0);
            boolean https = scheme != null && bool(scheme, "is_support_https", false);
            return Optional.of(new ModernDiscoveryResult(deviceType, model, deviceId, deviceName, mac, hardwareVersion,
                    encryptType, httpPort, loginVersion, https));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    private static String string(JsonObject object, String name) {
        return object.has(name) && !object.get(name).isJsonNull() ? object.get(name).getAsString() : "";
    }

    private static int integer(JsonObject object, String name, int fallback) {
        try {
            return object.has(name) ? object.get(name).getAsInt() : fallback;
        } catch (RuntimeException e) {
            return fallback;
        }
    }

    private static boolean bool(JsonObject object, String name, boolean fallback) {
        try {
            return object.has(name) ? object.get(name).getAsBoolean() : fallback;
        } catch (RuntimeException e) {
            return fallback;
        }
    }

    record ModernDiscoveryResult(String deviceType, String model, String deviceId, String deviceName, String mac,
            String hardwareVersion, String encryptType, int httpPort, int loginVersion, boolean https) {
        boolean isSupportedIotDevice() {
            return deviceType.startsWith("IOT.") && (encryptType.equalsIgnoreCase("KLAP")
                    || encryptType.equalsIgnoreCase("XOR"));
        }

        String protocol() {
            if (encryptType.equalsIgnoreCase("XOR")) {
                return "XOR";
            }
            if (loginVersion >= 2) {
                return "KLAP_V2";
            }
            return "KLAP";
        }
    }
}
