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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.jdt.annotation.NonNullByDefault;

/** Cipher state for TP-Link's KLAP local protocol. */
@NonNullByDefault
final class KlapCipher {
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    private final byte[] ivPrefix;
    private final byte[] key;
    private final byte[] signatureKey;
    private int sequence;

    KlapCipher(byte[] localSeed, byte[] remoteSeed, byte[] authHash) throws IOException {
        try {
            key = Arrays.copyOf(
                    sha256(concat("lsk".getBytes(StandardCharsets.US_ASCII), localSeed, remoteSeed, authHash)), 16);
            byte[] fullIv = sha256(
                    concat("iv".getBytes(StandardCharsets.US_ASCII), localSeed, remoteSeed, authHash));
            ivPrefix = Arrays.copyOf(fullIv, 12);
            sequence = ByteBuffer.wrap(fullIv, fullIv.length - 4, 4).order(ByteOrder.BIG_ENDIAN).getInt();
            signatureKey = Arrays.copyOf(
                    sha256(concat("ldk".getBytes(StandardCharsets.US_ASCII), localSeed, remoteSeed, authHash)), 28);
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to initialize KLAP cipher", e);
        }
    }

    synchronized EncryptedRequest encrypt(String request) throws IOException {
        sequence++;
        try {
            Cipher cipher = cipher(Cipher.ENCRYPT_MODE, sequence);
            byte[] ciphertext = cipher.doFinal(request.getBytes(StandardCharsets.UTF_8));
            byte[] signature = sha256(concat(signatureKey, intBytes(sequence), ciphertext));
            return new EncryptedRequest(concat(signature, ciphertext), sequence);
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to encrypt KLAP request", e);
        }
    }

    String decrypt(byte[] response, int requestSequence) throws IOException {
        if (response.length < 33) {
            throw new IOException("KLAP response is too short");
        }
        byte[] ciphertext = Arrays.copyOfRange(response, 32, response.length);
        try {
            Cipher cipher = cipher(Cipher.DECRYPT_MODE, requestSequence);
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to decrypt KLAP response", e);
        }
    }

    int getSequence() {
        return sequence;
    }

    private Cipher cipher(int mode, int seq) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(concat(ivPrefix, intBytes(seq))));
        return cipher;
    }

    static byte[] sha256(byte[] data) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    static byte[] sha1(byte[] data) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-1").digest(data);
    }

    static byte[] md5(byte[] data) throws GeneralSecurityException {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    static byte[] concat(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }

    static byte[] intBytes(int value) {
        return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(value).array();
    }

    record EncryptedRequest(byte[] payload, int sequence) {
    }
}
