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
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;

/** HTTP/KLAP transport used by authenticated Kasa firmware. */
@NonNullByDefault
final class KlapTransport {
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(3);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final long DEFAULT_SESSION_TIMEOUT_SECONDS = 86400;
    private static final String DEFAULT_KASA_USERNAME = "kasa@tp-link.net";
    private static final String DEFAULT_KASA_PASSWORD = "kasaSetup";

    private final HttpClient httpClient;
    private final SecureRandom random = new SecureRandom();
    private final String username;
    private final String password;
    private final int configuredVersion;
    private final int port;

    private String host;
    private String sessionCookie = "";
    private long expiresAtMillis;
    private int activeVersion;
    private @Nullable KlapCipher cipher;

    KlapTransport(String host, int port, String username, String password, int configuredVersion) {
        this.host = host;
        this.port = port > 0 ? port : 80;
        this.username = username;
        this.password = password;
        this.configuredVersion = configuredVersion;
        httpClient = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
    }

    synchronized void setHost(String host) {
        if (!this.host.equals(host)) {
            this.host = host;
            reset();
        }
    }

    synchronized String sendCommand(String command) throws IOException {
        @Nullable IOException last = null;
        for (int attempt = 0; attempt < 2; attempt++) {
            ensureSession();
            @Nullable KlapCipher activeCipher = cipher;
            if (activeCipher == null) {
                throw new IOException("KLAP cipher is not initialized");
            }
            KlapCipher.EncryptedRequest encrypted = activeCipher.encrypt(command);
            HttpRequest request = HttpRequest.newBuilder(uri("/app/request?seq=" + encrypted.sequence()))
                    .timeout(REQUEST_TIMEOUT).header("Cookie", sessionCookie)
                    .header("Content-Type", "application/octet-stream")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(encrypted.payload())).build();
            try {
                HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
                if (response.statusCode() == 200) {
                    return activeCipher.decrypt(response.body(), encrypted.sequence());
                }
                if (response.statusCode() == 403) {
                    last = new IOException("KLAP session rejected by device (HTTP 403)");
                    reset();
                    continue;
                }
                throw new IOException("KLAP request failed with HTTP " + response.statusCode());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while communicating with KLAP device", e);
            }
        }
        throw last != null ? last : new IOException("KLAP request failed");
    }

    synchronized void reset() {
        sessionCookie = "";
        expiresAtMillis = 0;
        activeVersion = 0;
        cipher = null;
    }

    int getActiveVersion() {
        return activeVersion;
    }

    private void ensureSession() throws IOException {
        if (cipher == null || sessionCookie.isBlank() || System.currentTimeMillis() >= expiresAtMillis) {
            handshake();
        }
    }

    private void handshake() throws IOException {
        reset();
        byte[] localSeed = new byte[16];
        random.nextBytes(localSeed);

        HttpRequest request = HttpRequest.newBuilder(uri("/app/handshake1")).timeout(REQUEST_TIMEOUT)
                .header("Accept", "application/json").header("Content-Type", "application/octet-stream")
                .POST(HttpRequest.BodyPublishers.ofByteArray(localSeed)).build();
        final HttpResponse<byte[]> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted during KLAP handshake", e);
        }
        if (response.statusCode() != 200) {
            throw new IOException("KLAP handshake1 failed with HTTP " + response.statusCode());
        }
        if (response.body().length < 48) {
            throw new IOException("KLAP handshake1 returned an invalid response");
        }

        byte[] remoteSeed = Arrays.copyOfRange(response.body(), 0, 16);
        byte[] serverHash = Arrays.copyOfRange(response.body(), 16, 48);
        @Nullable Match match = matchCredentials(localSeed, remoteSeed, serverHash);
        if (match == null) {
            throw new IOException("KLAP authentication failed; check the TP-Link account credentials");
        }

        sessionCookie = extractSessionCookie(response);
        if (sessionCookie.isBlank()) {
            throw new IOException("KLAP handshake did not return TP_SESSIONID");
        }
        long timeoutSeconds = extractTimeout(response);
        long safetyBuffer = Math.min(1200, Math.max(10, timeoutSeconds / 10));
        expiresAtMillis = System.currentTimeMillis() + Math.max(30, timeoutSeconds - safetyBuffer) * 1000L;

        byte[] handshake2Payload;
        try {
            handshake2Payload = match.version == 2
                    ? KlapCipher.sha256(KlapCipher.concat(remoteSeed, localSeed, match.authHash))
                    : KlapCipher.sha256(KlapCipher.concat(remoteSeed, match.authHash));
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to create KLAP handshake2 payload", e);
        }

        HttpRequest handshake2 = HttpRequest.newBuilder(uri("/app/handshake2")).timeout(REQUEST_TIMEOUT)
                .header("Cookie", sessionCookie).header("Content-Type", "application/octet-stream")
                .POST(HttpRequest.BodyPublishers.ofByteArray(handshake2Payload)).build();
        try {
            HttpResponse<byte[]> response2 = httpClient.send(handshake2, HttpResponse.BodyHandlers.ofByteArray());
            if (response2.statusCode() != 200) {
                reset();
                throw new IOException("KLAP handshake2 failed with HTTP " + response2.statusCode());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted during KLAP handshake2", e);
        }

        cipher = new KlapCipher(localSeed, remoteSeed, match.authHash);
        activeVersion = match.version;
    }

    private @Nullable Match matchCredentials(byte[] localSeed, byte[] remoteSeed, byte[] serverHash) throws IOException {
        List<Credentials> candidates = credentialCandidates();
        int[] versions = configuredVersion == 1 ? new int[] { 1 }
                : configuredVersion == 2 ? new int[] { 2 } : new int[] { 2, 1 };
        try {
            for (int version : versions) {
                for (Credentials credentials : candidates) {
                    byte[] authHash = authHash(credentials, version);
                    byte[] expected = version == 2
                            ? KlapCipher.sha256(KlapCipher.concat(localSeed, remoteSeed, authHash))
                            : KlapCipher.sha256(KlapCipher.concat(localSeed, authHash));
                    if (java.security.MessageDigest.isEqual(expected, serverHash)) {
                        return new Match(version, authHash);
                    }
                }
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to calculate KLAP authentication hashes", e);
        }
        return null;
    }

    private List<Credentials> credentialCandidates() {
        Set<Credentials> set = new LinkedHashSet<>();
        set.add(new Credentials(username, password));
        set.add(new Credentials(DEFAULT_KASA_USERNAME, DEFAULT_KASA_PASSWORD));
        set.add(new Credentials("", ""));
        return new ArrayList<>(set);
    }

    static byte[] authHash(String username, String password, int version) throws GeneralSecurityException {
        return authHash(new Credentials(username, password), version);
    }

    private static byte[] authHash(Credentials credentials, int version) throws GeneralSecurityException {
        byte[] user = credentials.username.getBytes(StandardCharsets.UTF_8);
        byte[] pass = credentials.password.getBytes(StandardCharsets.UTF_8);
        if (version == 2) {
            return KlapCipher.sha256(KlapCipher.concat(KlapCipher.sha1(user), KlapCipher.sha1(pass)));
        }
        return KlapCipher.md5(KlapCipher.concat(KlapCipher.md5(user), KlapCipher.md5(pass)));
    }

    private String extractSessionCookie(HttpResponse<?> response) {
        for (String header : response.headers().allValues("set-cookie")) {
            for (String part : header.split(";")) {
                String value = part.trim();
                if (value.toUpperCase(Locale.ROOT).startsWith("TP_SESSIONID=")) {
                    return value;
                }
            }
        }
        return "";
    }

    private long extractTimeout(HttpResponse<?> response) {
        for (String header : response.headers().allValues("set-cookie")) {
            for (String part : header.split(";")) {
                String value = part.trim();
                if (value.toUpperCase(Locale.ROOT).startsWith("TIMEOUT=")) {
                    try {
                        return Long.parseLong(value.substring("TIMEOUT=".length()));
                    } catch (NumberFormatException e) {
                        return DEFAULT_SESSION_TIMEOUT_SECONDS;
                    }
                }
            }
        }
        return DEFAULT_SESSION_TIMEOUT_SECONDS;
    }

    private URI uri(String path) {
        String hostPart = host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
        return URI.create("http://" + hostPart + ":" + port + path);
    }

    private record Credentials(String username, String password) {
    }

    private record Match(int version, byte[] authHash) {
    }
}
