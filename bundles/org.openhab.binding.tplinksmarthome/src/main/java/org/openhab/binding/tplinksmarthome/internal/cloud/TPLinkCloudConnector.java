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
package org.openhab.binding.tplinksmarthome.internal.cloud;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.tplinksmarthome.internal.TPLinkCredentials;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Minimal TP-Link cloud connector modeled after the TapoControl account bridge.
 *
 * Cloud login is used to validate account credentials and maintain an account session. Local device control continues
 * to use the credentials directly and does not depend on a cloud token.
 */
@NonNullByDefault
public final class TPLinkCloudConnector {
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final List<String> APP_TYPES = List.of("Tapo_Ios", "Kasa", "Kasa_Android");

    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
    private final String terminalUuid = UUID.randomUUID().toString();

    private String token = "";
    private String activeAppType = "";

    public synchronized void login(String cloudUrl, TPLinkCredentials credentials) throws IOException {
        logout();
        if (!credentials.areSet()) {
            throw new IOException("TP-Link cloud credentials are not configured");
        }
        URI uri;
        try {
            uri = URI.create(cloudUrl);
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid TP-Link cloud URL", e);
        }

        @Nullable String lastError = null;
        for (String appType : APP_TYPES) {
            JsonObject params = new JsonObject();
            params.addProperty("appType", appType);
            params.addProperty("cloudUserName", credentials.username());
            params.addProperty("cloudPassword", credentials.password());
            params.addProperty("terminalUUID", terminalUuid);

            JsonObject root = new JsonObject();
            root.addProperty("method", "login");
            root.add("params", params);
            root.addProperty("requestTimeMils", System.currentTimeMillis());

            HttpRequest request = HttpRequest.newBuilder(uri).timeout(REQUEST_TIMEOUT)
                    .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(root.toString()))
                    .build();
            final HttpResponse<String> response;
            try {
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while logging in to TP-Link cloud", e);
            }
            if (response.statusCode() != 200) {
                lastError = "HTTP " + response.statusCode();
                continue;
            }
            try {
                JsonObject responseJson = JsonParser.parseString(response.body()).getAsJsonObject();
                int errorCode = responseJson.has("error_code") ? responseJson.get("error_code").getAsInt() : -1;
                if (errorCode == 0 && responseJson.has("result") && responseJson.get("result").isJsonObject()) {
                    JsonObject result = responseJson.getAsJsonObject("result");
                    if (result.has("token") && !result.get("token").isJsonNull()) {
                        String newToken = result.get("token").getAsString();
                        if (!newToken.isBlank()) {
                            token = newToken;
                            activeAppType = appType;
                            return;
                        }
                    }
                }
                String message = responseJson.has("msg") && !responseJson.get("msg").isJsonNull()
                        ? responseJson.get("msg").getAsString()
                        : "unknown error";
                lastError = "error " + errorCode + " (" + message + ")";
            } catch (RuntimeException e) {
                lastError = "invalid cloud response";
            }
        }
        throw new IOException("TP-Link cloud login failed: " + (lastError == null ? "unknown error" : lastError));
    }

    public synchronized void logout() {
        token = "";
        activeAppType = "";
    }

    public synchronized boolean isLoggedIn() {
        return !token.isBlank();
    }

    public synchronized String getActiveAppType() {
        return activeAppType;
    }
}
