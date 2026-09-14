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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Locale;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Connection facade for legacy XOR and modern KLAP transports.
 *
 * The public API intentionally remains the same so the device-specific command code does not need to know which
 * transport a firmware revision uses.
 */
@NonNullByDefault
public class Connection {

    public static final int TP_LINK_SMART_HOME_PORT = 9999;
    private final Logger logger = LoggerFactory.getLogger(Connection.class);
    private static final int SOCKET_TIMEOUT_MILLISECONDS = 2_000;

    private enum ActiveTransport {
        UNKNOWN,
        XOR,
        KLAP
    }

    private @Nullable String ipAddress;
    private String configuredProtocol = "AUTO";
    private String username = "";
    private String password = "";
    private int httpPort = 80;
    private ActiveTransport activeTransport = ActiveTransport.UNKNOWN;
    private @Nullable KlapTransport klapTransport;

    public Connection(@Nullable final String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public Connection(final TPLinkSmartHomeConfiguration configuration) {
        ipAddress = configuration.ipAddress;
        configure(configuration);
    }

    /** Apply protocol/authentication settings after the device has been initialized. */
    public synchronized void configure(final TPLinkSmartHomeConfiguration configuration) {
        configure(configuration, configuration.username, configuration.password);
    }

    /**
     * Apply protocol settings while allowing credentials to be supplied by an account bridge.
     */
    public synchronized void configure(final TPLinkSmartHomeConfiguration configuration, @Nullable String username,
            @Nullable String password) {
        String newProtocol = normalizeProtocol(configuration.protocol);
        String newUsername = username == null ? "" : username;
        String newPassword = password == null ? "" : password;
        int newHttpPort = configuration.httpPort > 0 ? configuration.httpPort : 80;

        if (!newProtocol.equals(configuredProtocol) || !newUsername.equals(this.username)
                || !newPassword.equals(this.password) || newHttpPort != httpPort) {
            configuredProtocol = newProtocol;
            this.username = newUsername;
            this.password = newPassword;
            httpPort = newHttpPort;
            activeTransport = ActiveTransport.UNKNOWN;
            klapTransport = null;
        }
    }

    public synchronized void setIpAddress(final String ipAddress) {
        if (this.ipAddress == null || !this.ipAddress.equals(ipAddress)) {
            this.ipAddress = ipAddress;
            activeTransport = ActiveTransport.UNKNOWN;
            if (klapTransport != null) {
                klapTransport.setHost(ipAddress);
            }
        }
    }

    public synchronized String sendCommand(final String command) throws IOException {
        if (ipAddress == null || ipAddress.isBlank()) {
            throw new IOException("Ip address not set. Wait for discovery or manually trigger discovery process.");
        }

        if ("XOR".equals(configuredProtocol)) {
            return sendLegacyCommand(command);
        }
        if (configuredProtocol.startsWith("KLAP")) {
            return sendKlapCommand(command, configuredKlapVersion());
        }

        // AUTO: prefer the last known-good transport and re-probe when it stops working.
        if (activeTransport == ActiveTransport.XOR) {
            try {
                return sendLegacyCommand(command);
            } catch (IOException e) {
                activeTransport = ActiveTransport.UNKNOWN;
                return tryKlapAfterLegacyFailure(command, e);
            }
        }
        if (activeTransport == ActiveTransport.KLAP) {
            try {
                return sendKlapCommand(command, 0);
            } catch (IOException klapFailure) {
                activeTransport = ActiveTransport.UNKNOWN;
                try {
                    String response = sendLegacyCommand(command);
                    activeTransport = ActiveTransport.XOR;
                    return response;
                } catch (IOException legacyFailure) {
                    klapFailure.addSuppressed(legacyFailure);
                    throw klapFailure;
                }
            }
        }

        try {
            String response = sendLegacyCommand(command);
            activeTransport = ActiveTransport.XOR;
            logger.debug("TP-Link transport selected legacy XOR for {}", ipAddress);
            return response;
        } catch (IOException legacyFailure) {
            return tryKlapAfterLegacyFailure(command, legacyFailure);
        }
    }

    private String tryKlapAfterLegacyFailure(String command, IOException legacyFailure) throws IOException {
        try {
            String response = sendKlapCommand(command, 0);
            activeTransport = ActiveTransport.KLAP;
            KlapTransport transport = klapTransport;
            logger.debug("TP-Link transport selected KLAP{} for {}",
                    transport == null ? "" : " v" + transport.getActiveVersion(), ipAddress);
            return response;
        } catch (IOException klapFailure) {
            klapFailure.addSuppressed(legacyFailure);
            throw klapFailure;
        }
    }

    private String sendLegacyCommand(final String command) throws IOException {
        try (Socket socket = createSocket(); OutputStream outputStream = socket.getOutputStream()) {
            outputStream.write(CryptUtil.encryptWithLength(command));
            return readReturnValue(socket);
        }
    }

    private String sendKlapCommand(final String command, int version) throws IOException {
        String host = ipAddress;
        if (host == null || host.isBlank()) {
            throw new IOException("Ip address not set. Wait for discovery or manually trigger discovery process.");
        }
        KlapTransport transport = klapTransport;
        if (transport == null) {
            transport = new KlapTransport(host, httpPort, username, password, version);
            klapTransport = transport;
        }
        return transport.sendCommand(command);
    }

    private int configuredKlapVersion() {
        if ("KLAP_V1".equals(configuredProtocol)) {
            return 1;
        }
        if ("KLAP_V2".equals(configuredProtocol)) {
            return 2;
        }
        return 0;
    }

    private static String normalizeProtocol(@Nullable String protocol) {
        if (protocol == null || protocol.isBlank()) {
            return "AUTO";
        }
        String normalized = protocol.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (normalized) {
            case "XOR", "KLAP", "KLAP_V1", "KLAP_V2" -> normalized;
            default -> "AUTO";
        };
    }

    private String readReturnValue(final Socket socket) throws IOException {
        try (InputStream is = socket.getInputStream()) {
            return CryptUtil.decryptWithLength(is);
        }
    }

    /** Wrapper around socket creation retained to keep existing device tests mockable. */
    protected Socket createSocket() throws UnknownHostException, IOException {
        if (ipAddress == null) {
            throw new IOException("Ip address not set. Wait for discovery or manually trigger discovery process.");
        }
        final Socket socket = new Socket(ipAddress, TP_LINK_SMART_HOME_PORT);
        socket.setSoTimeout(SOCKET_TIMEOUT_MILLISECONDS);
        return socket;
    }
}
