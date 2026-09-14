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
package org.openhab.binding.tplinksmarthome.internal.handler;

import java.io.IOException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.tplinksmarthome.internal.TPLinkAccountBridgeConfiguration;
import org.openhab.binding.tplinksmarthome.internal.TPLinkCredentials;
import org.openhab.binding.tplinksmarthome.internal.cloud.TPLinkCloudConnector;
import org.openhab.core.thing.Bridge;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.openhab.core.thing.binding.BaseBridgeHandler;
import org.openhab.core.types.Command;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Account bridge that centralizes TP-Link credentials and maintains a best-effort TP-Link cloud session.
 *
 * Child devices use the bridge credentials for local KLAP authentication. Local device control is intentionally not
 * dependent on the cloud session being available.
 */
@NonNullByDefault
public class TPLinkAccountBridgeHandler extends BaseBridgeHandler {
    private final Logger logger = LoggerFactory.getLogger(TPLinkAccountBridgeHandler.class);
    private final TPLinkCloudConnector cloudConnector = new TPLinkCloudConnector();

    private TPLinkCredentials credentials = TPLinkCredentials.EMPTY;
    private TPLinkAccountBridgeConfiguration configuration = new TPLinkAccountBridgeConfiguration();
    private @Nullable ScheduledFuture<?> reconnectJob;

    public TPLinkAccountBridgeHandler(Bridge bridge) {
        super(bridge);
    }

    @Override
    public void initialize() {
        stopReconnectJob();
        configuration = getConfigAs(TPLinkAccountBridgeConfiguration.class);
        credentials = new TPLinkCredentials(nullToEmpty(configuration.username), nullToEmpty(configuration.password));

        if (!credentials.areSet()) {
            cloudConnector.logout();
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                    "TP-Link account username and password are required.");
            return;
        }

        // The bridge primarily supplies credentials to child Things. Keep it ONLINE when credentials are configured
        // even if optional cloud validation is temporarily unavailable.
        updateStatus(ThingStatus.ONLINE, ThingStatusDetail.NONE, "TP-Link credentials configured; validating cloud login.");
        scheduler.execute(this::loginCloud);

        if (configuration.reconnectInterval > 0) {
            reconnectJob = scheduler.scheduleWithFixedDelay(this::loginCloud, configuration.reconnectInterval,
                    configuration.reconnectInterval, TimeUnit.MINUTES);
        }
    }

    @Override
    public void dispose() {
        stopReconnectJob();
        cloudConnector.logout();
        super.dispose();
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
        logger.debug("TP-Link account bridge does not handle channel command {} for {}", command, channelUID);
    }

    public TPLinkCredentials getCredentials() {
        return credentials;
    }

    public boolean isCloudLoggedIn() {
        return cloudConnector.isLoggedIn();
    }

    private void loginCloud() {
        if (!credentials.areSet()) {
            return;
        }
        try {
            cloudConnector.login(nullToDefault(configuration.cloudUrl, "https://eu-wap.tplinkcloud.com"), credentials);
            updateStatus(ThingStatus.ONLINE, ThingStatusDetail.NONE,
                    "TP-Link cloud login successful (" + cloudConnector.getActiveAppType() + ").");
        } catch (IOException e) {
            logger.debug("TP-Link cloud login validation failed: {}", e.getMessage());
            updateStatus(ThingStatus.ONLINE, ThingStatusDetail.NONE,
                    "Credentials are available to local devices; cloud validation failed: " + e.getMessage());
        }
    }

    private void stopReconnectJob() {
        ScheduledFuture<?> job = reconnectJob;
        if (job != null) {
            job.cancel(true);
            reconnectJob = null;
        }
    }

    private static String nullToEmpty(@Nullable String value) {
        return value == null ? "" : value;
    }

    private static String nullToDefault(@Nullable String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
