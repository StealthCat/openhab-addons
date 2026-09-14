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
package org.openhab.binding.tplinksmarthome.internal.device;

import java.io.IOException;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.tplinksmarthome.internal.Commands;
import org.openhab.binding.tplinksmarthome.internal.Connection;
import org.openhab.binding.tplinksmarthome.internal.TPLinkSmartHomeConfiguration;
import org.openhab.binding.tplinksmarthome.internal.model.ErrorResponse;
import org.openhab.binding.tplinksmarthome.internal.model.HasErrorResponse;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.types.Command;
import org.openhab.core.types.State;

/**
 * Abstract class as base for Smart Home device implementations.
 *
 * @author Hilbrand Bouwkamp - Initial contribution
 */
@NonNullByDefault
public abstract class SmartHomeDevice {

    protected final Commands commands = new Commands();
    protected @NonNullByDefault({}) Connection connection;
    protected @NonNullByDefault({}) TPLinkSmartHomeConfiguration configuration;

    protected void checkErrors(@Nullable HasErrorResponse response) throws IOException {
        final ErrorResponse errorResponse = response == null ? null : response.getErrorResponse();

        if (errorResponse != null && errorResponse.getErrorCode() != 0) {
            throw new IOException("Error (" + errorResponse.getErrorCode() + "): " + errorResponse.getErrorMessage());
        }
    }

    public void initialize(Connection connection, TPLinkSmartHomeConfiguration configuration) {
        connection.configure(configuration);
        this.connection = connection;
        this.configuration = configuration;
    }

    public abstract String getUpdateCommand();

    public abstract boolean handleCommand(ChannelUID channelUID, Command command) throws IOException;

    public abstract State updateChannel(ChannelUID channelUid, DeviceState deviceState);

    public void refreshedDeviceState(@Nullable DeviceState deviceState) {
    }
}
