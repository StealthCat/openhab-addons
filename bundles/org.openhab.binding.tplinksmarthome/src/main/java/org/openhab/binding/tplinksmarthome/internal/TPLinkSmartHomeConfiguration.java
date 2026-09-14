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

/**
 * Data class representing the user configurable settings of the device
 *
 * @author Hilbrand Bouwkamp - Initial contribution
 */
public class TPLinkSmartHomeConfiguration {

    /**
     * IP Address of the device.
     */
    public String ipAddress;

    /**
     * The id of the device;
     */
    public String deviceId;

    /**
     * Refresh rate for the device in seconds.
     */
    public int refresh;

    /**
     * Transition period of light bulb state changes in seconds.
     */
    public int transitionPeriod;

    /**
     * Local protocol. Supported values are AUTO, XOR, KLAP, KLAP_V1 and KLAP_V2.
     */
    public String protocol = "AUTO";

    /**
     * TP-Link/Kasa account e-mail used for authenticated local access.
     */
    public String username = "";

    /**
     * TP-Link/Kasa account password used for authenticated local access.
     */
    public String password = "";

    /**
     * HTTP port used by KLAP, normally 80.
     */
    public int httpPort = 80;
}
