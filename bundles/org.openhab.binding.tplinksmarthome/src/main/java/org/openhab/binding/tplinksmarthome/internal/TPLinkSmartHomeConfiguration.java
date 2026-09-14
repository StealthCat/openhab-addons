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

/** Data class representing user configurable settings of the device. */
public class TPLinkSmartHomeConfiguration {
    public String ipAddress;
    public String deviceId;
    public int refresh;
    public int transitionPeriod;

    /** AUTO, XOR, KLAP, KLAP_V1 or KLAP_V2. */
    public String protocol = "AUTO";

    /** TP-Link cloud account e-mail used by authenticated local firmware. */
    public String username = "";

    /** TP-Link cloud account password used only for local KLAP authentication. */
    public String password = "";

    /** HTTP port advertised by modern TP-Link discovery, normally 80. */
    public int httpPort = 80;
}
