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

/** Configuration for the TP-Link account/cloud bridge. */
public class TPLinkAccountBridgeConfiguration {
    public String username = "";
    public String password = "";
    public String cloudUrl = "https://eu-wap.tplinkcloud.com";
    public int reconnectInterval = 60;
}
