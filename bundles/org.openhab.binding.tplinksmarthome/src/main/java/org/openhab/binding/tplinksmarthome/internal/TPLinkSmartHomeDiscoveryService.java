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

import static org.openhab.binding.tplinksmarthome.internal.TPLinkSmartHomeBindingConstants.*;
import static org.openhab.binding.tplinksmarthome.internal.TPLinkSmartHomeThingType.*;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.tplinksmarthome.internal.TPLinkModernDiscovery.ModernDiscoveryResult;
import org.openhab.binding.tplinksmarthome.internal.model.Sysinfo;
import org.openhab.core.config.discovery.AbstractDiscoveryService;
import org.openhab.core.config.discovery.DiscoveryResult;
import org.openhab.core.config.discovery.DiscoveryResultBuilder;
import org.openhab.core.config.discovery.DiscoveryService;
import org.openhab.core.thing.ThingTypeUID;
import org.openhab.core.thing.ThingUID;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Detects legacy XOR and modern authenticated TP-Link/Kasa IOT devices. */
@Component(service = { DiscoveryService.class,
        TPLinkIpAddressService.class }, configurationPid = "discovery.tplinksmarthome")
@NonNullByDefault
public class TPLinkSmartHomeDiscoveryService extends AbstractDiscoveryService implements TPLinkIpAddressService {

    private static final String BROADCAST_IP = "255.255.255.255";
    private static final int DISCOVERY_TIMEOUT_SECONDS = 8;
    private static final int UDP_PACKET_TIMEOUT_MS = (int) TimeUnit.SECONDS.toMillis(DISCOVERY_TIMEOUT_SECONDS - 1);
    private static final long REFRESH_INTERVAL_MINUTES = 1;

    private final Logger logger = LoggerFactory.getLogger(TPLinkSmartHomeDiscoveryService.class);
    private final Commands commands = new Commands();
    private final Map<String, String> idInetAddressCache = new ConcurrentHashMap<>();
    private final Map<String, String> macInetAddressCache = new ConcurrentHashMap<>();
    private final DatagramPacket legacyDiscoverPacket;
    private final DatagramPacket modernDiscoverPacket;
    private final DatagramPacket modernDiscoverPacketAlt;
    private final byte[] buffer = new byte[4096];
    private @NonNullByDefault({}) DatagramSocket discoverSocket;
    private @NonNullByDefault({}) ScheduledFuture<?> discoveryJob;

    public TPLinkSmartHomeDiscoveryService() throws UnknownHostException {
        super(SUPPORTED_THING_TYPES, DISCOVERY_TIMEOUT_SECONDS);
        InetAddress broadcast = InetAddress.getByName(BROADCAST_IP);
        byte[] legacyBuffer = CryptUtil.encrypt(Commands.getSysinfo());
        legacyDiscoverPacket = new DatagramPacket(legacyBuffer, legacyBuffer.length, broadcast,
                Connection.TP_LINK_SMART_HOME_PORT);
        byte[] modernBuffer = TPLinkModernDiscovery.buildDiscoveryPacket();
        modernDiscoverPacket = new DatagramPacket(modernBuffer, modernBuffer.length, broadcast,
                TPLinkModernDiscovery.DISCOVERY_PORT);
        modernDiscoverPacketAlt = new DatagramPacket(modernBuffer, modernBuffer.length, broadcast,
                TPLinkModernDiscovery.DISCOVERY_PORT_ALT);
    }

    TPLinkSmartHomeDiscoveryService(ScheduledExecutorService scheduler) throws UnknownHostException {
        super(scheduler, SUPPORTED_THING_TYPES, DISCOVERY_TIMEOUT_SECONDS, true, null, null);
        InetAddress broadcast = InetAddress.getByName(BROADCAST_IP);
        byte[] legacyBuffer = CryptUtil.encrypt(Commands.getSysinfo());
        legacyDiscoverPacket = new DatagramPacket(legacyBuffer, legacyBuffer.length, broadcast,
                Connection.TP_LINK_SMART_HOME_PORT);
        byte[] modernBuffer = TPLinkModernDiscovery.buildDiscoveryPacket();
        modernDiscoverPacket = new DatagramPacket(modernBuffer, modernBuffer.length, broadcast,
                TPLinkModernDiscovery.DISCOVERY_PORT);
        modernDiscoverPacketAlt = new DatagramPacket(modernBuffer, modernBuffer.length, broadcast,
                TPLinkModernDiscovery.DISCOVERY_PORT_ALT);
    }

    @Override
    public @Nullable String getLastKnownIpAddress(String deviceId) {
        return idInetAddressCache.get(deviceId);
    }

    @Override
    public @Nullable String getLastKnownIpAddressByMac(String macAddress) {
        return macInetAddressCache.get(normalizeMac(macAddress));
    }

    @Override
    protected void startBackgroundDiscovery() {
        discoveryJob = scheduler.scheduleWithFixedDelay(this::startScan, 0, REFRESH_INTERVAL_MINUTES, TimeUnit.MINUTES);
    }

    @Override
    protected void stopBackgroundDiscovery() {
        stopScan();
        if (discoveryJob != null && !discoveryJob.isCancelled()) {
            discoveryJob.cancel(true);
            discoveryJob = null;
        }
    }

    @Override
    protected void startScan() {
        logger.debug("Start scan for TP-Link Smart devices.");
        synchronized (this) {
            try {
                idInetAddressCache.clear();
                macInetAddressCache.clear();
                discoverSocket = sendDiscoveryPacket();
                while (true) {
                    if (discoverSocket == null) {
                        break;
                    }
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    discoverSocket.receive(packet);
                    logger.debug("TP-Link Smart device discovery returned package with length {}", packet.getLength());
                    if (packet.getLength() > 0) {
                        detectThing(packet);
                    }
                }
            } catch (SocketTimeoutException e) {
                logger.debug("Discovering poller timeout...");
            } catch (IOException e) {
                logger.debug("Error during discovery: {}", e.getMessage());
            } finally {
                closeDiscoverSocket();
                removeOlderResults(getTimestampOfLastScan());
            }
        }
    }

    @Override
    protected void stopScan() {
        logger.debug("Stop scan for TP-Link Smart devices.");
        closeDiscoverSocket();
        super.stopScan();
    }

    protected DatagramSocket sendDiscoveryPacket() throws IOException {
        DatagramSocket ds = new DatagramSocket(null);
        ds.setBroadcast(true);
        ds.setSoTimeout(UDP_PACKET_TIMEOUT_MS);
        ds.send(legacyDiscoverPacket);
        ds.send(modernDiscoverPacket);
        ds.send(modernDiscoverPacketAlt);
        logger.trace("Legacy and modern TP-Link discovery packages sent.");
        return ds;
    }

    private void closeDiscoverSocket() {
        if (discoverSocket != null) {
            discoverSocket.close();
            discoverSocket = null;
        }
    }

    private void detectThing(DatagramPacket packet) throws IOException {
        if (packet.getLength() > 16 && packet.getData()[packet.getOffset()] == 2) {
            detectModernThing(packet);
        } else {
            detectLegacyThing(packet);
        }
    }

    private void detectLegacyThing(DatagramPacket packet) throws IOException {
        String ipAddress = packet.getAddress().getHostAddress();
        String rawData = CryptUtil.decrypt(packet.getData(), packet.getLength());
        Sysinfo sysinfoRaw = commands.getSysinfoReponse(rawData);
        Sysinfo sysinfo = sysinfoRaw.getActualSysinfo();
        String deviceId = sysinfo.getDeviceId();
        idInetAddressCache.put(deviceId, ipAddress);
        cacheMacAddress(sysinfo.getMac(), ipAddress);
        Optional<TPLinkSmartHomeThingType> thingType = getThingTypeUID(sysinfo.getModel());
        if (thingType.isPresent()) {
            ThingTypeUID thingTypeUID = thingType.get().thingTypeUID();
            ThingUID thingUID = new ThingUID(thingTypeUID,
                    deviceId.substring(deviceId.length() - 6, deviceId.length()));
            Map<String, Object> properties = PropertiesCollector.collectProperties(thingType.get(), ipAddress,
                    sysinfoRaw);
            DiscoveryResult discoveryResult = DiscoveryResultBuilder.create(thingUID).withLabel(sysinfo.getAlias())
                    .withRepresentationProperty(CONFIG_DEVICE_ID).withProperties(properties).build();
            thingDiscovered(discoveryResult);
        } else {
            logger.debug("Detected, but ignoring unsupported TP-Link Smart Home device model '{}'", sysinfo.getModel());
        }
    }

    private void detectModernThing(DatagramPacket packet) {
        String ipAddress = packet.getAddress().getHostAddress();
        Optional<ModernDiscoveryResult> parsed = TPLinkModernDiscovery.parse(packet.getData(), packet.getLength());
        if (parsed.isEmpty()) {
            return;
        }
        ModernDiscoveryResult result = parsed.get();
        if (!result.isSupportedIotDevice()) {
            logger.debug("Detected TP-Link device '{}' using family/encryption {}/{}; leaving it to the Tapo binding",
                    result.model(), result.deviceType(), result.encryptType());
            return;
        }
        Optional<TPLinkSmartHomeThingType> thingType = getThingTypeUID(result.model());
        if (thingType.isEmpty()) {
            logger.debug("Detected, but ignoring unsupported modern TP-Link Smart Home device model '{}'", result.model());
            return;
        }
        if (!result.deviceId().isBlank()) {
            idInetAddressCache.put(result.deviceId(), ipAddress);
        }
        cacheMacAddress(result.mac(), ipAddress);
        ThingUID thingUID = new ThingUID(thingType.get().thingTypeUID(), uidSuffix(result, ipAddress));
        Map<String, Object> properties = new HashMap<>();
        properties.put(CONFIG_IP, ipAddress);
        properties.put(CONFIG_PROTOCOL, result.protocol());
        properties.put(CONFIG_HTTP_PORT, result.httpPort());
        properties.put(PROPERTY_TYPE, result.deviceType());
        properties.put(PROPERTY_MODEL, result.model());
        if (!result.mac().isBlank()) {
            properties.put(PROPERTY_MAC, result.mac());
        }
        if (!result.hardwareVersion().isBlank()) {
            properties.put(PROPERTY_HARDWARE_VERSION, result.hardwareVersion());
        }
        properties.put(PROPERTY_PROTOCOL_NAME, result.protocol());
        if (result.loginVersion() > 0) {
            properties.put(PROPERTY_PROTOCOL_VERSION, Integer.toString(result.loginVersion()));
        }
        String label = result.model() + " (" + ipAddress + ")";
        DiscoveryResult discoveryResult = DiscoveryResultBuilder.create(thingUID).withLabel(label)
                .withRepresentationProperty(CONFIG_IP).withProperties(properties).build();
        thingDiscovered(discoveryResult);
    }

    private void cacheMacAddress(@Nullable String macAddress, String ipAddress) {
        if (macAddress != null && !macAddress.isBlank()) {
            macInetAddressCache.put(normalizeMac(macAddress), ipAddress);
        }
    }

    private static String normalizeMac(String macAddress) {
        return macAddress.replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ENGLISH);
    }

    private String uidSuffix(ModernDiscoveryResult result, String ipAddress) {
        String source = !result.deviceId().isBlank() ? result.deviceId()
                : !result.mac().isBlank() ? result.mac() : ipAddress;
        String normalized = source.replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ENGLISH);
        return normalized.length() > 6 ? normalized.substring(normalized.length() - 6) : normalized;
    }

    private Optional<TPLinkSmartHomeThingType> getThingTypeUID(String model) {
        String modelLC = model.toLowerCase(Locale.ENGLISH);
        return SUPPORTED_THING_TYPES_LIST.stream().filter(type -> modelLC.startsWith(type.thingTypeUID().getId()))
                .findFirst();
    }
}
