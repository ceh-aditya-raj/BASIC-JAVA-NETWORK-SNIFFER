package org.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.io.EOFException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeoutException;

public class Net_Sniffer {
    private static final Logger logger = LoggerFactory.getLogger(Net_Sniffer.class);

    // LISTING ALL NETWORK INTERFACE
    public static void listNetworkInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        if (allDevs == null || allDevs.isEmpty()) {
            logger.warn("No network interfaces found.");
            return;
        } else {
            logger.info("Available Network Interfaces:");
            for (PcapNetworkInterface dev : allDevs) {
                logger.info("{} - {}", dev.getName(), dev.getDescription());
            }
        }
    }

    // FINDING NETWORK INTERFACE AND CAPTURING PACKETS
    public static void NET_INTER_CAP(String interfaceName) throws PcapNativeException, NotOpenException, EOFException, TimeoutException, InterruptedException {
        PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
        if (nif == null) {
            logger.info("Network interface " + interfaceName + " not found.");
            return;
        }

        PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10 * 1000);

        handle.setFilter("tcp or udp", BpfProgram.BpfCompileMode.OPTIMIZE); // Filter for TCP and UDP packets

        // Capturing packets continuously
        handle.loop(-1, (PacketListener) Net_Sniffer::analyzePacket);

        handle.close();
    }

    // Utility method to convert hex code to human-readable format
    public static String hexToHumanReadable(byte[] hexData) {
        if (hexData == null || hexData.length == 0) {
            return "";
        }

        StringBuilder humanReadableString = new StringBuilder();
        for (byte b : hexData) {
            // Append only printable ASCII characters, skip control characters
            if (b >= 32 && b <= 126) {
                humanReadableString.append((char) b);
            } else {
                // Replace non-printable characters with a dot (.)
                humanReadableString.append('.');
            }
        }
        return humanReadableString.toString();
    }

    public static void analyzePacket(Packet packet) {
        // Parse Ethernet header (first 14 bytes)
        byte[] rawData = packet.getRawData();
        if (rawData.length < 14) {
            logger.info("Packet too short to be valid.");
            return;
        }

        String destMac = bytesToHex(rawData, 0, 6);
        String srcMac = bytesToHex(rawData, 6, 6);
        String etherType = bytesToHex(rawData, 12, 2);

        logger.info("Ethernet Header: ");
        logger.info("  Destination MAC: {}", destMac);
        logger.info("  Source MAC: {}", srcMac);
        logger.info("  EtherType: {}", etherType);

        // Parse IPv4 header (next 20 bytes)
        if (rawData.length < 34) {
            logger.info("Packet too short for IP header.");
            return;
        }

        String srcIp = (rawData[26] & 0xFF) + "." + (rawData[27] & 0xFF) + "." + (rawData[28] & 0xFF) + "." + (rawData[29] & 0xFF);
        String destIp = (rawData[30] & 0xFF) + "." + (rawData[31] & 0xFF) + "." + (rawData[32] & 0xFF) + "." + (rawData[33] & 0xFF);
        int protocol = rawData[23] & 0xFF;  // Protocol field (0x06 for TCP, 0x11 for UDP)

        logger.info("IPv4 Header: ");
        logger.info("  Source IP: {}", srcIp);
        logger.info("  Destination IP: {}", destIp);
        logger.info("  Protocol: {}", protocol == 0x06 ? "TCP" : (protocol == 0x11 ? "UDP" : "Other"));

        // Parse UDP header if it's UDP
        if (protocol == 0x11 && rawData.length >= 42) {
            int srcPort = ((rawData[34] & 0xFF) << 8) | (rawData[35] & 0xFF);
            int destPort = ((rawData[36] & 0xFF) << 8) | (rawData[37] & 0xFF);
            logger.info("UDP Header: ");
            logger.info("  Source Port: {}", srcPort);
            logger.info("  Destination Port: {}", destPort);
        }

        // Log the data payload (if any)
        if (rawData.length > 42) {
            byte[] payload = Arrays.copyOfRange(rawData, 42, rawData.length);
            logger.info("Payload (hex): {}", bytesToHex(payload));  // Use the updated bytesToHex method
            logger.info("Payload (readable): {}", hexToHumanReadable(payload));
        }
    }

    // Helper method to convert a specific byte range to hex
    public static String bytesToHex(byte[] bytes, int offset, int length) {
        StringBuilder hexString = new StringBuilder();
        for (int i = offset; i < offset + length; i++) {
            hexString.append(String.format("%02X ", bytes[i]));
        }
        return hexString.toString().trim();
    }

    // Helper method to convert byte array to hex string (for comparison)
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString().trim();
    }

    public static void main(String[] args) {
        try {
            listNetworkInterfaces();
            NET_INTER_CAP("\\Device\\NPF_{1BBD3629-2852-4CAC-9EC6-9D347593129D}");  // Call the static method
        } catch (PcapNativeException | NotOpenException | EOFException | TimeoutException | InterruptedException e) {
            logger.error("Error Occurred: {}", e);  // Print the error if an exception occurs
        }
    }
}
