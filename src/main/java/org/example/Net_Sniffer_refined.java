package org.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.io.EOFException;
import java.util.List;
import java.util.concurrent.TimeoutException;

public class Net_Sniffer_refined {

    private static final Logger logger = LoggerFactory.getLogger(Net_Sniffer_refined.class);

    // LISTING ALL NETWORK INTERFACES
    public static void listNetworkInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        if (allDevs == null || allDevs.isEmpty()) {
            logger.warn("No network interfaces found.");
            return;
        }
        logger.info("Available Network Interfaces:");
        for (PcapNetworkInterface dev : allDevs) {
            logger.info("{} - {}", dev.getName(), dev.getDescription());
        }
    }

    // FINDING NETWORK INTERFACE AND CAPTURING PACKETS
    public static void capturePackets(String interfaceName) throws PcapNativeException, NotOpenException, EOFException, TimeoutException, InterruptedException {
        PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
        if (nif == null) {
            logger.error("Network interface {} not found.", interfaceName);
            return;
        }

        // Open a handle to capture packets in promiscuous mode
        try (PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10 * 1000)) {

            // Set a filter for HTTP traffic (port 80)
            String filter = "tcp port 80";
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
            logger.info("Capturing packets with filter: {}", filter);

            // Capture packets continuously and log them in human-readable format
            handle.loop(-1, (PacketListener) packet -> {
                logger.info("Captured Packet:");
                analyzePacket(packet);
            });

            // Capture and log packets continuously
            handle.loop(-1, (PacketListener) packet -> {
                logger.info("Captured Packet: {}", packet);

                // Analyze captured packets
                analyzePacket(packet);
            });

        } catch (PcapNativeException | NotOpenException e) {
            logger.error("Error capturing packets: {}", e.getMessage(), e);
        }
    }

    // ANALYZE CAPTURED PACKETS
    private static void analyzePacket(Packet packet) {
        IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        UdpPacket udpPacket = packet.get(UdpPacket.class);

        if (ipv4Packet != null) {
            logger.info("Source IP: {}", ipv4Packet.getHeader().getSrcAddr());
            logger.info("Destination IP: {}", ipv4Packet.getHeader().getDstAddr());
        }

        if (tcpPacket != null) {
            logger.info("TCP Packet: Source Port: {}, Destination Port: {}",
                    tcpPacket.getHeader().getSrcPort(), tcpPacket.getHeader().getDstPort());
        }

        if (udpPacket != null) {
            logger.info("UDP Packet: Source Port: {}, Destination Port: {}",
                    udpPacket.getHeader().getSrcPort(), udpPacket.getHeader().getDstPort());
        }
    }

    public static void main(String[] args) {
        try {
            // List all available network interfaces
            listNetworkInterfaces();

            // Replace with the appropriate network interface from the list
            String interfaceName = "\\Device\\NPF_{1BBD3629-2852-4CAC-9EC6-9D347593129D}";

            // Capture packets on the selected interface
            capturePackets(interfaceName);
        } catch (PcapNativeException | NotOpenException | EOFException | TimeoutException | InterruptedException e) {
            logger.error("Error occurred: {}", e.getMessage(), e);
        }
    }
}