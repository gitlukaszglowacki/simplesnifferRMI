package Server;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class Sniff implements java.io.Serializable {
    long total, mb, wej, wyj, prom;
    HashMap<Integer, String> ipwej;
    HashMap<Integer, Integer> iloscwej;
    HashMap<Integer, String> ipwyj;
    HashMap<Integer, Integer> iloscwyj;
    Pcap pcap;
    
    public Sniff() {
        this.total = 0;
        this.wej = 0;
        this.wyj = 0;
        this.mb = 0;
        this.prom = 0;
        ipwej = new HashMap<>();
        iloscwej = new HashMap<>();
        ipwyj = new HashMap<>();
        iloscwyj = new HashMap<>();        
        pcap = null;
    }
    
    public int start() throws IOException {
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with  // NICs
        StringBuilder errbuf = new StringBuilder(); // For any error msgs
        Scanner input = new Scanner(System.in);
        
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return -1;
        }
        
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description = (device.getDescription() != null) ? device.getDescription() : "No description available";  
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
        }
        
        PcapIf device = (PcapIf) alldevs.get(0); // We know we have at least 1 device
        // 2 to kabel
        // 0 to wifi
        String description = (device.getDescription() != null) ? device.getDescription() : "No description available";
        System.out.printf("Wybrana karta : %s [%s]\n", device.getName(), description);
        
        String ad = device.getHardwareAddress().toString();
        final byte[] hardwareAddress = device.getHardwareAddress();
        System.out.println("\nAdres MAC wybranej karty sieciowej: " + FormatUtils.mac(hardwareAddress));

        int snaplen = 64 * 1024; // Capture all packets, no truncation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10*1000; // No timeout, non-interactive traffic
        pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return -2;
        }
        
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            long count = 0;

            public void nextPacket(PcapPacket packet, String user) {
                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();
                Ethernet eth = new Ethernet();

                //packet.scan(Ethernet.ID);
                //packet.getCaptureHeader();

                //if (packet.hasHeader(ip) && packet.hasHeader(tcp) && (packet.hasHeader(eth))) {
                if (packet.hasHeader(eth)) {    
//                    System.out.println("Nasz MAC:" + FormatUtils.mac(hardwareAddress)
//                            + "\tSrc MAC: " + FormatUtils.mac(eth.source())
//                            + "\tDsc MAC: " + FormatUtils.mac(eth.destination())
//                            + "\tIP src: " + FormatUtils.ip(ip.source())
//                            + "\tIP dest: " + FormatUtils.ip(ip.destination()));
                    String nasz = FormatUtils.mac(hardwareAddress);
                    String src = FormatUtils.mac(eth.source());
                    String dest = FormatUtils.mac(eth.destination());
                    if (nasz.equals(src)) {
                        if (packet.hasHeader(ip))
                            dodaj_ip(ipwyj, iloscwyj, FormatUtils.ip(ip.destination()));
                        wyj += packet.getPacketWirelen();
                    }
                    else if (nasz.equals(dest)) {
                        if (packet.hasHeader(ip))
                            dodaj_ip(ipwej, iloscwej, FormatUtils.ip(ip.source()));
                        wej += packet.getPacketWirelen();
                    }
                    else {
                        prom += packet.getPacketWirelen();
                    }
                }

                total += packet.getPacketWirelen();

                if (total > 1048576) {
                    mb++;
                    //System.out.println(mb + "MB" + "\t total:" + total);
                    total -= 1048576;
                }
            }
        };
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, " ");

        return 0;
    }
    
    private static void dodaj_ip(HashMap map, HashMap ilosc, String nowy) {
        boolean ok = false;
        Integer i = 0;
        if (sprawdz_liste(map) && sprawdz_liste(ilosc)) {
            Iterator<Map.Entry<Integer, String>> it = map.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<Integer, String> ip_object = it.next();
                //System.out.printf("%s dodaje - ", (String)ip_object.getValue());
                //System.out.printf("%s\n", nowy);
                String test = (String)ip_object.getValue();
                if (test.equals(nowy)) {
                    Integer il = (Integer)ilosc.get(ip_object.getKey());
                    System.out.println("Ilosc IP: " + test + " - nowy " + nowy + " ilosc " + il);
                    il++;
                    ilosc.put(ip_object.getKey(), il);
                    ok = true;
                    System.out.println("Zmieniam IP: " + test + " - nowy " + nowy + " ilosc " + il);
                }
                else
                    i = ip_object.getKey();
                //System.out.println("*" + i + " to bylo i !!!");
            }
            if (!ok){
                map.put(i + 1, nowy);
                ilosc.put(i + 1, 1);
                System.out.println("Dodaje IP:" + nowy);
            }
        }
        else{
            map.put(1, nowy);
            ilosc.put(1, 1);
            System.out.println("Dodaje pierwsze IP:" + nowy);
        }
        System.out.println("***************");
    }
    
    private static boolean sprawdz_liste(HashMap map) {
        if (map.size() < 1) {
            return false;
        } else {
            return true;
        }
    }
    
    public HashMap dajIPwej() {
        return this.ipwej;
    }

    public HashMap dajIPwyj() {
        return this.ipwyj;
    }    

    public HashMap dajIloscwej() {
        return this.iloscwej;
    }
    
    public HashMap dajIloscwyj() {
        return this.iloscwyj;
    }
    
    public int stop() {
        pcap.breakloop();
        pcap.close();
        return 0;
    }
    
    public long dajWej() {
        return this.wej;
    }

    public long dajWyj() {
        return this.wyj;
    }
    
    public long dajProm() {
        return this.prom;
    }
    
    public long dajTotal() {
        return this.total;
    }
    
    public long dajMB() {
        return this.mb;
    }    
    
}

