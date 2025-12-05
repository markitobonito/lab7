package net.floodlightcontroller.eaprad;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Collections;
import java.io.File;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.NodePortTuple;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.VlanVid;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EapRadiusModule implements IFloodlightModule, IOFMessageListener, IOFSwitchListener {
    private static final Logger log = LoggerFactory.getLogger(EapRadiusModule.class);
    private IFloodlightProviderService floodlightProvider;
    private IOFSwitchService switchService;
    private IDeviceService deviceService;
    private IRoutingService routingService;
    private static final int AUTH_PORT = 10000;
    private static final byte[] AES_KEY = "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] AES_IV = "abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII);
    private final ObjectMapper json = new ObjectMapper();
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
    private Map<String, String> userPasswords;
    private Map<String, Object> configData;
    private List<String> serverIps;
    private Map<String, Map<String, Object>> serversByIp;
    private static final String GATEWAY_IP = "10.33.0.1";
    private static final DatapathId GATEWAY_DPID = DatapathId.of("00:00:ce:0f:cd:64:46:48");
    private static final OFPort GATEWAY_ATTACH_PORT = OFPort.of(6);
    private static final OFPort MIRROR_PORT = OFPort.of(5);
    private static final OFPort CONTROLLER_PORT = OFPort.of(1);
    private static final String CONTROLLER_IP = "192.168.200.200";
    private static final String IDS_IP = "10.33.0.8";
    private static final String INTERNAL_NETWORK = "10.33.0.0/16";

    private static class ServerInfo {
        String ip;
        MacAddress mac;
        ServerInfo(String ip, MacAddress mac) { this.ip = ip; this.mac = mac; }
    }
    private List<ServerInfo> officialServers = new ArrayList<>();

    @Override
    public String getName() { return "EapRadiusModule"; }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = new ArrayList<>();
        l.add(IFloodlightProviderService.class);
        l.add(IOFSwitchService.class);
        l.add(IDeviceService.class);
        l.add(IRoutingService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        switchService = context.getServiceImpl(IOFSwitchService.class);
        deviceService = context.getServiceImpl(IDeviceService.class);
        routingService = context.getServiceImpl(IRoutingService.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        switchService.addOFSwitchListener(this);
        Runtime.getRuntime().addShutdownHook(new Thread(this::cleanupYaml));
        try {
            configData = yamlMapper.readValue(new File("config.yaml"), Map.class);
            loadUsersAndServers();
            loadOfficialServers();
            log.info("=== EapRadiusModule iniciado - " + userPasswords.size() + " usuarios activos ===");
        } catch (Exception e) {
            log.error("Error al cargar config.yaml", e);
        }
    }

    private void loadOfficialServers() {
        officialServers.clear();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> servidores = (List<Map<String, Object>>) configData.get("servidores");
        if (servidores != null) {
            for (Map<String, Object> s : servidores) {
                String ip = (String) s.get("ip");
                String macStr = (String) s.get("mac");
                if (ip != null && macStr != null) {
                    try {
                        MacAddress mac = MacAddress.of(macStr);
                        officialServers.add(new ServerInfo(ip, mac));
                    } catch (Exception e) {
                        log.error("Invalid MAC for server IP: " + ip, e);
                    }
                }
            }
        }
    }

    private void loadUsersAndServers() {
        userPasswords = new HashMap<>();
        serverIps = new ArrayList<>();
        serversByIp = new HashMap<>();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> usuarios = (List<Map<String, Object>>) configData.get("usuarios");
        if (usuarios != null) {
            for (Map<String, Object> u : usuarios) {
                String nombre = (String) u.get("nombre");
                String contrasena = (String) u.get("contrasena");
                String estado = (String) u.get("estado");
                if ("activo".equals(estado)) {
                    userPasswords.put(nombre, contrasena);
                }
            }
        }
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> servidores = (List<Map<String, Object>>) configData.get("servidores");
        if (servidores != null) {
            for (Map<String, Object> s : servidores) {
                String ip = (String) s.get("ip");
                serverIps.add(ip);
                serversByIp.put(ip, s);
            }
        }
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (msg.getType() != OFType.PACKET_IN) return Command.CONTINUE;
        OFPacketIn pi = (OFPacketIn) msg;
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        if (eth == null) return Command.STOP;
        if (eth.getEtherType() == EthType.ARP) {
            return handleArp(sw, pi, cntx, eth);
        }
        if (eth.getEtherType() != EthType.IPv4) return Command.STOP;
        IPv4 ip = (IPv4) eth.getPayload();
        if (ip == null) return Command.STOP;
        if (ip.getProtocol() == IpProtocol.UDP) {
            UDP udp = (UDP) ip.getPayload();
            if (udp.getDestinationPort().getPort() == AUTH_PORT) {
                handleAuthPacket(sw, pi, eth, ip, udp);
                return Command.STOP;
            }
        }
        String srcIpStr = ip.getSourceAddress().toString();
        String dstIpStr = ip.getDestinationAddress().toString();
        MacAddress srcMac = eth.getSourceMACAddress();
        OFPort inPort = pi.getMatch().get(MatchField.IN_PORT);
        String dpid = sw.getId().toString();
        log.debug("Procesando paquete: srcMAC=" + srcMac + ", srcIP=" + srcIpStr + ", dstIP=" + dstIpStr + ", dpid=" + dpid + ", inPort=" + inPort);
        String user = getAuthenticatedUser(dpid, inPort, srcMac, srcIpStr);
        if (user == null) {
            log.warn("Paquete de usuario no autenticado (spoof?) desde " + srcMac + " en " + dpid + ":" + inPort);
            log.debug("Contexto_usuarios actual: " + configData.get("contexto_usuarios"));
            return Command.STOP;
        }
        log.debug("Usuario autenticado encontrado: " + user);
        int dstPort = getDestinationPort(ip);
        if (dstPort == -1 && ip.getProtocol() != IpProtocol.ICMP) return Command.STOP;
        boolean isInternal = isInternalIp(dstIpStr);
        String effectiveDstIp = isInternal ? dstIpStr : GATEWAY_IP;
        if (isInternal && !serverIps.contains(dstIpStr)) {
            log.debug("Acceso a IP interna no servidor: " + dstIpStr + " - permitiendo como tráfico normal");
        } else if (isInternal && !hasAccess(user, dstIpStr, dstPort)) {
            log.warn("Usuario " + user + " intentó acceder a puerto prohibido " + dstPort + " en " + dstIpStr);
            installTempDrop(sw, pi, eth, srcIpStr, dstIpStr, dstPort);
            return Command.STOP;
        }
        installPath(sw, pi, eth, srcIpStr, effectiveDstIp, ip.getProtocol(), inPort, dstIpStr);
        return Command.STOP;
    }

    private Command handleArp(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Ethernet eth) {
        OFPort inPort = pi.getMatch().get(MatchField.IN_PORT);
        MacAddress srcMac = eth.getSourceMACAddress();
        String dpid = sw.getId().toString();
        String user = getAuthenticatedUser(dpid, inPort, srcMac, "0.0.0.0");
        if (user != null) {
            log.debug("Flooding ARP para usuario autenticado " + user);
            OFPacketOut po = sw.getOFFactory().buildPacketOut()
                    .setBufferId(pi.getBufferId())
                    .setInPort(inPort)
                    .setActions(Collections.singletonList(
                            sw.getOFFactory().actions().buildOutput()
                                    .setPort(OFPort.FLOOD)
                                    .build()))
                    .setData(pi.getBufferId() == OFBufferId.NO_BUFFER ? eth.serialize() : new byte[0])
                    .build();
            sw.write(po);
            return Command.STOP;
        }
        return Command.CONTINUE;
    }

    private boolean isInternalIp(String ip) {
        int addr = IPv4.toIPv4Address(ip);
        int net = IPv4.toIPv4Address("10.33.0.0");
        int mask = ~((1 << (32 - 16)) - 1);
        return (addr & mask) == net;
    }

    private String getAuthenticatedUser(String dpid, OFPort inPort, MacAddress mac, String ip) {
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> contextos = (List<Map<String, Object>>) configData.get("contexto_usuarios");
        if (contextos == null) return null;
        log.debug("Buscando usuario autenticado para dpid=" + dpid + ", inPort=" + inPort + ", mac=" + mac + ", ip=" + ip);
        for (Map<String, Object> c : contextos) {
            log.debug("Contexto: dpid=" + c.get("dpid") + ", puerto=" + c.get("puerto") + ", mac=" + c.get("mac") + ", ip=" + c.get("ip") + ", usuario=" + c.get("usuario"));
            if (dpid.equals(c.get("dpid")) && inPort.getPortNumber() == ((Integer) c.get("puerto")).intValue() && mac.toString().equals(c.get("mac")) && (ip.equals("0.0.0.0") || ip.equals(c.get("ip")))) {
                return (String) c.get("usuario");
            }
        }
        return null;
    }

    private int getDestinationPort(IPv4 ip) {
        if (ip.getProtocol() == IpProtocol.TCP) {
            return ((TCP) ip.getPayload()).getDestinationPort().getPort();
        } else if (ip.getProtocol() == IpProtocol.UDP) {
            return ((UDP) ip.getPayload()).getDestinationPort().getPort();
        }
        return -1;
    }

    private boolean hasAccess(String user, String dstIp, int dstPort) {
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> usuarios = (List<Map<String, Object>>) configData.get("usuarios");
        Map<String, Object> userMap = null;
        for (Map<String, Object> u : usuarios) {
            if (user.equals(u.get("nombre"))) {
                userMap = u;
                break;
            }
        }
        if (userMap == null) return false;
        String rol = (String) userMap.get("rol");
        String codigoStr = String.valueOf(userMap.get("codigo"));
        if ("superadmin".equals(rol)) return true;
        if (!"10.33.0.6".equals(dstIp)) return false;
        if (userMap.containsKey("puerto_10.33.0.6") && ((Integer) userMap.get("puerto_10.33.0.6")).intValue() == dstPort) return true;
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rolesList = (List<Map<String, Object>>) configData.get("roles");
        if (rolesList != null) {
            for (Map<String, Object> r : rolesList) {
                String rname = (String) r.get("rol");
                if (rname == null) rname = (String) r.get("nombre");
                if (rname.equals(rol) && r.containsKey("puerto_10.33.0.6") && ((Integer) r.get("puerto_10.33.0.6")).intValue() == dstPort) return true;
            }
        }
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> cursos = (List<Map<String, Object>>) configData.get("cursos");
        if (cursos != null) {
            for (Map<String, Object> curso : cursos) {
                if ("DICTANDO".equals(curso.get("estado"))) {
                    @SuppressWarnings("unchecked")
                    List<Object> alumnosObj = (List<Object>) curso.get("alumnos");
                    List<String> alumnos = new ArrayList<>();
                    for (Object a : alumnosObj) {
                        alumnos.add(String.valueOf(a));
                    }
                    if (alumnos.contains(codigoStr)) {
                        @SuppressWarnings("unchecked")
                        List<Map<String, Object>> servs = (List<Map<String, Object>>) curso.get("servidores");
                        for (Map<String, Object> s : servs) {
                            if ("recursos".equals(s.get("nombre"))) {
                                @SuppressWarnings("unchecked")
                                List<Map<String, Object>> permit = (List<Map<String, Object>>) s.get("servicios_permitidos");
                                for (Map<String, Object> p : permit) {
                                    if (((Integer) p.get("puerto_web")).intValue() == dstPort) return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        Map<String, Object> server = serversByIp.get(dstIp);
        if (server != null) {
            @SuppressWarnings("unchecked")
            List<String> ports = (List<String>) server.get("puertos");
            boolean hasPort = false;
            for (String p : ports) {
                int portNum;
                if ("ssh".equals(p)) portNum = 22;
                else portNum = Integer.parseInt(p);
                if (portNum == dstPort) hasPort = true;
            }
            if (hasPort) return true;
        }
        return false;
    }

    private void installTempDrop(IOFSwitch sw, OFPacketIn pi, Ethernet eth, String srcIp, String dstIp, int dstPort) {
        IPv4 ip = (IPv4) eth.getPayload();
        Match.Builder mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.IN_PORT, pi.getMatch().get(MatchField.IN_PORT))
          .setExact(MatchField.ETH_SRC, eth.getSourceMACAddress())
          .setExact(MatchField.ETH_TYPE, EthType.IPv4)
          .setExact(MatchField.IPV4_SRC, IPv4Address.of(srcIp))
          .setExact(MatchField.IPV4_DST, IPv4Address.of(dstIp));
        if (ip.getProtocol() == IpProtocol.TCP) {
            TCP tcp = (TCP) ip.getPayload();
            mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
              .setExact(MatchField.TCP_DST, tcp.getDestinationPort());
        } else if (ip.getProtocol() == IpProtocol.UDP) {
            UDP udp = (UDP) ip.getPayload();
            mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
              .setExact(MatchField.UDP_DST, udp.getDestinationPort());
        }
        OFFlowMod drop = sw.getOFFactory().buildFlowAdd()
                .setMatch(mb.build())
                .setPriority(2000)
                .setHardTimeout(30)
                .setActions(new ArrayList<>())
                .build();
        sw.write(drop);
    }

    private void installPath(IOFSwitch sw, OFPacketIn pi, Ethernet eth, String srcIp, String effectiveDstIp, IpProtocol proto, OFPort inPort, String originalDstIp) {
        IPv4 ip = (IPv4) eth.getPayload();
        IPv4Address matchDstAddr = IPv4Address.of(originalDstIp);
        DatapathId srcDpid = sw.getId();
        OFPort srcAttachPort = inPort;
        DatapathId dstDpid = null;
        OFPort dstAttachPort = null;
        Route forwardRoute = null;
        TransportPort srcTransportPort = null;
        TransportPort dstTransportPort = null;
        if (proto == IpProtocol.TCP) {
            TCP tcp = (TCP) ip.getPayload();
            srcTransportPort = tcp.getSourcePort();
            dstTransportPort = tcp.getDestinationPort();
        } else if (proto == IpProtocol.UDP) {
            UDP udp = (UDP) ip.getPayload();
            srcTransportPort = udp.getSourcePort();
            dstTransportPort = udp.getDestinationPort();
        }
        if ("10.33.0.6".equals(effectiveDstIp)) {
            dstDpid = DatapathId.of("00:00:36:10:1e:65:77:49");
            dstAttachPort = OFPort.of(2);
        } else if (GATEWAY_IP.equals(effectiveDstIp)) {
            dstDpid = GATEWAY_DPID;
            dstAttachPort = GATEWAY_ATTACH_PORT;
        } else {
            IDevice dstDevice = deviceService.findDevice(
                    MacAddress.NONE, VlanVid.ZERO, IPv4Address.of(effectiveDstIp), IPv6Address.NONE, DatapathId.NONE, OFPort.ANY);
            if (dstDevice == null || dstDevice.getAttachmentPoints().length == 0) {
                log.warn("No se encontró attachment point para " + effectiveDstIp + ". Flooding packet.");
                floodPacket(sw, pi, eth, inPort);
                return;
            }
            SwitchPort ap = dstDevice.getAttachmentPoints()[0];
            dstDpid = ap.getSwitchDPID();
            dstAttachPort = ap.getPort();
        }
        try {
            forwardRoute = routingService.getRoute(srcDpid, srcAttachPort, dstDpid, dstAttachPort, U64.of(0));
        } catch (Throwable e) {
            log.warn("Error calculando ruta hacia " + effectiveDstIp + ": " + e.getMessage());
            forwardRoute = null;
        }
        if (forwardRoute == null) {
            handleNoRoute(sw, pi, eth, srcIp, matchDstAddr, proto, srcTransportPort, dstTransportPort, dstDpid, dstAttachPort, inPort, effectiveDstIp.equals(GATEWAY_IP));
            return;
        }
        List<NodePortTuple> forwardPath = forwardRoute.getPath();
        Match.Builder mbFwd = sw.getOFFactory().buildMatch();
        mbFwd.setExact(MatchField.ETH_TYPE, EthType.IPv4)
             .setExact(MatchField.IP_PROTO, proto)
             .setExact(MatchField.IPV4_SRC, IPv4Address.of(srcIp));
        if (!effectiveDstIp.equals(GATEWAY_IP)) {
            mbFwd.setExact(MatchField.IPV4_DST, matchDstAddr);
        }
        if (dstTransportPort != null && proto != IpProtocol.ICMP) {
            if (proto == IpProtocol.TCP) {
                mbFwd.setExact(MatchField.TCP_DST, dstTransportPort);
            } else if (proto == IpProtocol.UDP) {
                mbFwd.setExact(MatchField.UDP_DST, dstTransportPort);
            }
        }
        Match matchFwd = mbFwd.build();
        for (int i = 0; i < forwardPath.size(); i += 2) {
            NodePortTuple npt = forwardPath.get(i);
            IOFSwitch s = switchService.getSwitch(npt.getNodeId());
            if (s == null) continue;
            OFPort outPort = forwardPath.get(i + 1).getPortId();
            List<OFAction> actions = new ArrayList<>();
            actions.add(s.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(0xffff).build());
            if (s.getId().equals(GATEWAY_DPID) && outPort.equals(GATEWAY_ATTACH_PORT)) {
                actions.add(s.getOFFactory().actions().buildOutput().setPort(MIRROR_PORT).setMaxLen(0xffff).build());
            }
            OFFlowMod fm = s.getOFFactory().buildFlowAdd()
                    .setMatch(matchFwd)
                    .setActions(actions)
                    .setIdleTimeout(60)
                    .setHardTimeout(300)
                    .setPriority(1000)
                    .build();
            s.write(fm);
        }
        // Install on destination switch if multi-hop
        if (!forwardPath.isEmpty()) {
            IOFSwitch dstSw = switchService.getSwitch(dstDpid);
            if (dstSw != null) {
                NodePortTuple lastNpt = forwardPath.get(forwardPath.size() - 1);
                Match.Builder mbDst = dstSw.getOFFactory().buildMatch();
                mbDst.setExact(MatchField.IN_PORT, lastNpt.getPortId())
                     .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                     .setExact(MatchField.IP_PROTO, proto)
                     .setExact(MatchField.IPV4_SRC, IPv4Address.of(srcIp));
                if (!effectiveDstIp.equals(GATEWAY_IP)) {
                    mbDst.setExact(MatchField.IPV4_DST, matchDstAddr);
                }
                if (dstTransportPort != null && proto != IpProtocol.ICMP) {
                    if (proto == IpProtocol.TCP) {
                        mbDst.setExact(MatchField.TCP_DST, dstTransportPort);
                    } else if (proto == IpProtocol.UDP) {
                        mbDst.setExact(MatchField.UDP_DST, dstTransportPort);
                    }
                }
                List<OFAction> actions = new ArrayList<>();
                actions.add(dstSw.getOFFactory().actions().buildOutput().setPort(dstAttachPort).setMaxLen(0xffff).build());
                if (dstSw.getId().equals(GATEWAY_DPID) && dstAttachPort.equals(GATEWAY_ATTACH_PORT)) {
                    actions.add(dstSw.getOFFactory().actions().buildOutput().setPort(MIRROR_PORT).setMaxLen(0xffff).build());
                }
                OFFlowMod fmDst = dstSw.getOFFactory().buildFlowAdd()
                        .setMatch(mbDst.build())
                        .setActions(actions)
                        .setIdleTimeout(60)
                        .setHardTimeout(300)
                        .setPriority(1000)
                        .build();
                dstSw.write(fmDst);
            }
        }
        // Instalar ruta de regreso
        Route reverseRoute = null;
        try {
            reverseRoute = routingService.getRoute(dstDpid, dstAttachPort, srcDpid, srcAttachPort, U64.of(0));
        } catch (Throwable e) {
            log.warn("Error calculando ruta de regreso desde " + effectiveDstIp + ": " + e.getMessage());
            reverseRoute = null;
        }
        if (reverseRoute != null) {
            List<NodePortTuple> reversePath = reverseRoute.getPath();
            Match.Builder mbRev = sw.getOFFactory().buildMatch();
            mbRev.setExact(MatchField.ETH_TYPE, EthType.IPv4)
                 .setExact(MatchField.IP_PROTO, proto)
                 .setExact(MatchField.IPV4_DST, IPv4Address.of(srcIp));
            if (!effectiveDstIp.equals(GATEWAY_IP)) {
                mbRev.setExact(MatchField.IPV4_SRC, matchDstAddr);
            }
            if (dstTransportPort != null && proto != IpProtocol.ICMP) {
                if (proto == IpProtocol.TCP) {
                    mbRev.setExact(MatchField.TCP_SRC, dstTransportPort);
                } else if (proto == IpProtocol.UDP) {
                    mbRev.setExact(MatchField.UDP_SRC, dstTransportPort);
                }
            }
            Match matchRev = mbRev.build();
            for (int i = 0; i < reversePath.size(); i += 2) {
                NodePortTuple npt = reversePath.get(i);
                IOFSwitch s = switchService.getSwitch(npt.getNodeId());
                if (s == null) continue;
                OFPort outPort = reversePath.get(i + 1).getPortId();
                List<OFAction> actions = new ArrayList<>();
                actions.add(s.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(0xffff).build());
                OFFlowMod fm = s.getOFFactory().buildFlowAdd()
                        .setMatch(matchRev)
                        .setActions(actions)
                        .setIdleTimeout(60)
                        .setHardTimeout(300)
                        .setPriority(1000)
                        .build();
                s.write(fm);
            }
            // Install on source switch for return if multi-hop
            if (!reversePath.isEmpty()) {
                IOFSwitch srcSw = switchService.getSwitch(srcDpid);
                if (srcSw != null) {
                    NodePortTuple lastNpt = reversePath.get(reversePath.size() - 1);
                    Match.Builder mbSrc = srcSw.getOFFactory().buildMatch();
                    mbSrc.setExact(MatchField.IN_PORT, lastNpt.getPortId())
                         .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                         .setExact(MatchField.IP_PROTO, proto)
                         .setExact(MatchField.IPV4_DST, IPv4Address.of(srcIp));
                    if (!effectiveDstIp.equals(GATEWAY_IP)) {
                        mbSrc.setExact(MatchField.IPV4_SRC, matchDstAddr);
                    }
                    if (dstTransportPort != null && proto != IpProtocol.ICMP) {
                        if (proto == IpProtocol.TCP) {
                            mbSrc.setExact(MatchField.TCP_SRC, dstTransportPort);
                        } else if (proto == IpProtocol.UDP) {
                            mbSrc.setExact(MatchField.UDP_SRC, dstTransportPort);
                        }
                    }
                    OFFlowMod fmSrc = srcSw.getOFFactory().buildFlowAdd()
                            .setMatch(mbSrc.build())
                            .setActions(Collections.singletonList(
                                    srcSw.getOFFactory().actions().buildOutput()
                                            .setPort(srcAttachPort)
                                            .setMaxLen(0xffff)
                                            .build()))
                            .setIdleTimeout(60)
                            .setHardTimeout(300)
                            .setPriority(1000)
                            .build();
                    srcSw.write(fmSrc);
                }
            }
        } else {
            // Si no hay ruta de regreso, instalar regla de entrega en switch fuente para el retorno
            Match.Builder mbRev = sw.getOFFactory().buildMatch();
            mbRev.setExact(MatchField.ETH_TYPE, EthType.IPv4)
                 .setExact(MatchField.IP_PROTO, proto)
                 .setExact(MatchField.IPV4_DST, IPv4Address.of(srcIp));
            if (!effectiveDstIp.equals(GATEWAY_IP)) {
                mbRev.setExact(MatchField.IPV4_SRC, matchDstAddr);
            }
            if (dstTransportPort != null && proto != IpProtocol.ICMP) {
                if (proto == IpProtocol.TCP) {
                    mbRev.setExact(MatchField.TCP_SRC, dstTransportPort);
                } else if (proto == IpProtocol.UDP) {
                    mbRev.setExact(MatchField.UDP_SRC, dstTransportPort);
                }
            }
            OFFlowMod fmRev = sw.getOFFactory().buildFlowAdd()
                    .setMatch(mbRev.build())
                    .setActions(Collections.singletonList(
                            sw.getOFFactory().actions().buildOutput()
                                    .setPort(srcAttachPort)
                                    .setMaxLen(0xffff)
                                    .build()))
                    .setIdleTimeout(60)
                    .setHardTimeout(300)
                    .setPriority(1000)
                    .build();
            sw.write(fmRev);
        }
        OFPort outPort = forwardPath.isEmpty() ? dstAttachPort : forwardPath.get(0).getPortId();
        OFPacketOut po = sw.getOFFactory().buildPacketOut()
                .setInPort(inPort)
                .setActions(Collections.singletonList(
                        sw.getOFFactory().actions().buildOutput()
                                .setPort(outPort)
                                .setMaxLen(0xffff)
                                .build()))
                .setData(pi.getBufferId() == OFBufferId.NO_BUFFER ? eth.serialize() : new byte[0])
                .setBufferId(pi.getBufferId())
                .build();
        sw.write(po);
    }

    private void handleNoRoute(IOFSwitch sw, OFPacketIn pi, Ethernet eth, String srcIp, IPv4Address matchDstAddr, IpProtocol proto, TransportPort srcTransportPort, TransportPort dstTransportPort, DatapathId dstDpid, OFPort dstAttachPort, OFPort inPort, boolean isToGateway) {
        IOFSwitch dstSwitch = switchService.getSwitch(dstDpid);
        if (dstSwitch != null) {
            OFFactory df = dstSwitch.getOFFactory();
            Match.Builder mbFwd = df.buildMatch();
            mbFwd.setExact(MatchField.ETH_TYPE, EthType.IPv4)
                 .setExact(MatchField.IP_PROTO, proto)
                 .setExact(MatchField.IPV4_SRC, IPv4Address.of(srcIp));
            if (!isToGateway) {
                mbFwd.setExact(MatchField.IPV4_DST, matchDstAddr);
            }
            if (dstTransportPort != null && proto != IpProtocol.ICMP) {
                if (proto == IpProtocol.TCP) {
                    mbFwd.setExact(MatchField.TCP_DST, dstTransportPort);
                } else if (proto == IpProtocol.UDP) {
                    mbFwd.setExact(MatchField.UDP_DST, dstTransportPort);
                }
            }
            List<OFAction> actions = new ArrayList<>();
            actions.add(df.actions().buildOutput().setPort(dstAttachPort).setMaxLen(0xffff).build());
            if (isToGateway) {
                actions.add(df.actions().buildOutput().setPort(MIRROR_PORT).setMaxLen(0xffff).build());
            }
            OFFlowMod fm = df.buildFlowAdd()
                    .setMatch(mbFwd.build())
                    .setActions(actions)
                    .setIdleTimeout(60)
                    .setHardTimeout(300)
                    .setPriority(1000)
                    .build();
            dstSwitch.write(fm);
            log.info("Regla instalada directamente en switch destino " + dstDpid + " para " + matchDstAddr + " -> puerto " + dstAttachPort);
        } else {
            log.warn("No se encontró switch destino " + dstDpid + " para instalar regla directa.");
        }
        // Instalar regla de regreso en switch fuente
        Match.Builder mbRev = sw.getOFFactory().buildMatch();
        mbRev.setExact(MatchField.ETH_TYPE, EthType.IPv4)
             .setExact(MatchField.IP_PROTO, proto)
             .setExact(MatchField.IPV4_DST, IPv4Address.of(srcIp));
        if (!isToGateway) {
            mbRev.setExact(MatchField.IPV4_SRC, matchDstAddr);
        }
        if (dstTransportPort != null && proto != IpProtocol.ICMP) {
            if (proto == IpProtocol.TCP) {
                mbRev.setExact(MatchField.TCP_SRC, dstTransportPort);
            } else if (proto == IpProtocol.UDP) {
                mbRev.setExact(MatchField.UDP_SRC, dstTransportPort);
            }
        }
        OFFlowMod fmRev = sw.getOFFactory().buildFlowAdd()
                .setMatch(mbRev.build())
                .setActions(Collections.singletonList(
                        sw.getOFFactory().actions().buildOutput()
                                .setPort(inPort)
                                .setMaxLen(0xffff)
                                .build()))
                .setIdleTimeout(60)
                .setHardTimeout(300)
                .setPriority(1000)
                .build();
        sw.write(fmRev);
        floodPacket(sw, pi, eth, inPort);
    }

    private void floodPacket(IOFSwitch sw, OFPacketIn pi, Ethernet eth, OFPort inPort) {
        OFPacketOut po = sw.getOFFactory().buildPacketOut()
                .setBufferId(pi.getBufferId())
                .setInPort(inPort)
                .setActions(Collections.singletonList(
                        sw.getOFFactory().actions().buildOutput()
                                .setPort(OFPort.FLOOD)
                                .build()))
                .setData(pi.getBufferId() == OFBufferId.NO_BUFFER ? eth.serialize() : new byte[0])
                .build();
        sw.write(po);
    }

    private void handleAuthPacket(IOFSwitch sw, OFPacketIn pi, Ethernet eth, IPv4 ip, UDP udp) {
        byte[] payload = (udp.getPayload() instanceof Data)
                ? ((Data) udp.getPayload()).getData()
                : udp.getPayload().serialize();
        try {
            byte[] decrypted = decryptAES(payload);
            @SuppressWarnings("unchecked")
            Map<String, String> map = json.readValue(new String(decrypted, "UTF-8").trim(), Map.class);
            String dpid = sw.getId().toString();
            OFPort inPort = pi.getMatch().get(MatchField.IN_PORT);
            MacAddress mac = eth.getSourceMACAddress();
            String srcIp = ip.getSourceAddress().toString();
            if ("deauth".equals(map.get("action"))) {
                removeUserFlows(dpid, inPort, mac, srcIp);
                removeUserContextFromYaml(mac.toString());
                return;
            }
            String user = map.get("user");
            String pass = map.get("pass");
            if (user != null && pass != null && userPasswords.containsKey(user) && userPasswords.get(user).equals(pass)) {
                addUserContextToYaml(user, dpid, inPort, mac.toString(), srcIp);
                installAuthUserFlow(sw, inPort, mac);
                log.info("Autenticación EXITOSA: " + user);
            } else {
                log.warn("Autenticación FALLIDA para " + user);
            }
        } catch (Exception e) {
            log.error("Error en autenticación", e);
        }
    }

    private void removeUserFlows(String dpid, OFPort inPort, MacAddress mac, String ip) {
        IOFSwitch sw = switchService.getSwitch(DatapathId.of(dpid));
        if (sw == null) return;
        Match.Builder mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.ETH_SRC, mac);
        OFFlowDelete fd = sw.getOFFactory().buildFlowDelete()
                .setMatch(mb.build())
                .build();
        sw.write(fd);
        if (ip != null && !ip.equals("0.0.0.0")) {
            Match.Builder mbIp = sw.getOFFactory().buildMatch();
            mbIp.setExact(MatchField.IPV4_SRC, IPv4Address.of(ip));
            OFFlowDelete fdIp = sw.getOFFactory().buildFlowDelete()
                    .setMatch(mbIp.build())
                    .build();
            sw.write(fdIp);
        }
        log.info("Flows eliminados para usuario desautenticado: mac=" + mac + ", ip=" + ip);
    }

    private void installAuthUserFlow(IOFSwitch sw, OFPort inPort, MacAddress mac) {
        OFFactory factory = sw.getOFFactory();
        Match match = factory.buildMatch()
                .setExact(MatchField.IN_PORT, inPort)
                .setExact(MatchField.ETH_SRC, mac)
                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                .build();
        OFFlowMod fm = factory.buildFlowAdd()
                .setMatch(match)
                .setActions(Collections.singletonList(
                        factory.actions().buildOutput()
                                .setPort(OFPort.CONTROLLER)
                                .setMaxLen(0xffff)
                                .build()))
                .setPriority(5)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .build();
        sw.write(fm);
    }

    private void addUserContextToYaml(String user, String dpid, OFPort inPort, String mac, String ip) {
        try {
            Map<String, Object> data = yamlMapper.readValue(new File("config.yaml"), Map.class);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> ctx = (List<Map<String, Object>>) data.get("contexto_usuarios");
            if (ctx == null) {
                ctx = new ArrayList<>();
                data.put("contexto_usuarios", ctx);
            }
            Map<String, Object> entry = new HashMap<>();
            entry.put("usuario", user);
            entry.put("dpid", dpid);
            entry.put("puerto", inPort.getPortNumber());
            entry.put("mac", mac);
            entry.put("ip", ip);
            ctx.add(entry);
            yamlMapper.writeValue(new File("config.yaml"), data);
            configData = data;
        } catch (Exception e) {
            log.error("Error guardando contexto", e);
        }
    }

    private void removeUserContextFromYaml(String mac) {
        try {
            Map<String, Object> data = yamlMapper.readValue(new File("config.yaml"), Map.class);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> ctx = (List<Map<String, Object>>) data.get("contexto_usuarios");
            if (ctx != null) {
                ctx.removeIf(e -> mac.equals(e.get("mac")));
                if (ctx.isEmpty()) data.remove("contexto_usuarios");
                yamlMapper.writeValue(new File("config.yaml"), data);
                configData = data;
            }
        } catch (Exception e) {
            log.error("Error removiendo contexto", e);
        }
    }

    private void cleanupYaml() {
        try {
            Map<String, Object> data = yamlMapper.readValue(new File("config.yaml"), Map.class);
            data.remove("contexto_usuarios");
            yamlMapper.writeValue(new File("config.yaml"), data);
            log.info("contexto_usuarios eliminado al apagar");
        } catch (Exception e) {
            log.error("Error en cleanup", e);
        }
    }

    private byte[] decryptAES(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(AES_KEY, "AES");
        IvParameterSpec iv = new IvParameterSpec(AES_IV);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    private void installDefaultFlows(IOFSwitch sw) {
        OFFactory factory = sw.getOFFactory();

        OFFlowMod lldp = factory.buildFlowAdd()
                .setMatch(factory.buildMatch()
                        .setExact(MatchField.ETH_TYPE, EthType.LLDP)
                        .build())
                .setActions(Collections.singletonList(
                        factory.actions().buildOutput()
                                .setPort(OFPort.CONTROLLER)
                                .setMaxLen(0xffff)
                                .build()))
                .setPriority(10)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .build();
        sw.write(lldp);

        OFFlowMod bddp = factory.buildFlowAdd()
                .setMatch(factory.buildMatch()
                        .setExact(MatchField.ETH_TYPE, EthType.of(0x8942))
                        .build())
                .setActions(Collections.singletonList(
                        factory.actions().buildOutput()
                                .setPort(OFPort.CONTROLLER)
                                .setMaxLen(0xffff)
                                .build()))
                .setPriority(10)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .build();
        sw.write(bddp);

        OFFlowMod arp = factory.buildFlowAdd()
                .setMatch(factory.buildMatch()
                        .setExact(MatchField.ETH_TYPE, EthType.ARP)
                        .build())
                .setActions(Collections.singletonList(
                        factory.actions().buildOutput()
                                .setPort(OFPort.FLOOD)
                                .build()))
                .setPriority(10)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .build();
        sw.write(arp);

        OFFlowMod dhcpClient = factory.buildFlowAdd()
                .setMatch(factory.buildMatch()
                        .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                        .setExact(MatchField.IP_PROTO, IpProtocol.UDP)
                        .setExact(MatchField.UDP_SRC, TransportPort.of(68))
                        .setExact(MatchField.UDP_DST, TransportPort.of(67))
                        .build())
                .setActions(Collections.singletonList(
                        factory.actions().buildOutput()
                                .setPort(OFPort.NORMAL)
                                .setMaxLen(0xffff)
                                .build()))
                .setPriority(10)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .build();
        sw.write(dhcpClient);

        OFFlowMod dhcpServer = factory.buildFlowAdd()
                .setMatch(factory.buildMatch()
                        .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                        .setExact(MatchField.IP_PROTO, IpProtocol.UDP)
                        .setExact(MatchField.UDP_SRC, TransportPort.of(67))
                        .setExact(MatchField.UDP_DST, TransportPort.of(68))
                        .build())
                .setActions(Collections.singletonList(
                        factory.actions().buildOutput()
                                .setPort(OFPort.NORMAL)
                                .setMaxLen(0xffff)
                                .build()))
                .setPriority(10)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .build();
        sw.write(dhcpServer);

        OFFlowMod mdns = factory.buildFlowAdd()
                .setMatch(factory.buildMatch()
                        .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                        .setExact(MatchField.IP_PROTO, IpProtocol.UDP)
                        .setExact(MatchField.UDP_DST, TransportPort.of(5353))
                        .build())
                .setActions(Collections.singletonList(
                        factory.actions().buildOutput()
                                .setPort(OFPort.NORMAL)
                                .setMaxLen(0xffff)
                                .build()))
                .setPriority(10)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .build();
        sw.write(mdns);

        OFFlowMod igmp = factory.buildFlowAdd()
                .setMatch(factory.buildMatch()
                        .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                        .setExact(MatchField.IP_PROTO, IpProtocol.IGMP)
                        .build())
                .setActions(Collections.singletonList(
                        factory.actions().buildOutput()
                                .setPort(OFPort.NORMAL)
                                .setMaxLen(0xffff)
                                .build()))
                .setPriority(10)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .build();
        sw.write(igmp);

        OFFlowMod auth = factory.buildFlowAdd()
                .setMatch(factory.buildMatch()
                        .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                        .setExact(MatchField.IP_PROTO, IpProtocol.UDP)
                        .setExact(MatchField.IPV4_DST, IPv4Address.of("10.33.0.7"))
                        .setExact(MatchField.UDP_DST, TransportPort.of(AUTH_PORT))
                        .build())
                .setActions(Collections.singletonList(
                        factory.actions().buildOutput()
                                .setPort(OFPort.CONTROLLER)
                                .setMaxLen(0xffff)
                                .build()))
                .setPriority(20)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .build();
        sw.write(auth);

        OFFlowMod miss = factory.buildFlowAdd()
                .setMatch(factory.buildMatch().build())
                .setActions(Collections.singletonList(
                        factory.actions().buildOutput()
                                .setPort(OFPort.CONTROLLER)
                                .setMaxLen(0xffff)
                                .build()))
                .setPriority(0)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .build();
        sw.write(miss);

        if (sw.getId().equals(GATEWAY_DPID)) {
            // Flow para IDS -> Controlador
            Match.Builder mbIdsToCtrl = factory.buildMatch();
            mbIdsToCtrl.setExact(MatchField.ETH_TYPE, EthType.IPv4)
                       .setExact(MatchField.IPV4_SRC, IPv4Address.of(IDS_IP))
                       .setExact(MatchField.IPV4_DST, IPv4Address.of(CONTROLLER_IP));
            OFFlowMod fmIdsToCtrl = factory.buildFlowAdd()
                    .setMatch(mbIdsToCtrl.build())
                    .setActions(Collections.singletonList(
                            factory.actions().buildOutput()
                                    .setPort(CONTROLLER_PORT)
                                    .setMaxLen(0xffff)
                                    .build()))
                    .setPriority(100)
                    .setIdleTimeout(0)
                    .setHardTimeout(0)
                    .build();
            sw.write(fmIdsToCtrl);

            // Flow para Controlador -> IDS
            Match.Builder mbCtrlToIds = factory.buildMatch();
            mbCtrlToIds.setExact(MatchField.ETH_TYPE, EthType.IPv4)
                       .setExact(MatchField.IPV4_SRC, IPv4Address.of(CONTROLLER_IP))
                       .setExact(MatchField.IPV4_DST, IPv4Address.of(IDS_IP));
            OFFlowMod fmCtrlToIds = factory.buildFlowAdd()
                    .setMatch(mbCtrlToIds.build())
                    .setActions(Collections.singletonList(
                            factory.actions().buildOutput()
                                    .setPort(MIRROR_PORT)
                                    .setMaxLen(0xffff)
                                    .build()))
                    .setPriority(100)
                    .setIdleTimeout(0)
                    .setHardTimeout(0)
                    .build();
            sw.write(fmCtrlToIds);
            log.info("Flows permanentes instalados para IDS <-> Controlador en switch " + GATEWAY_DPID);
        }
    }

    @Override
    public void switchAdded(DatapathId switchId) {
        IOFSwitch sw = switchService.getSwitch(switchId);
        if (sw != null) {
            installDefaultFlows(sw);
        }
    }

    @Override
    public void switchRemoved(DatapathId switchId) {}

    @Override
    public void switchActivated(DatapathId switchId) {}

    @Override
    public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {}

    @Override
    public void switchChanged(DatapathId switchId) {}

    @Override public boolean isCallbackOrderingPrereq(OFType type, String name) { return false; }

    @Override public boolean isCallbackOrderingPostreq(OFType type, String name) { return false; }

    @Override public Collection<Class<? extends IFloodlightService>> getModuleServices() { return null; }

    @Override public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() { return null; }
}
//////base de datos de prueba/////
{"usuarios":[{"nombre":"marco","codigo":20012482,"rol":"superadmin","estado":"activo","puerto_10.33.0.6":8085,"contrasena":"marco123"},{"nombre":"max","codigo":20041321,"rol":"alumno","puerto_10.33.0.6":8085,"estado":"activo","contrasena":"max123"},{"nombre":"dani","codigo":20080621,"rol":"alumno","puerto_10.33.0.6":8086,"estado":"activo","contrasena":"dani123"},{"nombre":"juan","codigo":20080622,"rol":"alumno","puerto_10.33.0.6":8084,"estado":"activo","contrasena":"juan123"},{"nombre":"mica","codigo":20080623,"rol":"alumno","puerto_10.33.0.6":8087,"estado":"baneado","contrasena":"mica123"},{"nombre":"cris","codigo":20080624,"rol":"docente","estado":"activo","contrasena":"cris123"},{"nombre":"fer","codigo":20080625,"rol":"docente","estado":"activo","contrasena":"fer123"}],"cursos":[{"nombre":"sdn","estado":"DICTANDO","alumnos":[20012482,20041321,20080625],"servidores":[{"nombre":"recursos","servicios_permitidos":[{"puerto_web":8081}]}]},{"nombre":"inalambrica","estado":"INACTIVO","alumnos":[20080621,20080622,20080624],"servidores":[{"nombre":"recursos","servicios_permitidos":[{"puerto_web":8082}]}]},{"nombre":"trafico","estado":"DICTANDO","alumnos":[20080623,20080624,20080625],"servidores":[{"nombre":"recursos","servicios_permitidos":[{"puerto_web":8083}]}]}],"servidores":[{"nombre":"recursos","ip":"10.33.0.6","mac":"fa:16:3e:06:cb:e4","puertos":["ssh",8081,8082,8083,8084,8085,8086,8087,8088]},{"nombre":"radius","ip":"10.33.0.7","mac":"fa:16:3e:95:58:da","puertos":["ssh"]},{"nombre":"ids","ip":"10.33.0.8","mac":"fa:16:3e:d2:13:7d","puertos":["ssh"]},{"nombre":"controlador","ip":"192.168.200.200","mac":"fa:16:3e:87:a4:00","puertos":["ssh"]}],"roles":[{"nombre":"alumno"},{"nombre":"docente","puerto_10.33.0.6":8088},{"nombre":"admin"},{"nombre":"superadmin"},{"nombre":"invitado"}]}
/////reglas del suricata para pruebas////////
 alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ALERTA: Tráfico ICMP Detectado"; classtype:misc-activity; sid:1000001; rev:1;)
# Grupo 1 (SID 1000100)
alert ip $HOME_NET any -> [1.116.180.98,1.117.17.164,1.119.194.226] any (msg:"ALERTA: CINS Saliente (G1)"; classtype:trojan-activity; sid:1000100; rev:1;)
# Grupo 2 (SID 1000101)
alert ip $HOME_NET any -> [1.15.118.23,1.159.95.168,1.213.196.20] any (msg:"ALERTA: CINS Saliente (G2)"; classtype:trojan-activity; sid:1000101; rev:1;)
# Grupo 3 (SID 1000102)
alert ip $HOME_NET any -> [1.222.72.173,1.223.87.38,1.24.16.103] any (msg:"ALERTA: CINS Saliente (G3)"; classtype:trojan-activity; sid:1000102; rev:1;)
# Grupo 4 (SID 1000103)
alert ip $HOME_NET any -> [1.24.16.104,1.24.16.110,1.24.16.113] any (msg:"ALERTA: CINS Saliente (G4)"; classtype:trojan-activity; sid:1000103; rev:1;)
# Grupo 5 (SID 1000104)
alert ip $HOME_NET any -> [1.24.16.129,1.24.16.132,1.24.16.133] any (msg:"ALERTA: CINS Saliente (G5)"; classtype:trojan-activity; sid:1000104; rev:1;)
# Grupo 6 (SID 1000105)
alert ip $HOME_NET any -> [1.24.16.155,1.24.16.156,1.24.16.210] any (msg:"ALERTA: CINS Saliente (G6)"; classtype:trojan-activity; sid:1000105; rev:1;)
# Grupo 7 (SID 1000106)
alert ip $HOME_NET any -> [1.24.16.222,1.24.16.226,1.24.16.229] any (msg:"ALERTA: CINS Saliente (G7)"; classtype:trojan-activity; sid:1000106; rev:1;)
# Grupo 8 (SID 1000107)
alert ip $HOME_NET any -> [1.24.16.233,1.24.16.239,1.24.16.253] any (msg:"ALERTA: CINS Saliente (G8)"; classtype:trojan-activity; sid:1000107; rev:1;)
# Grupo 9 (SID 1000108)
alert ip $HOME_NET any -> [1.24.16.30,1.24.16.49,1.24.16.51] any (msg:"ALERTA: CINS Saliente (G9)"; classtype:trojan-activity; sid:1000108; rev:1;)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  
/////autenticación para pruebas/////#!/usr/bin/env python3
import socket
import sys
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ==========================
# CONFIGURACIÓN
# ==========================
RADIUS_INTERCEPT_IP = "10.33.0.7"   # Destino del paquete UDP
RADIUS_INTERCEPT_PORT = 10000       # Puerto que tu switch interceptará
AES_KEY = b"12345678901234567890123456789012"  # 32 bytes (AES-256)
AES_IV  = b"abcdefghijklmnop"                   # 16 bytes

# ==========================
# SCRIPT
# ==========================
def encrypt(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data.encode(), AES.block_size))

def main():
    if len(sys.argv) != 3:
        print("Uso: auth_client.py <usuario> <contraseña>")
        exit(1)

    usuario = sys.argv[1]
    password = sys.argv[2]

    payload = json.dumps({
        "user": usuario,
        "pass": password
    })

    encrypted = encrypt(payload)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(encrypted, (RADIUS_INTERCEPT_IP, RADIUS_INTERCEPT_PORT))
    print("[OK] Paquete de autenticación enviado.")

if __name__ == "__main__":
    main()
 /////desautenticación pra pruebas/////                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  
#!/usr/bin/env python3
import socket
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ==========================
# CONFIGURACIÓN
# ==========================
radius="10.33.0.7"
AUTH_PORT = 10000                  # Puerto para autenticación/desautenticación
AES_KEY = b"12345678901234567890123456789012"  # 32 bytes (AES-256)
AES_IV  = b"abcdefghijklmnop"                   # 16 bytes

# ==========================
# FUNCIONES
# ==========================
def encrypt(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data.encode(), AES.block_size))

def main():
    payload = json.dumps({
        "action": "deauth"
    })

    encrypted = encrypt(payload)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(encrypted, (radius, AUTH_PORT))
    print("[OK] Paquete de desautenticación enviado.")

if __name__ == "__main__":
    main()
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          
