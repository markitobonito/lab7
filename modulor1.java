package net.floodlightcontroller.eaprad;

import java.util.Collection;
import java.util.Map;
import java.util.Collections;
import java.util.List;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.module.*;
import net.floodlightcontroller.packet.*;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.*;
import org.projectfloodlight.openflow.protocol.instruction.*;
import org.projectfloodlight.openflow.protocol.match.*;
import org.projectfloodlight.openflow.types.*;
import org.tinyradius.util.RadiusClient;
import org.tinyradius.packet.AccessRequest;
import org.tinyradius.packet.RadiusPacket;
import org.tinyradius.attribute.RadiusAttribute;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EapRadiusModule implements IFloodlightModule, IOFMessageListener {

    private static final Logger log = LoggerFactory.getLogger(EapRadiusModule.class);

    protected IFloodlightProviderService floodlightProvider;

    // RADIUS
    private static final String RADIUS_HOST = "10.33.0.7";
    private static final String RADIUS_SECRET = "floodlight123";

    // CIFRADO
    private static final byte[] AES_KEY = "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] AES_IV  = "abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII);

    private static final int AUTH_PORT = 10000;

    // <<<=== CAMBIA ESTA IP POR LA DE TU CONTROLADOR (la que sale hacia el RADIUS) ===>>>
    private static final String MY_CONTROLLER_IP = "192.168.200.200";

    private final ObjectMapper json = new ObjectMapper();

    @Override public String getName() { return "EapRadiusModule"; }

    @Override public boolean isCallbackOrderingPrereq(OFType type, String name) { return false; }
    @Override public boolean isCallbackOrderingPostreq(OFType type, String name) { return false; }

    @Override public Collection<Class<? extends IFloodlightService>> getModuleServices() { return null; }
    @Override public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() { return null; }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        return Collections.singletonList(IFloodlightProviderService.class);
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        log.info("EapRadiusModule init complete");
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        log.info("EapRadiusModule started and listening for PACKET_IN");
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

        if (msg.getType() != OFType.PACKET_IN) return Command.CONTINUE;

        OFPacketIn pi = (OFPacketIn) msg;
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        if (eth == null) return Command.CONTINUE;

        if (eth.getEtherType() != EthType.IPv4) return Command.CONTINUE;
        IPv4 ip = (IPv4) eth.getPayload();
        if (ip == null || ip.getProtocol() != IpProtocol.UDP) return Command.CONTINUE;

        UDP udp = (UDP) ip.getPayload();
        if (udp == null) return Command.CONTINUE;
        if (udp.getDestinationPort().getPort() != AUTH_PORT) return Command.CONTINUE;

        byte[] encryptedPayload = udp.getPayload() instanceof Data
                ? ((Data) udp.getPayload()).getData()
                : udp.getPayload().serialize();

        if (encryptedPayload == null || encryptedPayload.length == 0) {
            log.warn("Payload UDP vacío en paquete de autenticación");
            return Command.STOP;
        }

        String jsonCredentials;
        try {
            byte[] decrypted = aes256cbcDecrypt(encryptedPayload, AES_KEY, AES_IV);
            jsonCredentials = new String(decrypted, StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            log.error("Error descifrando payload de autenticación: {}", e.toString());
            return Command.STOP;
        }

        String username, password;
        try {
            @SuppressWarnings("unchecked")
            Map<String,Object> m = json.readValue(jsonCredentials, Map.class);
            Object u = m.get("user");
            Object p = m.get("pass");
            if (u == null || p == null) {
                log.warn("JSON no contiene user/pass: {}", jsonCredentials);
                return Command.STOP;
            }
            username = String.valueOf(u);
            password = String.valueOf(p);
        } catch (Exception e) {
            log.error("JSON inválido en payload descifrado: {}", e.toString());
            return Command.STOP;
        }

        log.info("Autenticación recibida desde MAC {}: user='{}'", eth.getSourceMACAddress(), username);

        // ====================== RADIUS REQUEST QUE SÍ FUNCIONA ======================
        try {
            RadiusClient rc = new RadiusClient(RADIUS_HOST, RADIUS_SECRET);

            // TinyRadius 1.1.3: constructor sin secret → lo añadimos manualmente
            AccessRequest ar = new AccessRequest(username, password);

            // Atributos obligatorios para que FreeRADIUS no descarte el paquete
            ar.addAttribute(new org.tinyradius.attribute.StringAttribute(1, username));           // User-Name (ya está, pero por si acaso)
            ar.addAttribute(new org.tinyradius.attribute.StringAttribute(2, password));           // User-Password (se cifra con secret)
            ar.addAttribute(new org.tinyradius.attribute.IpAttribute(4, MY_CONTROLLER_IP));       // NAS-IP-Address ← CLAVE
            ar.addAttribute(new org.tinyradius.attribute.StringAttribute(31, eth.getSourceMACAddress().toString())); // Calling-Station-Id
            ar.addAttribute(new org.tinyradius.attribute.IntegerAttribute(5, 0));                 // NAS-Port
            ar.addAttribute(new org.tinyradius.attribute.IntegerAttribute(6, 2));                 // Service-Type = Framed

            RadiusPacket response = rc.authenticate(ar);

            if (response.getPacketType() == RadiusPacket.ACCESS_ACCEPT) {
                log.info("RADIUS aceptó a usuario '{}', instalando flujo para MAC {}", username, eth.getSourceMACAddress());
                OFPort inPort = pi.getMatch().get(MatchField.IN_PORT);
                allowHost(sw, eth.getSourceMACAddress(), inPort);
            } else {
                log.warn("RADIUS rechazó a usuario '{}' (tipo {})", username, response.getPacketType());
            }
        } catch (Exception e) {
            log.error("Error contactando RADIUS: {}", e.toString());
        }

        return Command.STOP;
    }

    private void allowHost(IOFSwitch sw, MacAddress mac, OFPort inPort) {
        OFFactory ofFactory = sw.getOFFactory();

        Match match = ofFactory.buildMatch()
                .setExact(MatchField.ETH_SRC, mac)
                .setExact(MatchField.IN_PORT, inPort)
                .build();

        OFActionOutput out = ofFactory.actions().buildOutput()
                .setPort(OFPort.NORMAL)
                .setMaxLen(0xffff)
                .build();

        List<OFAction> actions = Collections.singletonList((OFAction) out);
        OFInstructionApplyActions apply = ofFactory.instructions().applyActions(actions);

        OFFlowAdd flowAdd = ofFactory.buildFlowAdd()
                .setMatch(match)
                .setInstructions(Collections.singletonList((OFInstruction) apply))
                .setPriority(200)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .setBufferId(OFBufferId.NO_BUFFER)
                .build();

        sw.write(flowAdd);
        log.info("FlowAdd enviado al switch {} para MAC {}", sw.getId(), mac.toString());
    }

    private static byte[] aes256cbcDecrypt(byte[] cipherText, byte[] key, byte[] iv) throws Exception {
        if (key.length != 32) throw new IllegalArgumentException("Key must be 32 bytes for AES-256");
        if (iv.length != 16) throw new IllegalArgumentException("IV must be 16 bytes");

        SecretKeySpec skey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, skey, ivspec);
        return cipher.doFinal(cipherText);
    }
}