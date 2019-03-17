package constructor.ethernet;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;

public class IP {
	private IcmpV4EchoPacket packet;
	private int length;
	private short identifier;
	private String ipsrc;
	private String ipdst;
	private short ttl;
	private static short sequence=1;
	private String macsrc;
	private String macdst;

	/*
	Función: IP (constructor)
	Parámetros de entrada: dirección ip de origen, dirección ip de destino, longitud del mensaje a crear, id del mensaje, 
	tiempo de vida del mensaje, dirección mac de origen y dirección mac de destino
	Valor de salida: un objeto tipo IP
	Descripción: Crea un objeto tipo IP con los datos dados. Para la creación del ICMPV4ECHO, primero se crea un unknown packet 
	cuyos datos se llenan con datos aleatorios del tamaño indicado (length) y este paquete se agrega al campo de datos del ICMP; 
	segundo, de indicador se coloca el indicado (id), y por último de secuencia se coloca sequence (número que indica la cantidad de mensajes enviados)
	*/
	public IP(String ipO, String ipD, int length, short id, short ttl, String macsrc, String macdst) {
		this.ipsrc=ipO;
		this.ipdst=ipD;
		this.length=length;
		this.identifier = id;
		this.ttl=ttl;
		this.macsrc=macsrc;
		this.macdst=macdst;

		UnknownPacket.Builder unknownb = new UnknownPacket.Builder();
		unknownb.rawData(this.randomMsg(this.length));
		IcmpV4EchoPacket.Builder b = new IcmpV4EchoPacket.Builder();
		b.identifier(identifier).sequenceNumber(sequence).payloadBuilder(unknownb);
		this.packet = b.build();
		sequence++;
	}
	/*
	Función: createICMP
	Parámetros de entrada: no tiene.
	Valor de salida: un EthernetPacket que contiene el mensaje ICMP creado (encapsulamiento: ICMP/IP/Ethernet)
	Descripción: Crea un paquete Ethernet, para eso se crea un paquete ICMPv4 de tipo echo, sin código y se utiliza el paquete propio del objeto
	para el campo de datos. Luego, se crea un paquete IPv4 utilizando los datos del objeto, con versión IPV4, protocolo ICMPv4 y de carga se utiliza
	el paquete ICMPv4. Por último, se crea un paquete Ethernet utilizando los datos del objeto, de tipo IPV4 y de carga se utiliza el paquete IPV4.
	*/
	public EthernetPacket createICMP() throws UnknownHostException {
		IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
		icmpV4b
			.type(IcmpV4Type.ECHO)
			.code(IcmpV4Code.NO_CODE)
			.payloadBuilder(new SimpleBuilder(packet))
			.correctChecksumAtBuild(true);

		IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
		ipv4b
			.version(IpVersion.IPV4)
			.tos(IpV4Rfc1349Tos.newInstance((byte) 0))
			.identification((short) identifier)
			.ttl((byte) ttl)
			.protocol(IpNumber.ICMPV4)
			.srcAddr((Inet4Address)InetAddress.getByName(ipsrc))
			.dstAddr((Inet4Address)InetAddress.getByName(ipdst))
			.payloadBuilder(icmpV4b)
			.correctChecksumAtBuild(true)
			.correctLengthAtBuild(true)
			.paddingAtBuild(true);

		EthernetPacket.Builder eb = new EthernetPacket.Builder();
		eb.dstAddr(MacAddress.getByName(macdst))
			.srcAddr(MacAddress.getByName(macsrc))
			.type(EtherType.IPV4)
			.payloadBuilder(ipv4b)
			.paddingAtBuild(true);
		return eb.build();
	}
	/*
	Función: randomMsg
	Parámetros de entrada: tamaño del arreglo a crear.
	Valor de salida: arreglo de bytes
	Descripción: Crea un arreglo de bytes de elemos aleatorios. 
	*/
	private byte[] randomMsg(int length) {
		byte[] msg=new byte[length];
		for (int i = 0; i < length; ++i) {
            msg[i] = (byte) (Math.random()* 101);
        }
		return msg;
	}
}
