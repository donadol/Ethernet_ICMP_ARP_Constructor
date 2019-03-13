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
	//private short sequenceNumber;

	public IP(String ipO, String ipD, int length, short id, short ttl, String macsrc, String macdst) {
		this.ipsrc=ipO;
		this.ipdst=ipD;
		this.length=length;
		this.identifier = id;
		//this.sequenceNumber = 1;
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
	public Packet createICMP() throws UnknownHostException {
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
			.srcAddr(MacAddress.getByName(macsrc))//poner mac pc
			.type(EtherType.IPV4)
			.payloadBuilder(ipv4b)
			.paddingAtBuild(true);
		return eb.build();
	}
	private byte[] randomMsg(int length) {
		byte[] msg=new byte[length];
		for (int i = 0; i < length; ++i) {
            msg[i] = (byte) (Math.random()* 101);
        }
		return msg;
	}
}
