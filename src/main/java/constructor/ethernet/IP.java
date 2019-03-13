package constructor.ethernet;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;

public class IP {
	private IcmpV4EchoPacket packet;
	private short length;
	private short identifier;
	private short sequenceNumber;
	private String ipsrc;
	private String ipdst;
	private short ttl;

	public IP(String ipO, String ipD, short length, short id, short ttl) {
		this.ipsrc=ipO;
		this.ipdst=ipD;
		this.length=length;
		this.identifier = id;
		this.sequenceNumber = 1;
		this.ttl=ttl;

		UnknownPacket.Builder unknownb = new UnknownPacket.Builder();
		unknownb.rawData(this.randomMsg(this.length));
		IcmpV4EchoPacket.Builder b = new IcmpV4EchoPacket.Builder();
		b.identifier(identifier).sequenceNumber(sequenceNumber).payloadBuilder(unknownb);
		this.packet = b.build();
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
			.identification((short) 1)
			.ttl((byte) ttl)
			.protocol(IpNumber.ICMPV4)
			.srcAddr((Inet4Address)InetAddress.getByAddress(Utils.StringToByteArray(ipsrc, "\\.", 6)))
			.dstAddr((Inet4Address)InetAddress.getByAddress(Utils.StringToByteArray(ipdst, "\\.", 6)))
			.payloadBuilder(icmpV4b)
			.correctChecksumAtBuild(true)
			.correctLengthAtBuild(true)
			.paddingAtBuild(true);

		EthernetPacket.Builder eb = new EthernetPacket.Builder();
		eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
			.srcAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
			.type(EtherType.IPV4)
			.payloadBuilder(ipv4b)
			.paddingAtBuild(true);
		return eb.build();
	}
	private byte[] randomMsg(short length) {
		byte[] msg=new byte[length];
		for (int i = 0; i < length; ++i) {
            msg[i] = (byte) (Math.random()* 101);
        }
		return msg;
	}
}
