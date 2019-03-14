package constructor.ethernet;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

public class ARP {
	byte[] ar$hrd;
	byte[] ar$pro;
	byte   ar$hln;
	byte   ar$pln;
	byte[] ar$op;
	byte[] ar$sha;
	byte[] ar$spa;
	byte[] ar$tha;
	byte[] ar$tpa;

	public ARP(short hwtype, short protype, short hwsize, short prosize, short opcode, String macSender, String ipSender, String macTarget, String ipTarget) throws UnknownHostException {
		this.ar$hrd=Utils.shortToByteArray(hwtype);
		this.ar$pro=Utils.shortToByteArray(protype);
		this.ar$hln=Utils.shortToByte(hwsize);
		this.ar$pln=Utils.shortToByte(prosize);
		this.ar$op=Utils.shortToByteArray(opcode);
		this.ar$sha=MacAddress.getByName(macSender).getAddress();
		this.ar$spa=InetAddress.getByName(ipSender).getAddress();
		this.ar$tha=MacAddress.getByName(macTarget).getAddress();
		this.ar$tpa=InetAddress.getByName(ipTarget).getAddress();
	}
	public byte[] constructARPMessage() {
		byte[] msg = new byte[28];
		System.arraycopy(ar$hrd, 0, msg, 0, ar$hrd.length);
		System.arraycopy(ar$pro, 0, msg, ar$hrd.length, ar$pro.length);
		msg[ar$hrd.length+ar$pro.length]=ar$hln;
		msg[ar$hrd.length+ar$pro.length+1]=ar$pln;
		System.arraycopy(ar$op,  0, msg, ar$hrd.length+ar$pro.length+2, ar$op.length);
		System.arraycopy(ar$sha, 0, msg, ar$hrd.length+ar$pro.length+2+ar$op.length, ar$sha.length);
		System.arraycopy(ar$spa, 0, msg, ar$hrd.length+ar$pro.length+2+ar$op.length+ar$sha.length, ar$spa.length);
		System.arraycopy(ar$tha, 0, msg, ar$hrd.length+ar$pro.length+2+ar$op.length+ar$sha.length+ar$spa.length, ar$tha.length);
		System.arraycopy(ar$tpa, 0, msg, ar$hrd.length+ar$pro.length+2+ar$op.length+ar$sha.length+ar$spa.length+ar$tha.length, ar$tpa.length);
		return msg;
	}
	public Packet createARP() {
		UnknownPacket.Builder arp = new UnknownPacket.Builder();
		arp.rawData(constructARPMessage());
		
		EthernetPacket.Builder eb = new EthernetPacket.Builder();
		eb.dstAddr(MacAddress.getByAddress(ar$tha))
			.srcAddr(MacAddress.getByAddress(ar$sha))
			.type(EtherType.ARP)
			.payloadBuilder(arp)
			.paddingAtBuild(true);
		return eb.build();
	}
}
