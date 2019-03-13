package constructor.ethernet;

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

	public ARP(short hwtype, short protype, short hwsize, short prosize, short opcode, String macSender, String ipSender, String macTarget, String ipTarget) {
		this.ar$hrd=Utils.shortToByteArray(hwtype);
		this.ar$pro=Utils.shortToByteArray(protype);
		this.ar$hln=Utils.shortToByte(hwsize);
		this.ar$pln=Utils.shortToByte(prosize);
		this.ar$op=Utils.shortToByteArray(opcode);
		this.ar$sha=Utils.hexStringToByteArray(Utils.clean(macSender,":"), ar$hln);
		this.ar$spa=Utils.StringToByteArray(ipSender, "\\.", ar$pln);
		this.ar$tha=Utils.hexStringToByteArray(Utils.clean(macTarget,":"), ar$hln);
		this.ar$tpa=Utils.StringToByteArray(ipTarget, "\\.", ar$pln);
	}
	public byte[] constructARPMessage() {
		byte[] msg = new byte[28];
		System.arraycopy(ar$hrd, 0, msg, 0, ar$hrd.length);
		System.arraycopy(ar$pro, 0, msg, ar$hrd.length, ar$pro.length);
		System.arraycopy(ar$hln, 0, msg, ar$hrd.length+ar$pro.length, 1);
		System.arraycopy(ar$pln, 0, msg, ar$hrd.length+ar$pro.length+1, 1);
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
		eb.dstAddr(MacAddress.getByAddress(ar$sha))
			.srcAddr(MacAddress.getByAddress(ar$tha))
			.type(EtherType.ARP)
			.payloadBuilder(arp)
			.paddingAtBuild(true);
		return eb.build();
	}
}
