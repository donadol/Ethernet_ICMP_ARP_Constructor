package constructor.ethernet;

import java.io.IOException;
import java.util.List;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.LinkLayerAddress;
import org.pcap4j.util.NifSelector;

public class Sender {
	private PcapHandle handle;
	private PcapHandle sendHandle;
	private static PcapNetworkInterface nif;
	private static final String COUNT_KEY = Sender.class.getName() + ".count";
	private static final int COUNT = Integer.getInteger(COUNT_KEY, 1);
	private static final String READ_TIMEOUT_KEY = Sender.class.getName() + ".readTimeout";
	private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]
	private static final String SNAPLEN_KEY = Sender.class.getName() + ".snaplen";
	private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]
	private static byte[] ipSrc;
	private static byte[] macSrc;

	public Sender() throws PcapNativeException {
		List<PcapAddress> ips;
		List<LinkLayerAddress> macs;
		
		//nif = devices.get(0);
		try {
		      nif = new NifSelector().selectNetworkInterface();
		    } catch (IOException e) {
		      e.printStackTrace();
		      return;
		    }
		if (nif == null) {
			return;
		}
		ips=nif.getAddresses();
		ipSrc=ips.get(1).getAddress().getAddress();//1 ipv4
		macs=nif.getLinkLayerAddresses();
		macSrc=macs.get(0).getAddress();
	}
	public void sendMessage(EthernetPacket packet) throws PcapNativeException, NotOpenException {
		handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
		sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
		try {
			sendHandle.sendPacket(packet);
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
			}
		} finally {
			if (handle != null && handle.isOpen()) {
				handle.close();
			}
			if (sendHandle != null && sendHandle.isOpen()) {
				sendHandle.close();
			}
		}
	}
}
