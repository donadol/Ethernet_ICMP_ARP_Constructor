package constructor.ethernet;

import java.io.IOException;
import java.util.List;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.NifSelector;

public class Sender {
	private EthernetPacket packet;
	private PcapHandle handle;
	private PcapHandle sendHandle;

	private static final int READ_TIMEOUT = 10; // [ms]

	private static final int SNAPLEN = 65536; // [bytes]


	public Sender(EthernetPacket msg) throws PcapNativeException {
		this.packet=msg;
		List<PcapNetworkInterface> devices;
		PcapNetworkInterface nif;
		devices=Pcaps.findAllDevs();
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

		System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

		handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
		sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
	}
	public void sendMessage() throws PcapNativeException, NotOpenException {

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
