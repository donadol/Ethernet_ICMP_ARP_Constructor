package constructor.ethernet;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.LinkLayerAddress;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;
import org.pcap4j.packet.AbstractPacket.AbstractBuilder;

public class Sender {
	private PcapHandle handle;
	private PcapHandle sendHandle;
	private static ExecutorService pool;
	private static PcapNetworkInterface nif;
	private static PacketListener listener;
	private static final String COUNT_KEY = Sender.class.getName() + ".count";
	private static final int COUNT = Integer.getInteger(COUNT_KEY, 1);
	private static final String READ_TIMEOUT_KEY = Sender.class.getName() + ".readTimeout";
	private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]
	private static final String SNAPLEN_KEY = Sender.class.getName() + ".snaplen";
	private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]
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
		handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
		sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
		pool = Executors.newSingleThreadExecutor();
		listener =
				new PacketListener() {
			public void gotPacket(Packet p) {}
		};
	}
	public void sendMessage(EthernetPacket packet) throws PcapNativeException {
		try {
			Task t = new Task(handle, listener);
			pool.execute(t);
			sendHandle.sendPacket(packet);
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (handle != null && handle.isOpen()) {
				try {
					handle.breakLoop();
				} catch (NotOpenException noe) {
				}
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
				}
				handle.close();
			}
			if (sendHandle != null && sendHandle.isOpen()) {
				sendHandle.close();
			}
			if (pool != null && !pool.isShutdown()) {
				pool.shutdown();
			}
		}
	}
	public void sendMessage(IpV4Packet.Builder packet, String macsrc, String macdst, IcmpV4EchoPacket.Builder echoPacket) throws PcapNativeException, NotOpenException {
		try {
			handle.setFilter(
					"icmp and ether dst " + Pcaps.toBpfString(MacAddress.getByName(macsrc)), BpfCompileMode.OPTIMIZE);

			Task t = new Task(handle, listener);
			pool.execute(t);

			EthernetPacket.Builder eb = new EthernetPacket.Builder();
			eb
			.dstAddr(MacAddress.getByName(macdst))
			.srcAddr(MacAddress.getByName(macsrc))
			.type(EtherType.IPV4)
			.paddingAtBuild(true);
			for (short i = 0; i < COUNT; i++) {
				echoPacket.sequenceNumber(i);
				packet.identification((short) i);

				for (final Packet ipV4Packet : IpV4Helper.fragment(packet.build(), 1480)) {
					eb.payloadBuilder(
							new AbstractBuilder() {
								public Packet build() {
									return ipV4Packet;
								}
							});

					sendHandle.sendPacket(eb.build());

					try {
						Thread.sleep(100);
					} catch (InterruptedException e) {
						break;
					}
				}

				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (handle != null && handle.isOpen()) {
				try {
					handle.breakLoop();
				} catch (NotOpenException noe) {
				}
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
				}
				handle.close();
			}
			if (sendHandle != null && sendHandle.isOpen()) {
				sendHandle.close();
			}
			if (pool != null && !pool.isShutdown()) {
				pool.shutdown();
			}
		}
	}
	private static class Task implements Runnable {

		private PcapHandle handle;
		private PacketListener listener;

		public Task(PcapHandle handle, PacketListener listener) {
			this.handle = handle;
			this.listener = listener;
		}

		public void run() {
			try {
				handle.loop(-1, listener);
			} catch (PcapNativeException e) {
				e.printStackTrace();
			} catch (InterruptedException e) {
			} catch (NotOpenException e) {
				e.printStackTrace();
			}
		}
	}
}
