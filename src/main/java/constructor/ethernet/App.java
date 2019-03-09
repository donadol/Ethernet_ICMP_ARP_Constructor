package constructor.ethernet;

import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.util.concurrent.*;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.*;

/**
 * Hello world!
 *
 */
public class App 
{
	private static final String COUNT_KEY = App.class.getName() + ".count";
	private static final int COUNT = Integer.getInteger(COUNT_KEY, 1);

	private static final String READ_TIMEOUT_KEY = App.class.getName() + ".readTimeout";
	private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

	private static final String SNAPLEN_KEY = App.class.getName() + ".snaplen";
	private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

	private static final MacAddress SRC_MAC_ADDR = MacAddress.getByName("8c:85:90:6e:ff:f9");

	private static MacAddress resolvedAddr;

	private App() {}

	public static void main(String[] args) throws PcapNativeException, NotOpenException {
		String ipO;
		String ipD;
		String selecc;
		String band;
		String  change;
		boolean t = true;
		int tamanCamp = 0;
		Scanner teclado = new Scanner(System.in);
		System.out.println(" Escriba la dirección IP del host origen ");	
		ipO = teclado.nextLine(); 
		System.out.println(" Escriba la dirección IP del host destino ");
		ipD = teclado.nextLine(); 
		System.out.println(" SE RECOMIENDA USAR EL SIGUIENTE MODELO" );
		System.out.println("|TYPE(8)|CODE|DATA| ");
		System.out.println(" ¿Desea cambiar algun campo? s/n");

		band = teclado.nextLine(); 
		if(band.equals("s")||band.equals("S"))
		{
			t=true;
			while(t)
			{
				System.out.println("********************************************** " );
				System.out.println(" ¿Qué campo desea cambiar? " );		
				System.out.println("1. DATA " );
				System.out.println("2. Salir" );
				change = teclado.nextLine();
				System.out.println("********************************************** " );
				if(change.equals("1"))
				{
					System.out.println(" ¿Qué tamaño desea para el campo de DATA? " );
					tamanCamp = Integer.parseInt(teclado.nextLine());

				}
				else if (change.equals("2"))
				{
					t = false;
				}
				else
				{
					System.out.println(" Opción no valida " );
				}
				System.out.println("********************************************** " );
			}
		}
		else
		{
			System.out.println(" ALGO DEBE IR ACA " );

		}
		

		System.out.println(COUNT_KEY + ": " + COUNT);
		System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
		System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
		System.out.println("\n");

		PcapNetworkInterface nif;
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

		PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
		PcapHandle sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
		ExecutorService pool = Executors.newSingleThreadExecutor();

		try {
			handle.setFilter(
					"arp and src host "
							+ ipD
							+ " and dst host "
							+ ipO
							+ " and ether dst "
							+ Pcaps.toBpfString(SRC_MAC_ADDR),
							BpfCompileMode.OPTIMIZE);

			PacketListener listener =
					new PacketListener() {
				public void gotPacket(Packet packet) {
					if (packet.contains(ArpPacket.class)) {
						ArpPacket arp = packet.get(ArpPacket.class);
						if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
							App.resolvedAddr = arp.getHeader().getSrcHardwareAddr();
						}
					}
					System.out.println(packet);
				}
			};

			Task task = new Task(handle, listener);
			pool.execute(task);

			ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
			try {
				arpBuilder
				.hardwareType(ArpHardwareType.ETHERNET)
				.protocolType(EtherType.IPV4)
				.hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
				.protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
				.operation(ArpOperation.REQUEST)
				.srcHardwareAddr(SRC_MAC_ADDR)
				.srcProtocolAddr(InetAddress.getByName(ipO))
				.dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
				.dstProtocolAddr(InetAddress.getByName(ipD));
			} catch (UnknownHostException e) {
				throw new IllegalArgumentException(e);
			}

			EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
			etherBuilder
			.dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
			.srcAddr(SRC_MAC_ADDR)
			.type(EtherType.ARP)
			.payloadBuilder(arpBuilder)
			.paddingAtBuild(true);

			for (int i = 0; i < COUNT; i++) {
				Packet p = etherBuilder.build();
				System.out.println(p);
				sendHandle.sendPacket(p);
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					break;
				}
			}
		} finally {
			if (handle != null && handle.isOpen()) {
				handle.close();
			}
			if (sendHandle != null && sendHandle.isOpen()) {
				sendHandle.close();
			}
			if (pool != null && !pool.isShutdown()) {
				pool.shutdown();
			}

			System.out.println(ipD + " was resolved to " + resolvedAddr);
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
				handle.loop(COUNT, listener);
			} catch (PcapNativeException e) {
				e.printStackTrace();
			} catch (InterruptedException e) {
				e.printStackTrace();
			} catch (NotOpenException e) {
				e.printStackTrace();
			}
		}
	}

}
