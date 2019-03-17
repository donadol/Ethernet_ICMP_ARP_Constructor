package constructor.ethernet;

import java.io.IOException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.EthernetPacket;
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

	/*
	Función: Sender (constructor)
	Parámetros de entrada: no tiene.
	Valor de salida: un objeto tipo Sender
	Descripción: Crea un objeto tipo Sender, imprime la lista de interfaces de red disponibles en el computador y se da la opción de escoger 
	cual utilizar.
	*/
	public Sender() throws PcapNativeException {
		try {
		      nif = new NifSelector().selectNetworkInterface();
		    } catch (IOException e) {
		      e.printStackTrace();
		      return;
		    }
		if (nif == null) {
			return;
		}
	}
	/*
	Función: sendMessage
	Parámetros de entrada: paquete ethernet
	Valor de salida: booleano que indica si se pudo enviar el mensaje o no. 
	Descripción: Envía el paquete Ethernet por medio de la tarjeta (nif) seleccionada.
	*/
	public boolean sendMessage(EthernetPacket packet) throws PcapNativeException, NotOpenException {
		boolean send=true;
		handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
		sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
		try {
			sendHandle.sendPacket(packet);
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				send = false;
			}
		} finally {
			if (handle != null && handle.isOpen()) {
				handle.close();
			}
			if (sendHandle != null && sendHandle.isOpen()) {
				sendHandle.close();
			}
		}
		return send;
	}
}
