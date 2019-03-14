package constructor.ethernet;

import java.net.UnknownHostException;
import java.util.Scanner;

//import org.apache.log4j.BasicConfigurator;
//import org.apache.log4j.LogManager;
import org.pcap4j.core.*;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.*;
import org.slf4j.Logger;

/**
 * Hello world!
 *
 */
public class EthernetConstructor 
{
	private static Scanner teclado;
	private static EthernetPacket packet;
	private static Sender sender;
	//private static final Logger log = (Logger) LogManager.getLogger(EthernetConstructor.class);
	private EthernetConstructor() {}

	public static void main(String[] args) throws PcapNativeException, NotOpenException, UnknownHostException {
		String ipO;
		String ipD;
		String selecc;
		String band;
		String change;
		String macsrc;
		String macdst="ff:ff:ff:ff:ff:ff";
		int length=65535;
		short id=1224;
		short ttl=100;
		teclado = new Scanner(System.in);
		//BasicConfigurator.configure();
		while(true){
			System.out.println("Protocolos:\n1.IP\n2.ARP\n3.Salir");
			selecc = teclado.nextLine();
			if(selecc.equals("1")) { //IP
				System.out.print("Escriba la dirección IP del host origen: ");	
				ipO = teclado.nextLine();
				System.out.print("Escriba la dirección MAC del host origen: ");	
				macsrc = teclado.nextLine();
				System.out.print("Escriba la dirección IP del host destino: ");
				ipD = teclado.nextLine();
				//System.out.print("Escriba la dirección MAC del host destino: ");
				//macdst = teclado.nextLine(); 
				//sugerir campos
				System.out.println("SE RECOMIENDA USAR EL SIGUIENTE MODELO" );
				System.out.println("|VERSION|IHL|TOS|LENGTH|IDENTIFICATION|TTL|PROTOCOL|");
				System.out.println("|   IPV4|  4|  0| "+length+"|          "+id+"|"+ttl+"|  ICMPV4|");
				System.out.println("¿Desea cambiar algun campo? (s/n)");
				band = teclado.nextLine(); 
				if(band.equals("s")||band.equals("S")){
					while(true){
						System.out.println("********************************************** " );
						System.out.println("¿Qué campo desea cambiar? " );
						System.out.println("1. Total lenght\n2. Identification\n3. Time to live\n4. Enviar\n5. Salir");
						change = teclado.nextLine();
						System.out.println("********************************************** " );
						if(change.equals("1")){
							System.out.println("¿Qué tamaño desea para el paquete?" );
							length = Integer.parseInt(teclado.nextLine());
						}
						else if(change.equals("2")){
							System.out.println("¿Qué identificador desea?" );
							id = Short.parseShort(teclado.nextLine());
						}
						else if(change.equals("3")){
							System.out.println("¿Qué tiempo de vida quiere?" );
							ttl = Short.parseShort(teclado.nextLine());
						}
						else if (change.equals("4")){
							createIPMessage(ipO, ipD, length, id, ttl, macsrc, macdst);
						}
						else if (change.equals("5")){
							return;
						}
						else{
							System.out.println(" Opción no valida " );
						}
						System.out.println("********************************************** " );
					}
				}
				else{
					createIPMessage(ipO, ipD, length, id, ttl, macsrc, macdst);
				}
			}
			else if(selecc.equals("2")) { //ARP
				System.out.print("Escriba la dirección MAC del host origen: ");	
				macsrc = teclado.nextLine(); 
				System.out.print("Escriba la dirección IP del host origen: ");	
				ipO = teclado.nextLine(); 
//				System.out.print("Escriba la dirección MAC del host destino: ");
//				macdst = teclado.nextLine(); 
				System.out.print("Escriba la dirección IP del host destino: ");
				ipD = teclado.nextLine(); 
				createARPMessage(macsrc, ipO, macdst, ipD);
			}
			else if(selecc.equals("3")) { //Salir
				return;
			}
			else {
				System.out.print(" Opción invalida");
			}
		}
	}
	private static void createIPMessage(String ipO, String ipD, int length, short id, short ttl, String macsrc, String macdst) throws UnknownHostException, PcapNativeException, NotOpenException {
		IP msg=new IP(ipO, ipD, length, id, ttl, macsrc, macdst);
		packet=(EthernetPacket) msg.createICMP();
		sender = new Sender();
		sender.sendMessage(packet);
	}
	private static void createARPMessage(String macSender, String ipSender, String macTarget, String ipTarget) throws UnknownHostException, PcapNativeException, NotOpenException {
		ARP msg=new ARP((short)1, (short)2048, (short)MacAddress.SIZE_IN_BYTES, (short)ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES, (short)1, macSender, ipSender, macTarget, ipTarget);
		packet=(EthernetPacket) msg.createARP();
		sender = new Sender();
		sender.sendMessage(packet);
	}
}
