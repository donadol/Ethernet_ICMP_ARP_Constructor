package constructor.ethernet;

import java.net.UnknownHostException;
import java.util.Scanner;

import org.pcap4j.core.*;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.*;

public class EthernetConstructor 
{
	private static Scanner teclado;
	private static EthernetPacket packet;
	private static Sender sender;
	private EthernetConstructor() {}

	/*
	Función: main
	Parámetros de entrada: no tiene.
	Valor de salida: 
	Descripción: Programa principal. En este programa se le piden los datos al usuario necesarios para la creación y envío del mensaje. 
	Además, se le exponen las opciones posibles al usuario:
		* tipo de mensaje a enviar
		* cambio de campos del modelo del protocolo ARP
	*/
	public static void main(String[] args) throws PcapNativeException, NotOpenException, UnknownHostException {
		String ipO;
		String ipD;
		String selecc;
		String band;
		String change;
		String macsrc;
		String macdst="ff:ff:ff:ff:ff:ff";
		int length=1472;
		short id=1224;
		short ttl=100;
		teclado = new Scanner(System.in);
		System.out.print("Escriba la dirección MAC del host origen: ");	
		macsrc = teclado.nextLine();
		while(true){
			System.out.println("Protocolos:\n1.IP\n2.ARP\n3.Salir");
			selecc = teclado.nextLine();
			if(selecc.equals("1")) { //IP
				System.out.print("Escriba la dirección IP del host origen: ");	
				ipO = teclado.nextLine();
				System.out.print("Escriba la dirección IP del host destino: ");
				ipD = teclado.nextLine();
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
							while(length>1472)
							{
								System.out.println("El tamaño maximo permitido es 1480" );
								System.out.println("¿Qué tamaño desea para el paquete?" );
								length = Integer.parseInt(teclado.nextLine());
							}	
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
			else if(selecc.equals("2")) {
				System.out.print("Escriba la dirección MAC del host origen: ");	
				macsrc = teclado.nextLine(); 
				System.out.print("Escriba la dirección IP del host origen: ");	
				ipO = teclado.nextLine();
				System.out.print("Escriba la dirección IP del host destino: ");
				ipD = teclado.nextLine(); 
				createARPMessage(macsrc, ipO, macdst, ipD);
			}
			else if(selecc.equals("3")) {
				return;
			}
			else {
				System.out.print(" Opción invalida");
			}
		}
	}
	/*
	Función: createIPMessage
	Parámetros de entrada: dirección ip de origen, dirección ip de destino, longitud del mensaje a crear, id del mensaje, tiempo de vida del mensaje, 
	dirección mac de origen y dirección mac de destino
	Valor de salida: no tiene.
	Descripción: A partir de los datos suministrados por el usuario y los predeterminados, en caso de que el usuario no los haya cambiado, crea el 
	mensaje, construye el paquete de ethernet y lo envía. Al final imprime el resultado, si se pudo enviar o no el mensaje.
	*/
	private static void createIPMessage(String ipO, String ipD, int length, short id, short ttl, String macsrc, String macdst) throws UnknownHostException, PcapNativeException, NotOpenException {
		IP msg=new IP(ipO, ipD, length, id, ttl, macsrc, macdst);
		packet= msg.createICMP();
		sender = new Sender();
		if(sender.sendMessage(packet))
			System.out.print("El mensaje ICMP se ha enviado");
		else
			System.out.print("El mensaje ICMP no se ha enviado");
	}
	/*
	Función: createARPMessage
	Parámetros de entrada: dirección mac de origen, dirección ip de origen, dirección mac de destino y dirección ip de destino
	Valor de salida: no tiene.
	Descripción: A partir de los datos suministrados por el usuario y los predeterminados crea el mensaje ARP, construye el paquete de ethernet 
	y lo envía. Al final imprime el resultado, si se pudo enviar o no el mensaje.
	*/
	private static void createARPMessage(String macSender, String ipSender, String macTarget, String ipTarget) throws UnknownHostException, PcapNativeException, NotOpenException {
		ARP msg=new ARP((short)1, (short)2048, (short)MacAddress.SIZE_IN_BYTES, (short)ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES, (short)1, macSender, ipSender, macTarget, ipTarget);
		packet= msg.createARP();
		sender = new Sender();
		if(sender.sendMessage(packet))
			System.out.print("El mensaje ARP se ha enviado");
		else
			System.out.print("El mensaje ARP no se ha enviado");
	}
}
