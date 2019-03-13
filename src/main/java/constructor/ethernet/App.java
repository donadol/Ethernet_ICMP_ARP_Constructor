package constructor.ethernet;

import java.util.Scanner;
import org.pcap4j.core.*;

/**
 * Hello world!
 *
 */
public class App 
{
	private static Scanner teclado;
	private App() {}

	public static void main(String[] args) throws PcapNativeException, NotOpenException {
		String ipO;
		String ipD;
		String selecc;
		String band;
		String  change;
		short length=(short) 65535;
		short id=1224;
		short ttl=100;
		teclado = new Scanner(System.in);
		while(true){
			System.out.println("Protocolos:\n1.IP\n2.ARP\n3.Salir");
			selecc = teclado.nextLine();
			if(selecc.equals("1")) { //IP
				System.out.print("Escriba la dirección IP del host origen: ");	
				ipO = teclado.nextLine(); 
				System.out.print("Escriba la dirección IP del host destino: ");
				ipD = teclado.nextLine(); 
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
							length = Short.parseShort(teclado.nextLine());
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
							createIPMessage(ipO, ipD, length, id, ttl);
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
					createIPMessage(ipO, ipD, length, id, ttl);

				}
			}
			else if(selecc.equals("2")) { //ARP
				createARPMessage();
			}
			else if(selecc.equals("3")) { //Salir
				return;
			}
			else {
				System.out.print(" Opción invalida");
			}
		}
	}
	private static void createIPMessage(String ipO, String ipD, short length, short id, short ttl) {
		IP msg=new IP(ipO, ipD, length, id, ttl);
		Sender sender = new Sender(msg);
	}
	private static void createARPMessage() {
		
	}
}
