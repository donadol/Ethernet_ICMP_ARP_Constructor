package constructor.ethernet;

public class Utils {
	/*
	Función: StringToByteArray
	Parámetros de entrada: Cadena de chars a convertir a bytes, cadena que indica según que separar la cadena a convertir, longitud del arreglo de 
	bytes a crear.
	Valor de salida: arreglo de bytes con la conversión realizada. 
	Descripción: Convertir la cadena original en un arreglo de bytes. Primero, se separa la cadena original según el regex. Luego, se recorre el arreglo
	de Strings obtenido en la separación, cada posición se convierte en entero, luego este se convierte en byte y se guarda en el arreglo a retornar. 
	*/
	public static byte[] StringToByteArray(String s, String regex, int len) {
		String[] str=s.split(regex);
		byte[] data= new byte[len];
		for (int i = 0; i < str.length; ++i) {
			int j = Integer.parseInt(str[i]);
			data[i]=shortToByte((short)j);
		}
		return data;
	}
	/*
	Función: shortToByteArray
	Parámetros de entrada: número a convertir a bytes
	Valor de salida: arreglo de bytes de dos posiciones con el resultado de la conversión. 
	Descripción: Convertir el número en bytes. 
	*/
	public static byte[] shortToByteArray(short x) {
		byte[] data = new byte[2];
		data[0] = (byte)((x >> 8) & 0xff);
		data[1] = (byte)(x & 0xff);
		return data;
	}
	/*
	Función: shortToByte
	Parámetros de entrada: número a convertir a byte
	Valor de salida: byte con el resultado de la conversión. 
	Descripción: Convertir el número en byte. 
	*/
	public static byte shortToByte(short x) {
		return (byte)(x & 0xff);
	}
}
