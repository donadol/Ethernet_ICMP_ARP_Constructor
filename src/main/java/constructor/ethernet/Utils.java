package constructor.ethernet;

public class Utils {
	public static byte[] StringToByteArray(String s, String regex, int len) {
		String[] str=s.split(regex);
		byte[] data= new byte[len];
		for (int i = 0; i < str.length; ++i) {
			int j = Integer.parseInt(str[i]);
			data[i]=shortToByte((short)j);
		}
		return data;
	}
	public static byte[] shortToByteArray(short x) {
		byte[] data = new byte[2];
		data[0] = (byte)((x >> 8) & 0xff);
		data[1] = (byte)(x & 0xff);
		return data;
	}
	public static byte shortToByte(short x) {
		return (byte)(x & 0xff);
	}
	public static String clean(String s, String regex){
    	String[] str=s.split(regex);
    	String x="";
    	for(int i=0; i<str.length;++i) {
    		x+=str[i];
    	}
    	System.out.println(x);
    	return x;
    }
	public static byte[] hexStringToByteArray(String s, int len) {
        byte[] data = new byte[len];
        for (int i = 0; i < len*2; i += 2) {
            data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
