package constructor.ethernet;

public class ARP {
	byte[] ar$hrd;
	byte[] ar$pro;
	byte   ar$hln;
	byte   ar$pln;
	byte[] ar$op;
	byte[] ar$sha;
	byte[] ar$spa;
	byte[] ar$tha;
	byte[] ar$tpa;

	public ARP(short hwtype, short protype, short hwsize, short prosize, short opcode, String macSender, String ipSender, String macTarget, String ipTarget) {
		this.ar$hrd=shortToByteArray(hwtype);
		this.ar$pro=shortToByteArray(protype);
		this.ar$hln=shortToByte(hwsize);
		this.ar$pln=shortToByte(prosize);
		this.ar$op=shortToByteArray(opcode);
		this.ar$sha=hexStringToByteArray(clean(macSender,":"), ar$hln);
		this.ar$spa=StringToByteArray(ipSender, "\\.", ar$pln);
		this.ar$tha=hexStringToByteArray(clean(macTarget,":"), ar$hln);
		this.ar$tpa=StringToByteArray(ipTarget, "\\.", ar$pln);
	}
	private static byte[] StringToByteArray(String s, String regex, int len) {
		String[] str=s.split(regex);
		byte[] data= new byte[len];
		for (int i = 0; i < str.length; ++i) {
			int j = Integer.parseInt(str[i]);
			data[i]=shortToByte((short)j);
		}
		return data;
	}
	private static byte[] shortToByteArray(short x) {
		byte[] data = new byte[2];
		data[0] = (byte)((x >> 8) & 0xff);
		data[1] = (byte)(x & 0xff);
		return data;
	}
	private static byte shortToByte(short x) {
		return (byte)(x & 0xff);
	}
	private static String clean(String s, String regex){
    	String[] str=s.split(regex);
    	String x="";
    	for(int i=0; i<str.length;++i) {
    		x+=str[i];
    	}
    	System.out.println(x);
    	return x;
    }
	private static byte[] hexStringToByteArray(String s, int len) {
        byte[] data = new byte[len];
        for (int i = 0; i < len*2; i += 2) {
            data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
	public byte[] constructARPMessage() {
		byte[] msg = new byte[28];
		System.arraycopy(ar$hrd, 0, msg, 0, ar$hrd.length);
		System.arraycopy(ar$pro, 0, msg, ar$hrd.length, ar$pro.length);
		System.arraycopy(ar$hln, 0, msg, ar$hrd.length+ar$pro.length, 1);
		System.arraycopy(ar$pln, 0, msg, ar$hrd.length+ar$pro.length+1, 1);
		System.arraycopy(ar$op,  0, msg, ar$hrd.length+ar$pro.length+2, ar$op.length);
		System.arraycopy(ar$sha, 0, msg, ar$hrd.length+ar$pro.length+2+ar$op.length, ar$sha.length);
		System.arraycopy(ar$spa, 0, msg, ar$hrd.length+ar$pro.length+2+ar$op.length+ar$sha.length, ar$spa.length);
		System.arraycopy(ar$tha, 0, msg, ar$hrd.length+ar$pro.length+2+ar$op.length+ar$sha.length+ar$spa.length, ar$tha.length);
		System.arraycopy(ar$tpa, 0, msg, ar$hrd.length+ar$pro.length+2+ar$op.length+ar$sha.length+ar$spa.length+ar$tha.length, ar$tpa.length);
		return msg;
	}
}
