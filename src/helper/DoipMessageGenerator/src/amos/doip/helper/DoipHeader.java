package amos.doip.helper;


public class DoipHeader {
    
    public final byte[] BASIC_HEADER = new byte[] {0x02, (byte)0xFE, 0, 0, 0, 0, 0, 0};
    
    private final int payloadType;
    private final byte[] payload;

    public DoipHeader(int payloadType, byte[] payload){
        this.payloadType = payloadType;
        this.payload = payload;
    }

    public byte[] toByteArray() {
        
        byte[] header = new byte[BASIC_HEADER.length];
        for(int i = 0; i < BASIC_HEADER.length; i += 1){
            header[i] = (byte) ((BASIC_HEADER[i] << 16) >> 16);
        }
        
        return header;
    }
}
