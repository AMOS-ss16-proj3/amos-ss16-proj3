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
        System.arraycopy(BASIC_HEADER, 0, header, 0, BASIC_HEADER.length);
        
        setPayloadType(payloadType, header);
        setPayloadLength(payload.length, header);
        
        return header;
    }
    
    public static void setPayloadType(int payloadType, byte[] header){
        final int TYPE_INDEX = 2;
        
        byte[] typeParts = new byte[]{
            (byte) (payloadType >> 8),
            (byte) payloadType
        };
        
        System.arraycopy(typeParts, 0, header, TYPE_INDEX, typeParts.length);
    }
    
    public static void setPayloadLength(int length, byte[] header){
        
        final int LENGTH_INDEX = 4;
        
        byte[] lengthParts = new byte[]{
            (byte) (length >> 24),
            (byte) (length >> 16),
            (byte) (length >> 8),
            (byte) length
        };
        
        System.arraycopy(lengthParts, 0, header, LENGTH_INDEX, lengthParts.length);
    }
}
