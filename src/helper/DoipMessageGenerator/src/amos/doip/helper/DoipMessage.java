package amos.doip.helper;


public class DoipMessage {

    private final int payloadType;
    private final byte[] payload;
    
    public DoipMessage(int payloadType, byte[] payload){
        this.payloadType = payloadType;
        this.payload = payload;
    }
    
    public byte[] toByteArray(){
        byte[] header = new DoipHeader(payloadType, payload).toByteArray();
        byte[] compound = new byte[header.length + payload.length];
        System.arraycopy(header, 0, compound, 0, header.length);
        System.arraycopy(payload, 0, compound, header.length, payload.length);
        
        return compound;
    }
    
}
