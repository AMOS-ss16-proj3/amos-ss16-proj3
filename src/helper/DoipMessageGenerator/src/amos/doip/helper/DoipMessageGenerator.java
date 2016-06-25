package amos.doip.helper;

import java.util.LinkedList;
import java.util.List;

public class DoipMessageGenerator {

    public static void main(String[] args) {
        // TODO Auto-generated method stub

        DoipMessage dmsg1 = new DoipMessage(1, new byte[]{0x04});
        DoipMessage dmsg2 = new DoipMessage(0x8001, new byte[]{0x03, (byte)0x80, (byte)0xe4,0x00, 0x3e, (byte)0x80});
        
        byte[] msg1 = dmsg1.toByteArray();
        byte[] msg2 = dmsg2.toByteArray();
        
        List<byte[]> msgs = new LinkedList<byte[]>();
        //msgs.add(msg1);
        msgs.add(msg2);
        
        
        Thread server = new Thread(new DoipServer());
        Thread client = new Thread(new DoipClient("localhost" ,13400, msgs));
        
        server.start();
        client.start();
        
        try {
            
            server.join();
            client.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        
        
    }

}
