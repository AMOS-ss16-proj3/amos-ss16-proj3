package amos.doip.helper;

import java.util.LinkedList;
import java.util.List;

public class DoipMessageGenerator {

    public static void main(String[] args) {
        // TODO Auto-generated method stub

        DoipMessage dmsg = new DoipMessage(1, new byte[]{0x04});
        
        byte[] msg = dmsg.toByteArray();
        
        List<byte[]> msgs = new LinkedList<byte[]>();
        msgs.add(msg);
        
        
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
