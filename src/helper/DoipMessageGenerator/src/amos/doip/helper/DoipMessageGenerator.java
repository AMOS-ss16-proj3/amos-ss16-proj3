package amos.doip.helper;

import java.util.LinkedList;
import java.util.List;
import java.nio.charset.Charset;

public class DoipMessageGenerator {

    public static final Charset ASCII = Charset.forName("US-ASCII");

    public static void main(String[] args) {
        // TODO Auto-generated method stub

        DoipMessage[] dmsgs = {

            /* 0 - Generic doip header negative acknowledge */
            new DoipMessage(0, new byte[]{0}),
            new DoipMessage(0, new byte[]{1}),
            new DoipMessage(0, new byte[]{2}),
            new DoipMessage(0, new byte[]{3}),
            new DoipMessage(0, new byte[]{4}),
            new DoipMessage(0, new byte[]{5}),
            new DoipMessage(0, new byte[]{(byte)0xFF}),


            /* 0x0001 - Vehicle identification request message */
            new DoipMessage(1, new byte[]{0x0}),

            /* 0x0002 - vehice identification request message with EID */
            new DoipMessage(2, new byte[]{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}),

            /* 0x0003 - vehicle identification request message with VIN */
            new DoipMessage(3, "Hallo Welt!".getBytes(ASCII)),
            new DoipMessage(3, "12345678901234567".getBytes(ASCII)),



            /* 0x8001 - */
            new DoipMessage(0x8001, new byte[]{0x03, (byte)0x80, (byte)0xe4,0x00, 0x3e, (byte)0x80})
        };
        
        
        List<byte[]> msgs = new LinkedList<byte[]>();
        for(DoipMessage dmsg : dmsgs){
            msgs.add(dmsg.toByteArray());
        }
        
        
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
