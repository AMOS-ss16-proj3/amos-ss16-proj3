package amos.doip.helper;

public class DoipMessageGenerator {

    public static void main(String[] args) {
        // TODO Auto-generated method stub

        DoipMessage msg = new DoipMessage(1, new byte[]{0x04});
        
        byte[] foo = msg.toByteArray();
        
        
        /*
        Thread server = new Thread(new DoipServer());
        Thread client = new Thread(new DoipClient());
        
        server.start();
        client.start();
        
        try {
            
            server.interrupt();
            server.join();
            client.join();
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        */
        
    }

}
