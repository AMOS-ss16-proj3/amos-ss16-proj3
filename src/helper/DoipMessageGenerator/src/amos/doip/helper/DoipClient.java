package amos.doip.helper;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.util.List;

public class DoipClient implements Runnable {
    
    private final List<byte[]> messageBacklog;
    private final String host;
    private final int port;
    
    public DoipClient(String host, int port, List<byte[]> msgs){
        this.host = host;
        this.port = port;
        messageBacklog = msgs;
    }

    @Override
    public void run() {

        Socket con = null;
        try{
            con = new Socket(host, port);
            OutputStream os = con.getOutputStream();
            
            sendMessages(os);
            
        } catch (IOException e){
            e.printStackTrace();
        } finally{
            if(con != null){
                try{con.close();}catch(IOException e){}
            }
        }
        
    }
    
    private void sendMessages(OutputStream stream) throws IOException{
        for(byte[] msg : messageBacklog){

            stream.write(msg, 0, msg.length);
        }
    }

}
