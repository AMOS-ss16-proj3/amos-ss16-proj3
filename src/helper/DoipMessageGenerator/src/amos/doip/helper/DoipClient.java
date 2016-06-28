package amos.doip.helper;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.util.List;

public class DoipClient implements Runnable {
    
    private final List<byte[]> msgBacklog;
    private final String host;
    private final int port;
    
    public DoipClient(String host, int port, List<byte[]> msgs){
        this.host = host;
        this.port = port;
        msgBacklog = msgs;
    }

    @Override
    public void run() {

        Socket con = null;
        for(byte[] msg : msgBacklog){
            try{
                con = null;
                con = openConnection();
                OutputStream os = con.getOutputStream();
                
                sendMsg(os, msg);
                
            } catch (IOException e){
                e.printStackTrace();
            } finally{
                if(con != null){
                    try{con.close();}catch(IOException e){}
                }
            }
        }
    }

    private Socket openConnection() throws IOException {
        Socket s = new Socket(host, port);
        return s;
    }
    
    private void sendMsg(OutputStream stream, byte[] msg) throws IOException{
        stream.write(msg, 0, msg.length);
    }

}
