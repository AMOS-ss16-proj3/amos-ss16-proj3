package amos.doip.helper;

import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;


public class DoipServer implements Runnable {

    private final int DOIP_PORT = 13400;
    
    @Override
    public void run() {
        
        try {
            ServerSocket s = new ServerSocket(DOIP_PORT);
            Socket con = null; 
            while((con = s.accept()) != null) {
                handleConnection(con);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private void handleConnection(Socket s) throws IOException{
        InputStream stream = s.getInputStream();
        while(stream.read() != -1);
        s.close();
    }

}
