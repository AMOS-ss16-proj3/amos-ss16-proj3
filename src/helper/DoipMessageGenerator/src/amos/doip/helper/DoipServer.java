package amos.doip.helper;

import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;


public class DoipServer implements Runnable {

    private final int DOIP_PORT = 13400;
    
    @Override
    public void run() {
        ServerSocket s = null;
        try {
            s = new ServerSocket(DOIP_PORT);
            Socket con = s.accept();
        
            handleConnection(con);
            
        } catch (IOException e) {
            e.printStackTrace();
        }finally{
            if(s != null){
                try{s.close();}catch(IOException e){}
            }
        }
    }
    
    private void handleConnection(Socket s) throws IOException{
        InputStream stream = s.getInputStream();
        int read = 0;
        while((read = stream.read()) != -1)System.out.println((byte)read);
        s.close();
    }

}
