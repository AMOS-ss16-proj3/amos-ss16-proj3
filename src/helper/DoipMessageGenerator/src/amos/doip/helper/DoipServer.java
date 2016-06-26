package amos.doip.helper;

import java.io.IOException;
import java.net.SocketException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;


public class DoipServer implements Runnable {

    private final int DOIP_PORT = 13400;

    private volatile ServerSocket s;
    private boolean isClosed = false;

    public DoipServer() throws IOException {
        s = new ServerSocket(DOIP_PORT);
    }
    
    @Override
    public void run() {
        try {
            Socket con = null;
            while((con = s.accept()) != null){
                handleConnection(con);
            }
            
        }catch (IOException e) {
            synchronized(this){
                if(!isClosed){
                    e.printStackTrace();
                }
            }
        }finally{
            if(s != null){
                try{s.close();}catch(IOException e){}
            }
        }
    }

    public void close(){
        synchronized(this){
            isClosed = true;
        }
        try{
            s.close();
        } catch(IOException e){
            e.printStackTrace();
        }
    }
    
    private void handleConnection(Socket s) throws IOException{
        InputStream stream = s.getInputStream();
        int read = 0;
        while((read = stream.read()) != -1)System.out.println((byte)read);
        s.close();
    }

}
