/**
* Copyright 2016 The Open Source Research Group,
*                University of Erlangen-Nürnberg
*
* Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE, Version 3.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     https://www.gnu.org/licenses/gpl.html
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

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
