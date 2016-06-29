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
