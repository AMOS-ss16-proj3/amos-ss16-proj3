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
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class DoipMessageGenerator {

    public static final Charset ASCII = Charset.forName("US-ASCII");

    private static DoipMessage[] dmsgs = {
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

        /* 0x0002 - vehicle identification request message with EID */
        new DoipMessage(2, new byte[]{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}),

        /* 0x0003 - vehicle identification request message with VIN */
        //new DoipMessage(3, "Hallo Welt!".getBytes(ASCII)),
        new DoipMessage(3, new byte[]{'1','2','3','4','5','6','7','8','9','0','1','2','3','4','5',0,0}),
        new DoipMessage(3, "12345678901234567".getBytes(ASCII)),
        new DoipMessage(3, "123456789012345678".getBytes(ASCII)),

        /* 0x0004 - vehicle announcement/vehicle identification response message */
        new DoipMessage(4, new byte[]{
            // VIN
            '1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7',
            // Logical address 
            (byte) 0x13, (byte)0x37,
            // EID
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            // GID
            (byte) 0xFF, (byte)0xEE, (byte) 0xDD, (byte) 0xCC, (byte) 0xBB, (byte) 0xAA,
            // Further action required
            0x00
        }),
        new DoipMessage(4, new byte[]{
            // VIN 
            '1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7',
            // Logical address
            (byte) 0x00, (byte)0x01,
            // EID
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            // GID
            (byte) 0xFF, (byte)0xEE, (byte) 0xDD, (byte) 0xCC, (byte) 0xBB, (byte) 0xAA,
            // Further action required
            0x00,
            // VIN/GID sync status
            0x00
        }),

        /* 0x0005 - Routing activation request */
        new DoipMessage(0x0005, new byte[]{
            // source address
            0x00, 0x01,
            // activation type
            0x00,
            // reserved by iso
            0x00, 0x00, 0x00, 0x00
        }),
        new DoipMessage(0x0005, new byte[]{
            // source address
            0x00, 0x01,
            // activation type
            0x00,
            // reserved by iso
            0x00, 0x00, 0x00, 0x00,
            // reserved for oem specific use
            0x12, 0x23, 0x34, 0x45
        }),
        
        /* 0x0006 - Routing activation response */
        new DoipMessage(0x0006, new byte[]{
            // logical address of external test equipment
            0x00, 0x01,
            // logical address of doip entity
            0x00, 0x00,
            // routing activation response code
            0x00,
            // reserved by iso
            0x00, 0x00, 0x00, 0x00
        }),
        new DoipMessage(0x0006, new byte[]{
            // logical address of external test equipment
            0x00, 0x01,
            // logical address of doip entity
            0x00, 0x00,
            // routing activation response code
            0x04,
            // reserved by iso
            0x00, 0x00, 0x00, 0x00,
            // reserved for oem specific use
            0x12, 0x23, 0x34, 0x45
        }),
        

        /* 0x0007 - Alive check request */
        new DoipMessage(0x0007, new byte[]{}),

        /* 0x0008 - Alive check response */
        new DoipMessage(0x0008, new byte[]{
            // source address
            (byte) 0xAC, (byte) 0xDC
        }),

        /* 0x4001 - Doip entity status request */
        new DoipMessage(0x4001, new byte[]{}),

        /* 0x4002 - Doip entity status response */
        new DoipMessage(0x4002, new byte[]{
            // node type
            0x00,
            // max. concurrent tcp_data sockets (MCTS)
            (byte) 123,
            // currently open TCP_data sockets (NCTS)
            (byte) 42
        }),
        new DoipMessage(0x4002, new byte[]{
            // node type
            0x00,
            // max. concurrent tcp_data sockets (MCTS)
            (byte) 123,
            // currently open TCP_data sockets (NCTS)
            (byte) 42,
            // max 
            (byte) 0xFF, (byte) 0xEE, (byte) 0xDD, (byte) 0xCC
        }),

        /* 0x4003 - Diagnostic power mode information request */
        new DoipMessage(0x4003, new byte[]{}),

        /* 0x4004 - Diagnostic power mode information response */
        new DoipMessage(0x4004, new byte[]{
            // diagnostic power mode
            0x01
        }),



        /* 0x8001 - Diagnostic message */
        new DoipMessage(0x8001, new byte[]{
            // source address
            0x03, (byte)0x80,
            // target address
            (byte)0xe4,0x00,
        }),
        new DoipMessage(0x8001, new byte[]{
            // source address
            0x03, (byte)0x80,
            // target address
            (byte)0xe4,0x00,
            // user data
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
        }),

        /* 0x8002 Diagnostic message positive ack */
        new DoipMessage(0x8002, new byte[]{
            // source address
            0x03, (byte)0x80,
            // target address
            (byte)0xe4,0x00,
            // ACK code
            0x00
        }),
        new DoipMessage(0x8002, new byte[]{
            // source address
            0x03, (byte)0x80,
            // target address
            (byte)0xe4,0x00,
            // ACK code
            0x00,
            // user data
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
        }),

        /* 0x8003 Diagnostic message negative ack */
        new DoipMessage(0x8003, new byte[]{
            // source address
            0x03, (byte)0x80,
            // target address
            (byte)0xe4,0x00,
            // NACK code
            0x00
        }),
        new DoipMessage(0x8003, new byte[]{
            // source address
            0x03, (byte)0x80,
            // target address
            (byte)0xe4,0x00,
            // NACK code
            0x00,
            // user data
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
        }),

    };
        
    public static void main(String[] args) {
        List<byte[]> msgs = new LinkedList<byte[]>();
        for(DoipMessage dmsg : dmsgs){
            msgs.add(dmsg.toByteArray());
        }
        
        
        try {
            DoipServer serverImpl = new DoipServer();
            Thread server = new Thread(serverImpl);
            Thread client = new Thread(new DoipClient("localhost" ,13400, msgs));
            
            server.start();
            client.start();
        
            
            client.join();
            Thread.sleep(300);
            serverImpl.close();
            server.join();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
