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


public class DoipMessage {

    private final int payloadType;
    private final byte[] payload;
    
    public DoipMessage(int payloadType, byte[] payload){
        this.payloadType = payloadType;
        this.payload = payload;
    }
    
    public byte[] toByteArray(){
        byte[] header = new DoipHeader(payloadType, payload).toByteArray();
        byte[] compound = new byte[header.length + payload.length];
        System.arraycopy(header, 0, compound, 0, header.length);
        System.arraycopy(payload, 0, compound, header.length, payload.length);
        
        return compound;
    }
    
}
