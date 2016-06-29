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


public class DoipHeader {
    
    public final static byte PROTO_VERSION = 0x02;
    public final byte[] BASIC_HEADER = new byte[] {PROTO_VERSION, 0, 0, 0, 0, 0, 0, 0};
    
    private final int payloadType;
    private final byte[] payload;

    public DoipHeader(int payloadType, byte[] payload){
        this.payloadType = payloadType;
        this.payload = payload;
    }

    public byte[] toByteArray() {
        
        byte[] header = new byte[BASIC_HEADER.length];
        System.arraycopy(BASIC_HEADER, 0, header, 0, BASIC_HEADER.length);
        
        setInverseProtoVersion(header);
        setPayloadType(payloadType, header);
        setPayloadLength(payload.length, header);
        
        return header;
    }
    
    public static void setPayloadType(int payloadType, byte[] header){
        final int TYPE_INDEX = 2;
        
        byte[] typeParts = new byte[]{
            (byte) (payloadType >> 8),
            (byte) payloadType
        };
        
        System.arraycopy(typeParts, 0, header, TYPE_INDEX, typeParts.length);
    }

    public static void setInverseProtoVersion(byte[] header){
        final int INDEX = 1;
        byte inverseVersion = PROTO_VERSION ^ ((byte) 0xFF);
        header[INDEX] = inverseVersion;
    }
    
    public static void setPayloadLength(int length, byte[] header){
        
        final int LENGTH_INDEX = 4;
        
        byte[] lengthParts = new byte[]{
            (byte) (length >> 24),
            (byte) (length >> 16),
            (byte) (length >> 8),
            (byte) length
        };
        
        System.arraycopy(lengthParts, 0, header, LENGTH_INDEX, lengthParts.length);
    }
}
