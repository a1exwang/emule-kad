# Kad Protocol - from aMule

1. 解析nodes.dat, 得到bootstrap节点列表

2. 对于KadVersion >= 6, 加密传输

    - 接受数据包, 解密
        - 需要自己的UdpVerifyKey, data[1..2]
        
    - 过程
        - CoreTimer
        - CKademlia::Process()
        - if (!Connected()) 
            instance->m_udpListener->Bootstrap(contact.ip, port, version, id)
        - CKademliaUDPListener::Bootstrap(ip,port,v,id)
               SendPacket(empty, KAD2_BOOTSTRAP_REQ, contact.ip, contact.port, 0, contact.id);
        - CKademliaUDPListener::SendPacket(data, opcode, destIp, port, targetKey, cryptTargetID)
        - cryptTargetID->StoreCryptValue(cryptKey);
        - theApp->clientudp->SendPacket(packet, ip, port, true, cryptKey, true, targetKey.GetKeyValue(theApp->GetPublicIP(false)));
        - CMuleUDPSocket::SendPacket(packet, IP, port, bEncrypt, pachTargetClientHashORKadID, bKad, uint32 nReceiverVerifyKey)
            - item.ip = ip
            - item.port = port
            - item.time = GetTickCount()
            - item.bEncrypt = xx
            - item.bKad = bKad
            - item.nReceiverVerifyKey = nReceiverVerifyKey
            - md4cpy(item.pachTargetClientHashORKadID, pachTargetClientHashORKadID)
            
        - CMuleUDPSocket::SendControlData()
        - CEncryptedDatagramSocket::EncryptSendClient(
            &sendbuffer, 
            len, 
            item.pachTargetClientHashORKadID,  // = KadID
            item.bKad, 
            item.nReceiverVerifyKey,  // = 0
            (item.bKad ? Kademlia::CPrefs::GetUDPVerifyKey(item.IP) : 0));
        - CEncryptedDatagramSocket::EncryptSendClient(
            uint8_t **buf, 
            int bufLen, 
            const uint8_t *clientHashOrKadID, 
            bool kad, 
            uint32_t receiverVerifyKey, 
            uint32_t senderVerifyKey)
            
            - nReceiverVerifyKey = 0
            - 生成1Byte随机数, 需要和协议码不冲突, 而且最低两bit: kadRecvKeyUsed : isEd2k
            - 2Byte随机数randomKeyPart, 作为key salt
            - sendbuffer.SetKey(md5, true);
            - md5:
                - md4cpy(keyData, clientHashOrKadID);
                  PokeUInt16(keyData+16, randomKeyPart);
                  md5.Calculate(keyData, sizeof(keyData));
                  
            - real data part:
                - 以下部分明文
                - +0 xxxxxx01
                - +1 key salt
                - 以下部分加密
                - +3 ENDIAN_SWAP_32(MAGICVALUE_UDP_SYNC_CLIENT)
                - +7 padLen
                - +8 random padding
                - +8+padLen ENDIAN_SWAP_I_32 receiverVerifyKey
                - +8+padLen+4 ENDIAN_SWAP_I_32 senderVerrfyKey
                - +8+padLen+8 kad buffer