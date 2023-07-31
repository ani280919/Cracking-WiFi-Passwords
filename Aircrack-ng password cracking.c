//PseudoCode For Cracking WPA/WPA2 PSK's through Dictionary Attack by AirCrack-NG
AirCrack_passphrase_cracking(pcap_file, password_list){
  1. Processingpcap file - Extract all handshake and beacon packets from pcap_file
      tshark -r pcap_file -R "eapol || wlan.fc.type_subtype == 0x08" -w extracted_pcap

      a_mac: Authenticator(AP) MAC Address
      s_mac: Supplicant (client) MAC Address
      a_nonce: Authenticator(AP) Nonce
      s_nonce: Supplicant(client) Nonce

  2. while (there exits a dictionary entry i in password.lst){
    2.1 passphrase= dictionary_entry[i]
    //construction of Pair-Wise Master Key(PMK)
    //PMKs are created using the Password-Based Key Derivation Function #2 (PBKDF2), with the SHA1 hashing function used with HMAC as the message authentication code
    2.2 PMK = PBKDF2(HMAC_SHA1, PSK, SSID, len(SSID), 4096, 256)
    //Four Way Handshake now produces a new key - PTK (Pair-Wise Transient Key)
    //Input to PTK :
    //Pairwise Master Key(PMK)
    //Authenticator Nonce
    //Supplicant Nonce
    //Authenticator MAC Address
    //Supplicant MAC Address
    2.3 key_data= min(a_mac,s_mac) + max(a_mac,s_mac) + min(a_nonce,s_nonce) + max(a_nonce,s_nonce)
    2.4 PTK = PRF(PMK,"Pairwise Key Expansion",key_data)
    //extract Key-Confirmation-Key (KCK) from PTK (First 16B)
    2.5 KCK = PTK [:16]
    2.6 EAPOL_data=extracted from raw handshake message 2
    2.7 EAPOL_data_with_zeroed_MIC= replace the 16 bytes of MIC field by '\x00'in EAPOL_data
    //compute the Message Integrity Code(MIC)
    //WPA1 uses HMAC with MD5 hash function, WPA2 uses HMAC with SHA1 hash
    2.8 if WPA1
           calculated_MIC = HMAC_MD5(KCK,EAPOL_data_with_zeroed_MIC, size(EAPOL_data))
        if WPA2
          calculated_MIC = HMAC_SHA1(KCK,EAPOL_data_with_zeroed_MIC,size(EAPOL_data))
    //calculated_MIC compared with the raw MIC to determine the correctness of the assumed PSK.
    2.9 MIC = get MIC from raw EAPOL packet 2
    3.0 if(calculated_MIC == MIC)
              print ("Key Found-- Success")
        else
              print("Key Not Found -- Failure")
    
  }
}