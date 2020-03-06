# Encryption

#### Rationale

In our drive towards a Lot49-style system, we needed to introduce a messaging system which could interoperate with lightning, and where lightning payments to relay nodes could be used to incentivise the message's delivery.

Whilst goTenna Mesh has a native messaging system -- in fact this is what we are already using to send any messages between goTenna devices -- this would not be suitable for our encrypted message payloads. This is because although goTenna can natively send an E2E encrypted message between devices, the entire message is encrypted which means that routing nodes would not be able to access the in-flight HTLC (as it would be encrypted for the end node only, no onions here!). Therefore we must send an unencrypted goTenna message, with an encrypted message portion.

#### Implementation

We opted for a scheme where an encrypted message is appended to the cleartext update_add_htlc message, satisfying the above requirement. When the final receiver decrypts the encrypted message, they can take the SHA256 hash of the decrypted payload as the HTLC preimage, where the SHA256 hash of the preimage is the payment_hash. This means that the receiver can decrypt the message to them and fulfil the HTLC in return for delivery using the same data. Fulfilling the HTLC effectively compensates routing nodes for the availability, power usage and bandwidth.


| Operation performed |      Sender       |       Receiver       |
|---------------------|-------------------|----------------------|
| Write message       | cleartext message |                      |
| ECIES encrypt       | encrypted message |                      |
| Send message        |        -->        | encrypted message    |
| ECIES decrypt       |                   | cleartext message    |
| SHA256(cleartext)   |                   | preimage             |
| SHA256(preimage)    |                   | payment_hash         |


#### Scheme

The ECIES encryption scheme was chosen for its ability to encrypt a message using keys based from a SECP256K1 curve point -- e.g. a lightning node public/private key pair. We made some slight modifications to [eciespy](https://github.com/ecies/py) module, whose homepage also includes some helpful breakdown of the scheme.

The scheme with default settings had some drawbacks for our low bandwidth transport layer: a nonce (16 bytes) and an uncompressed ephemeral sender public key (65 bytes) needed to also be transmitted with each message which had quite a negative impact on the remaining message size left for text payloads; recall, goTenna message size is 235 bytes each, limited to 210 bytes in binary mode. For now, we have fixed the nonce and can therefore use fixed “ephemeral” AES key for encryption and decryption, reclaiming these 81 bytes for additional message capacity. Now we only need to send the encrypted message and the 16 byte “tag”, as long as the receiver already knows the public key of the sender.

We are aware that the fixed nonce may impact ECIES’ chosen ciphertext security guarantees, and would lead to the same message being encrypted to the same ciphertext.

To gain knowledge of the original sender we prepend a single byte to the encrypted message: the sender goTenna ID (GID) modulo 256. Although this is not collision-resistant, it works well for a minimal proof of concept. In a system where the receiver might not already have the sender’s full pubkey:GID pair in it’s routing table, we might have to fallback to transmitting a compressed 33 byte public key with the message or switching encryption schemes. However, as we plan to overhaul and harden this in the future, we are happy with this for the time being.

Currently routing nodes are programmed to take 10 satoshis as routing fee each, therefore the sender should include as much fee as they believe the maximum number of hops might be. We are using 100 satoshis per message. Routing nodes are currently “free” to try and steal fees beyond these 10 satoshis per hop (especially if they know they are the last hop) but game theory dictates that if they are too greedy, they might take so much that the “fee pool” runs out before the final hop is reached and they won’t get anything, because the HTLC is never settled. This appears to open up griefing attack vectors, but it is not much different to current lightning network “HODL invoices" or poorly performing nodes: if the route fails, you must wait for the htlc to timeout and try again.
