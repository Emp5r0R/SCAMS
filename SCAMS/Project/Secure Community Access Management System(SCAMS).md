**What is Project SCAMS in General?
- SCAMS is a proposed IOT utilization of NFC technology, using the same with robust cryptographic algorithms to prevent tampering and many other frequency attacks in NFC.
### Proposal
- Implementing Asymmetric encryption algorithm in NFC to perform secure transition between NFC card/Tag and NFC Reader .This can be done by equipping the NFC card/tag with EMV chips or using cards that supports encryption and decryption (Eg,. MIFARE DESFire, MIFARE Plus, or any CIPURSE compliant cards)

- Cards use mutual authentication protocols where both the reader and the card authenticate each other before any date exchange.

- After authentication, a secure channel is established for da0
- After secure transaction between NFC card/tag and NFC reader data will be stored in Cloud in the format of Hash

	- ![[4-Pass Mutual Authentication Model.canvas|4-Pass Mutual Authentication Model]]
### Mitigation against common Problems or Attacks

- Cannot be tampered as uses encryption and decryption algorithms
- Frequencies cannot be captured as uses secure channel/protocol and cryptographic algorithms before UID transfer.
- Algorithms cannot be replicated as uses Asymmetric cryptographic algorithms with PRIVATE and PUBLIC keys.

### Public use cases

-  Can be used as authenticator in a public spaces.
- Can be used in Public buses , Government buildings, Gated communities as authenticator
- Can be used in Credit and Debit cards
- Using in Public/Common places helps to maintain the Higher privileged hierarchy (Eg.., places where general public cannot be entered or only for employs)   