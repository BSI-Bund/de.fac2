# de.fac2 - FIDO U2F Authenticator Applet v1.34

*de.fac2* is a Javacard applet which implements a Fido U2F token. It was designed and implemented based on the Common Criteria Protection Profile [BSI-CC-PP-0096-V3-2018 "FIDO Universal Second Factor (U2F) Authenticator Version 3"](https://www.bsi.bund.de/SharedDocs/Zertifikate_CC/PP/aktuell/PP_0096_0096V2_0096V3.html).

![Urkunde](https://github.com/tsenger/de.fac2/blob/master/docs/CC/1060_de.fac2_Urkunde_Header.png)

The implementation of this applet on a G+D Sm@rtCafe Expert 7.0 javacard was [certified by the BSI on May 8, 2020](https://github.com/BSI-Bund/de.fac2/blob/master/docs/CC/1060_de.fac2_Urkunde.pdf) and [Fido Level 3+ certified on January 15, 2021](https://github.com/BSI-Bund/de.fac2/blob/master/docs/FIDO%20U2F%20Certificate%20U2F100020210115001%20-%20U2F%20L3%2B%20Authenticator%20-BSI.pdf). This repository contains all sources of the applet. However, the G+D libraries for the Sm@rtCafe platform cannot be provided here. These can only be obtained directly from G+D.

This repository also contains the developer documentation necessary for CC certification. Parts of it have been redacted because they contain proprietary information of third parties.  

The attestation certificate in this repository has been replaced by a sample certificate. The certified token uses an attestation certificate signed by the [BSI FIDO U2F root](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/FIDO_U2F/FIDO_U2F_Root_Zertifikat_cer.html).

#### Notes
1. *The FIDO U2F Authenticator applet described in this certification procedure is set up as a **pilot project, which is not intended for production**. For this reason some requirements of the produced TOE were only exemplary implemented (especially the life cycle ALC) and do not correspond to the requirements for secure products. The certificate is only intended to show the feasibility by means of an exemplary certification.
Nevertheless feel free to use this source and docs as inspiration for your own product. Even though the CC process can be a tough challenge.*

2. *As smartcards have no buttons, the FIDO user presence check with a smartcard is here implemented by inserting the card into a reader or placing the card on an NFC field. After a single action, the presence check flag on the card is disabled.*

3. *The following attack scenario was reported to us by Sergei Volokitin: A reset command send by the reader to the card circumvents the user presence check. For example, malware on the host PC / smartphone could send a reset command to the reader programmatically. It is not possible for the card to distinguish if the reader sent a reset command or if it was physically removed from the reader. With reference to this scenario, the Guidance Documentation (AGD) and the Security Target (ST) were updated in July 2022 in a "Assurance Maintenance".*

