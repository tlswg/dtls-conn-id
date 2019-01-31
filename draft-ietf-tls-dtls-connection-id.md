---
title: Connection Identifiers for DTLS 1.2
abbrev: DTLS 1.2 Connection ID
docname: draft-ietf-tls-dtls-connection-id-latest
category: std
updates: 6347

ipr: pre5378Trust200902
area: Security
workgroup: TLS
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+
  docmapping: yes
author:
 -
       ins: E. Rescorla
       name: Eric Rescorla
       organization: RTFM, Inc.
       role: editor
       email: ekr@rtfm.com

 -
       ins: H. Tschofenig
       name: Hannes Tschofenig
       organization: Arm Limited
       role: editor
       email: hannes.tschofenig@arm.com
 -
       ins: T. Fossati
       name: Thomas Fossati
       organization: Arm Limited
       email: thomas.fossati@arm.com


normative:
  RFC2119:
  RFC5246:
  RFC6347:
  RFC8446:
informative:
  RFC6973:
  I-D.ietf-tls-dtls13:

--- abstract

This document specifies the Connection ID (CID) construct for the Datagram Transport
Layer Security (DTLS) protocol version 1.2.

A CID is an identifier carried in the record layer header that gives the
recipient additional information for selecting the appropriate security association.
In "classical" DTLS, selecting a security association of an incoming DTLS record
is accomplished with the help of the 5-tuple. If the source IP address and/or
source port changes during the lifetime of an ongoing DTLS session then the
receiver will be unable to locate the correct security context.

--- middle


#  Introduction

The Datagram Transport Layer Security (DTLS) protocol was designed for
securing connection-less transports, like UDP. DTLS, like TLS, starts
with a handshake, which can be computationally demanding (particularly
when public key cryptography is used). After a successful handshake,
symmetric key cryptography is used to apply data origin
authentication, integrity and confidentiality protection. This
two-step approach allows endpoints to amortize the cost of the initial
handshake across subsequent application data protection. Ideally, the
second phase where application data is protected lasts over a longer
period of time since the established keys will only need to be updated
once the key lifetime expires.

In the current version of DTLS, the IP address and port of the peer are used to
identify the DTLS association. Unfortunately, in some cases, such as NAT rebinding,
these values are insufficient. This is a particular issue in the Internet of Things
when devices enter extended sleep periods to increase their battery lifetime. The
NAT rebinding leads to connection failure, with the resulting cost of a new handshake.

This document defines an extension to DTLS 1.2 to add a Connection ID (CID) to the
DTLS record layer. The presence of the CID is negotiated via a DTLS
extension.

# Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 {{RFC2119}}.

The reader is assumed to be familiar with DTLS {{RFC6347}}.


# The "connection_id" Extension

This document defines the "connection_id" extension, which
is used in ClientHello and ServerHello messages.

The extension type is specified as follows.

~~~~
  enum {
     connection_id(TBD), (65535)
  } ExtensionType;
~~~~

The extension_data field of this extension, when included in the
ClientHello, MUST contain the Connection_ID structure, which carries the CID which
the client wishes the server to use when sending messages towards it.
A zero-length value indicates that the client is prepared to send
with a CID but does not wish the server to use one when
sending (alternately, this can be interpreted as the client wishes
the server to use a zero-length CID; the result is the same).

~~~~
  struct {
      opaque cid<0..2^8-1>;
  } Connection_ID;
~~~~

A server which is willing to use CIDs will respond with its own
"connection_id" extension, containing the CID it wishes the
client to use when sending messages towards it. A zero-length value
indicates that the server will send with the client's CID but does not
wish the client to use a CID (or again, alternately, to use a
zero-length CID).

When a session is resumed, the "connection_id" extension is
negotiated afresh, not retained from previous connections in
the session.

This is effectively the simplest possible design that will work.
Previous design ideas for using cryptographically generated session
ids, either using hash chains or public key encryption, were dismissed
due to their inefficient designs. Note that a client always has the
chance to fall back to a full handshake or more precisely to a
handshake that uses session resumption.

Because each party sends a CID value in the "connection_id" extension that it wants to 
receive in encrypted records, it is possible
for an endpoint to use a globally constant length for such CIDs.  
This can in turn ease parsing and connection lookup,
for example by having the length in question be a compile-time constant.
Implementations, which want to use variable-length CIDs, are responsible
for constructing the CID in such a way that its length can be determined
on reception. Note that such implementations must still be able to send
connection identifiers of different length to other parties.

Note that it is not possible to parse the records without knowing how 
long the CID is.

In DTLS 1.2, CIDs are exchanged at the beginning of the DTLS
session only. There is no dedicated "CID update" message
that allows new CIDs to be established mid-session, because
DTLS 1.2 in general does not allow TLS 1.3-style post-handshake messages
that do not themselves begin other handshakes. 

DTLS peers switch to the new record layer format, i.e., the record layer format 
containing the CID, when encryption is enabled.

# Record Layer Extensions and Record Payload Protection

This specification defines the DTLS 1.2 record layer format and 
{{I-D.ietf-tls-dtls13}} specifies how to carry the CID in DTLS 1.3.

In order to allow a receiver to determine whether a record has CID or not,
connections which have negotiated this extension use a distinguished
record type tls12_cid(25). Use of this content type has the following
two implications:

- The CID field is present
- The true content type is inside the encryption envelope, as described
  below.

When CID are being used, the content to be sent is first wrapped
along with the true content type and padding into a DTLSInnerPlaintext
value prior to encryption. The DTLSInnerPlaintext value is then
encrypted. {{dtls-record12}} illustrates the record format. 

~~~~
     struct {
         ContentType type;
         ProtocolVersion version;
         uint16 epoch;                         // DTLS field
         uint48 sequence_number;               // DTLS field
         uint16 length;
         opaque fragment[DTLSPlaintext.length];
     } DTLSPlaintext;

     struct {
         opaque content[DTLSPlaintext.length];
         ContentType type;
         uint8 zeros[length_of_padding];
     } DTLSInnerPlaintext;

     struct {
         ContentType special_type = tls12_cid; /* 25 */
         ProtocolVersion version;
         uint16 epoch;                         // DTLS field
         uint48 sequence_number;               // DTLS field
         opaque cid[cid_length];               // New field
         uint16 length;
         opaque encrypted_record[TLSCiphertext.length];
     } DTLSCiphertext;
~~~~
{: #dtls-record12 title="DTLS 1.2 Record Format with the CID"}

content
:  This field contains the byte encoding of a handshake, an alert 
   message, or the raw bytes of the application's data to send.

type
:  The DTLSInnerPlaintext.type value contains the content type of the
   record. This is the non-obfuscated (true) content type.

zeros
:  An arbitrary-length run of zero-valued bytes may appear in
   the cleartext after the type field.  This provides an opportunity
   for senders to pad any DTLS record by a chosen amount as long as
   the total stays within record size limits.  See Section 5.4 of
   for {{RFC8446}} more details. (Note that TLSInnerPlaintext in 
   that section refers to DTLSInnerPlaintext in this specification.) 

special_type
:  The outer opaque_type field of a DTLSCiphertext record
   is always set to the value 25 (tls12_cid). The actual content 
   type of the record is found in DTLSInnerPlaintext.type after 
   decryption. By encapsulating the true content type inside the 
   encrypted payload the outer content type (special_type) can be
   used to signal the new record layer format containing the CID. 

version
:  The DTLSCiphertext.version field describes the protocol being employed.
   This document describes an extension to DTLS version 1.2. 

length
:  The DTLSCiphertext.length field indicates the length (in bytes) of 
   the following DTLSCiphertext.encrypted_record, which is the sum of 
   the lengths of the content and the padding, plus one for the inner 
   content type, plus any expansion added by the AEAD algorithm.    

cid
:  The CID value of length indicated with cid_length, as agreed during the 
   exchange.

encrypted_record
:  The AEAD-encrypted form of the serialized DTLSInnerPlaintext structure.

Other fields are defined in RFC 6347. Note that this specification does 
not make use of the DTLSCompressed structure. 

In addition, the CID value is included in the MAC calculation for the
DTLS record layer. At the time of writing ciphers using authenticated 
encryption with additional data (AEAD) were state-of-the-art. Hence, this 
specification updates only the additional data calculation defined in 
Section 6.2.3.3 of {{RFC5246}}, which is re-used by Section
4.1.2.1 of {{RFC6347}}. 

The additional data calculation is extended as follows:

~~~~
    additional_data = seq_num + type + version +  
                      cid + cid_length + length;

    where "+" denotes concatenation. 
~~~~

seq_num
: As described in Section 6.2.3.3 of {{RFC5246}} this 64-bit value 
is formed by concatenating the epoch and the sequence number in the 
order they appear on the wire.

type
: This value contains the outer-header content type, i.e. the tls12_cid. 

version
: This value contains the version number. 

length
: This value contains the length information in the outer-header. 

cid
: Value of the negotiated CID. This field is empty in case 
a zero-length CID has been negotiated.

cid_length
: 1 byte field indicating the length of the negotiated CID. 
If a zero-length CID has been negotiated, and therefore no 
CID appears on the wire, a cid_length of zero (0) MUST be added. 

# Examples

{{dtls-example2}} shows an example exchange where a CID is
used uni-directionally from the client to the server. To indicate that 
a zero-length CID we use the term 'connection_id=empty'.

~~~~
Client                                             Server
------                                             ------

ClientHello                 -------->
(connection_id=empty)       


                            <--------      HelloVerifyRequest
                                                     (cookie)

ClientHello                 --------> 
(connection_id=empty)
(cookie)                   

                                                  ServerHello
                                          (connection_id=100)
                                                  Certificate
                                            ServerKeyExchange
                                           CertificateRequest
                            <--------         ServerHelloDone

Certificate                 
ClientKeyExchange
CertificateVerify
[ChangeCipherSpec]
Finished                    -------->
<CID=100>                   

                                           [ChangeCipherSpec]
                            <--------                Finished


Application Data            ========>
<CID=100>

                            <========        Application Data

Legend:

<...> indicates that a connection id is used in the record layer
(...) indicates an extension
[...] indicates a payload other than a handshake message
~~~~
{: #dtls-example2 title="Example DTLS 1.2 Exchange with CID"}

Note: In the example exchange the CID is included in the record layer 
once encryption is enabled. In DTLS 1.2 only one handshake message is 
encrypted, namely the Finished message. Since the example shows how to 
use the CID for payloads sent from the client to the server only the 
record layer payload containing the Finished messagen contains a CID. 
Application data payloads sent from the client to the server contain 
a CID in this example as well. 

#  Security and Privacy Considerations {#sec-cons}

The CID replaces the previously used 5-tuple and, as such, introduces
an identifier that remains persistent during the lifetime of a DTLS connection.
Every identifier introduces the risk of linkability, as explained in {{RFC6973}}.

In addition, endpoints can use the CID to attach arbitrary metadata
to each record they receive. This may be used as a mechanism to communicate
per-connection information to on-path observers. There is no straightforward way to
address this with CIDs that contain arbitrary values; implementations
concerned about this SHOULD refuse to use connection ids.

An on-path adversary, who is able to observe the DTLS protocol exchanges between the
DTLS client and the DTLS server, is able to link the observed payloads to all
subsequent payloads carrying the same connection id pair (for bi-directional
communication).  Without multi-homing or mobility, the use of the CID
is not different to the use of the 5-tuple.

With multi-homing, an adversary is able to correlate the communication
interaction over the two paths, which adds further privacy concerns.

Importantly, the sequence number makes it possible for a passive attacker
to correlate packets across CID changes. Thus, even if a client/server pair
do a rehandshake to change CID, that does not provide much privacy benefit.

This document does not change the security properties of DTLS {{RFC6347}}.
It merely provides a more robust mechanism for associating an incoming packet
with a stored security context.

#  IANA Considerations

IANA is requested to allocate an entry to the existing TLS "ExtensionType
Values" registry, defined in {{RFC5246}}, for connection_id(TBD) defined in
this document.

IANA is requested to allocate tls12_cid(25) in the "TLS ContentType
Registry".

--- back

# History

RFC EDITOR: PLEASE REMOVE THE THIS SECTION

draft-ietf-tls-dtls-connection-id-03

  - Updated list of contributors

draft-ietf-tls-dtls-connection-id-02

  - Move to internal content types a la DTLS 1.3.

draft-ietf-tls-dtls-connection-id-01

  - Remove 1.3 based on the WG consensus at IETF 101

draft-ietf-tls-dtls-connection-id-00

  - Initial working group version
    (containing a solution for DTLS 1.2 and 1.3)

draft-rescorla-tls-dtls-connection-id-00

  - Initial version

# Working Group Information

RFC EDITOR: PLEASE REMOVE THE THIS SECTION

The discussion list for the IETF TLS working group is located at the e-mail
address <tls@ietf.org>. Information on the group and information on how to
subscribe to the list is at <https://www1.ietf.org/mailman/listinfo/tls>

Archives of the list can be found at:
<https://www.ietf.org/mail-archive/web/tls/current/index.html>

# Contributors

Many people have contributed to this specification and we would like to thank 
the following individuals for their contributions:

~~~
* Yin Xinxing
  Huawei
  yinxinxing@huawei.com
~~~

~~~
* Nikos Mavrogiannopoulos
  RedHat
  nmav@redhat.com
~~~

~~~
* Tobias Gondrom 
  tobias.gondrom@gondrom.org
~~~

Additionally, we would like to thank the Connection ID task force team members:

- Martin Thomson (Mozilla)
- Christian Huitema (Private Octopus Inc.)
- Jana Iyengar (Google)
- Daniel Kahn Gillmor (ACLU)
- Patrick McManus (Mozilla)
- Ian Swett (Google)
- Mark Nottingham (Fastly)

Finally, we want to thank the IETF TLS working group chairs, Chris Wood, Joseph Salowey, and Sean Turner, for their patience, support and feedback.

# Acknowledgements

We would like to thank Achim Kraus for his review feedback. 
