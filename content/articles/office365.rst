==============================================
The road to hell is paved with SAML Assertions
==============================================

:date: 2016-04-27
:modified: 2016-04-27 12:40
:tags: SAML, office 365, impersonation, Single-Sign-On
:category: bounty
:slug: office365-authbypass
:authors: Ioannis Kakavas, Klemen Bratec
:summary: Cross Domain Authentication Bypass in Office 365

TL;DR
+++++
A vulnerability in Microsoft Office 365 SAML Service Provider implementation allowed for cross domain authentication bypass affecting **all** federated domains. An attacker exploiting this vulnerability could gain unrestricted access to a victim's Office 365 account, including access to their email, files stored in OneDrive etc.

This vulnerability was jointly discovered by Klemen Bratec from `Šola prihodnosti Maribor <http://www.sola-prihodnosti.si/en/>`_, and Ioannis Kakavas from `Greek Research and Technology Network <http://www.grnet.gr>`_ and this blog post is cross-posted here and on `Klemen's blog <https://bratec.si/security/2016/04/27/road-to-hell-paved-with-saml-assertions.html>`_.

Microsoft fixed the vulnerability within **7 hours** of our report and handled the disclosure process admirably.

Short SAML introduction
+++++++++++++++++++++++
``Well, wait, I lost you on the 8th word, what is SAML ?``

SAML stands for Security Assertion Markup Language and is an XML-based standard for exchanging authentication and authorization data between parties. The prominent use of SAML is 
for Cross Domain Web Single-Sign-On.
This is an overview of the SAML 2.0 Web Browser SSO Profile, short enough to get the gist of it so you can understand the following sections, long enough to bore you if you are
familiar with SAML already, so feel free to skip to `How Office 365 SAML implementation works`_.


Important Concepts
------------------
This section focuses on SAML 2.0. The most important components of the SAML specification are the following:

**Assertions**

Assertions are XML structures that contain packaged security information about the user. The two mostly used assertion types are

1. Authentication Assertions that contain the information that the user has proven their identity
2. Attribute Assertions that contain specific information about the user in the format of attributes ( such as email address, name, etc. )

**Protocols**

SAML protocols describe how certain SAML elements (including assertions) are packaged within request and response elements, and gives the processing rules that SAML entities must follow when producing or consuming these elements. The Authentication Request Protocol is described later on. 

**Bindings**

SAML bindings describe how a SAML message must be mapped on non SAML related messaging formats and communication protocols. For instance the *HTTP Redirect Binding* defines how SAML messages are formatted when carried directly in the URL query string of an HTTP GET request. A SAML request is transmitted via an SAMLRequest query parameter, the value of which is deflated, base64 encoded and URL encoded.

**Identity Provider**

The identity provider is the SAML authority that holds the information about users and can issue assertions for them to use in Service Providers. 

**Service Provider**

The service provider is the SAML consumer that consumes the information (in the form of assertions) about the users in order to allow them access to resources.


Web Browser SSO Example
-----------------------

A simple example of the Web Browser SSO Profile is the case where the service provider uses the HTTP Redirect binding and the identity provider uses the HTTP POST binding. The actors involved are

1. The principal (user) using a browser
2. The Identity Provider
3. The Service Provider

.. figure:: /images/SAMLwebsso.png
   :alt: SAML2.0 Web Browser SSO Profile example

   SAML2.0 Web Browser SSO Profile Example


It all starts with a user attempting to access a protected resource at some service (or explicitly asking to log in). The service is configured to allow/enforce federated login and as such presents or redirects the user
to a Discovery Service interface in order to select their Identity Provider. Upon user selection, and given that it knows and trusts the selected Identity Provider, the Service Provider creates a SAML Authentication Request that looks like this:

.. code:: xml

 <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_bec424fa5103428909a30ff1e31168327f79474984" Version="2.0" 
                     IssueInstant="2016-04-14T11:39:34Z" ForceAuthn="false" IsPassive="false" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
                     AssertionConsumerServiceURL="https://myserviceprovider.atsomeorg.com/Shibboleth.sso/SAML2/POST">
      <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://myserviceprovider.atsomeorg.com/shibboleth</saml:Issuer>
      <samlp:NameIDPolicy xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
             Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" 
             AllowCreate="true" />
 </samlp:AuthnRequest>

- *Issuer* is the EntityID of the Service Provider which is a URI like string that uniquely identifies it. The *Issuer* denotes which Service Provider requests the user authentication.
- *IssueIstant* indicates when this request is made and the *ID* is an internal identifier that the Service Provider uses to match the SAML Response that it will later receive to the originating request. 

The user's browser is then redirected to the respective URL at the Identity Provider depending on the binding that is used and that SAML Authentication Request is passed as a string query parameter in the HTTP GET ( after it has been deflated , base64 encoded and URL encoded ). 

Upon receiving the SAML Request, the Identity Provider checks that it knows and trusts the Service Provider that sends it, validates the contents of the Request  and prompts the user for authentication. If the 
user authenticates successfully, the Identity Provider generates a SAML response, that looks something like this: 

.. code:: xml

 <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
                 ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2016-04-14T11:40:48Z" 
                 Destination="https://myserviceprovider.atsomeorg.com/Shibboleth.sso/SAML2/POST" 
                 InResponseTo="_bec424fa5103428909a30ff1e31168327f79474984">
  <saml:Issuer>http://idp.example.com/idp/shibboleth</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" 
                  ID="pfx65c8c6cd-b03b-8634-fd54-636fa66e7722" Version="2.0" IssueInstant="2016-04-14T11:40:48Z">
    <saml:Issuer>http://idp.example.com/idp/shibboleth</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference URI="#pfx65c8c6cd-b03b-8634-fd54-636fa66e7722">
      <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>gxnHkIizISbLkkB1vSWapmWuQzk=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>Qn69P4a3PQTISfqk/0t2JdJqG1nlswFQt8bNWPZ+K41EIYkCcTyuwlKnCzlTvU1YgNXIvHcFEyKjYAge+s3gwqecATI+yRB9OtD34YxBC4kyGcbq/ETQxIQ515xehfRxLrQjUpRzgHQXMLSjGdgjeelfKsHeSczA9Hp44kasQSs=</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==
        </ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID SPNameQualifier="https://myserviceprovider.atsomeorg.com/shibboleth" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2016-04-14T11:50:48Z" Recipient="https://myserviceprovider.atsomeorg.com/Shibboleth.sso/SAML2/POST" InResponseTo="_bec424fa5103428909a30ff1e31168327f79474984"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2016-04-14T11:40:48Z" NotOnOrAfter="2016-04-14T11:50:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://myserviceprovider.atsomeorg.com/shibboleth</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2016-04-14T11:40:48Z" SessionNotOnOrAfter="2016-04-14T11:50:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
 </samlp:Response>
    
and instructs the user browser to make a HTTP POST request to - in this case - https://myserviceprovider.atsomeorg.com/Shibboleth.sso/SAML2/POST. 
 - *InResponseTo* contains the value that was sent as an ID in the SAML Request so that the Service Provider can match this to the request it sent. ( and to avoid replay attacks )
 - *IssueIstant*, *NotBefore* and *NotOnOrAfter* define a time interval for which the SAML Response ( and Assertion ) is valid, in order to protect against replay attacks. 
 - The Assertion contains in *Issuer* field so that the Service Provider can verify that the Assertion comes from the Identity Provider it expects it to come from.
 - The Assertion also contains an AudienceRestriction element that defines that this Assertion is targeted for a specific Service Provider and cannot be used for any other Service Provider.
 - The Assertion contains a Subject element which identifies the authenticated principal(user)  
 - The AttributeStatement part of the Assertion contains attributes and their values for the specific user that comes as authenticated. 

The Assertion (and possibly the whole SAML Response) is signed with a `XML Signature <https://en.wikipedia.org/wiki/XML_Signature>`_ that protects the integrity of the Assertion (or response) and verifies that it has not 
been modified in transit. 

Upon receiving the SAML Response, the Service Provider can verify its contents and structure, validate the signature and subsequently treat the user as authenticated initiating a web session for them.

By now, you should have wondered about at least a couple of things:
 1. How does the Service Provider know and trust the Identity Provider?
 2. How does the Identity Provider know and trust the Service Provider?
 3. The Identity Provider signs that Assertion with what?
 4. How does the Service Provider verify the signature when it receives the Assertion?

What is purposely left out here for brevity is that the Identity Provider and the Service Provider need to bootstrap their trust somehow before all the above can happen. In order to do that, they need to exchange metadata. The metadata contain information like the certificate with the public key that corresponds to the private key that the Identity Provider uses to sign the Assertions, the URLs that correspond to each entity's bindings, the algorithms they support/request, etc. There are two ways for them to know each other's metadata
 - Either the Identity Provider and the Service Provider bootstrap their trust relationship bilaterally by exchanging metadata in a secure manner. 
 - Or both delegate this trust to a 3rd party by joining a Federation. The Federation Operator then assumes the task to gather the metadata from all entities that participate, sign and publish the aggregates. Each Identity Provider and Service Provider then consumes that metadata in order to get information about the rest of the entities that participate in that Federation.


How Office 365 SAML implementation works
++++++++++++++++++++++++++++++++++++++++

The Office 365 service provider implementation is a weird mixture of WS-Trust specification and SAML 2.0 Web Browser SSO Profile. That is, Office 365 supports SSO both with WS-Trust and with SAML 2.0 Web Browser SSO but the two implementations are not isolated. This is why, for example, in the `official documentation for SAML 2.0 SSO <https://msdn.microsoft.com/en-us/library/azure/jj205456.aspx>`_ shibboleth identity provider is referred to as a *Security Token Service*, terminology that is relevant to WS-Trust specification but not SAML. 
The SAML service provider is, however, SAML 2.0 compliant-ish (sic) from the perspective of a SAML identity provider and uses a token translation service to convert SAML messages to WS-Trust messages internally. This encapsulation becomes specifically relevant later on, when discussing the attack surface in `How could this be exploited?`_ as the vulnerability found in the SAML Service Provider implementation also affects the WS-Trust SSO implementation because of this token translation service.  

However, for the sake of simplicity, for the rest of this section the Office 365 service provider is considered to be a SAML service provider.

One additional thing to keep in mind is that Office 365 does not support Just-In-Time provisioning for accounts authenticating via SAML, so for Signle Sign On to work the account must already be registered in Azure AD for the 
specific tenant. This can happen via Directory Synchronization or via user provisioning with the help of an IDM system, but this is out of the scope of this post. 

The attributes that are required to be released from an Identity Provider to the Office 365 Service Provider for the user are two:
 - The UPN of the user expressed in an attribute with name IDPEmail
 - An ImmutableId that is what uniquely identifies the user, expressed in the Subject of the SAML Assertion


The process starts with the user accessing `Office 365 portal <https://portal.office.com>`_, being redirected to *https://login.microsoftonline.com/login.srf* where he is greeted with the following form

.. figure:: /images/office365-1.png
   :alt: Office 365 portal login form
   :width: 80 %
 
   Office 365 portal login form

Upon entering the username and pressing TAB or clicking on the password field, the page makes an XHR to *https://login.microsoftonline.com/common/userrealm* in order to check if the user's domain corresponds to an Office 365
tenant

.. code::

 GET /common/userrealm/?user=ikakavas@testdomain.gr&api-version=2.1&stsRequest=rQIIAbNSzigpKSi20tcvyC8qSczRy09Ly0xO1UvOz9XLL0rPTAGxioS4BMruuVuZ2Fh77Wj-e6KxLMF2FaMaTp36OYl5KZl56XqJxQUVFxgZu5hYDA2MjTcxsfo6-zp5nmCacFbuFpOgf1G6Z0p4sVtqSmpRYklmft4jJt7Q4tQi_7ycypD87NS8Scx8OfnpmXnxxUVp8Wk5-eVAAaDxBYnJJfElmcnZqSW7mFVSU00tTCxTUnRNkpOTdU2Sksx0kwxSzXRTzZMtTC1ME00Mk1MOsGwIucAi8IOFcREr0C-3A6ZLrn182Gt-tWV-vVlpwi5OW-L8Yl-SWJSeWmKrapSWkpqWWJpTAhYGAA2&checkForMicrosoftAccount=false HTTP/1.1
 Host: login.microsoftonline.com
 User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0
 Accept: application/json
 Accept-Language: en-US,en;q=0.5
 Accept-Encoding: gzip, deflate, br
 DNT: 1
 X-Requested-With: XMLHttpRequest
 Referer: https://login.microsoftonline.com/login.srf?wa=wsignin1.0&rpsnv=4&ct=1460721662&rver=6.7.6640.0&wp=MCMBI&wreply=https%3a%2f%2fportal.office.com%2flanding.aspx%3ftarget%3d%252fdefault.aspx&lc=1033&id=501392&msafed=0&client-request-id=3a47de76-3c34-4a3b-b883-fdc88176603d


If the domain is known and configured as federated, the user's browser is instructed to make an HTTP POST request to the HTTP-POST binding URL of the Identity Provider for that domain with a SAML Response in the body that looks like this:

.. code:: xml

 <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_f6daef39-fb54-407e-abb4-c75d261b75ae"
                    IssueInstant="2016-04-11T21:13:44Z"
                    Version="2.0"
                    AssertionConsumerServiceIndex="0"
                    >
    <saml:Issuer>urn:federation:MicrosoftOnline</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" />
 </samlp:AuthnRequest>

The user is then prompted for authentication in the Identity Provider 

.. figure:: /images/office365-2.png                                                                                                                                                                                                    
   :alt: Idenity Provider login form

   Idenity Provider login form


and subsequently their browser is instructed to make an HTTP POST back to the HTTP-POST binding URL of Office 365, *https://login.microsoftonline.com/login.srf* with the SAML Response containing the Assertion in the request body. An example of this SAML Response is seen below

.. code:: xml

 <saml2p:Response Destination="https://login.microsoftonline.com/login.srf"
                 ID="_cefc5f992f2e455d7b3e52522fc479db" InResponseTo="_f6daef39-fb54-407e-abb4-c75d261b75ae"
                 IssueInstant="2016-04-11T21:14:35.365Z" Version="2.0" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.admin.grnet.gr/idp/shibboleth</saml2:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
            <ds:Reference URI="#_cefc5f992f2e455d7b3e52522fc479db">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                        <ec:InclusiveNamespaces PrefixList="xsd" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transform>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                <ds:DigestValue>dc1f3jn97lZ6FWdxGxsEWxXNsTM=</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>
        Removed for brevity
        </ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>
                Removed for brevity
                </ds:X509Certificate>
           </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </saml2p:Status>
    <saml2:Assertion ID="_b971f4e7f575bcc9cbc9034246c62c98" IssueInstant="2016-04-11T21:14:35.365Z" Version="2.0"
                     xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <saml2:Issuer>https://idp.admin.grnet.gr/idp/shibboleth</saml2:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
                <ds:Reference URI="#_b971f4e7f575bcc9cbc9034246c62c98">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                            <ec:InclusiveNamespaces PrefixList="xsd" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                        </ds:Transform>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                    <ds:DigestValue>WBgE+nW+3g9P5XpiZwGE06MT//g=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>
            Removed for brevity
            </ds:SignatureValue>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>
                    Removed for brevity
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
        <saml2:Subject>
            <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">This is where my ImmutableId is</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData Address="2a02:214d:811b:7200:dc15:b7bc:a304:3738" InResponseTo="_f6daef39-fb54-407e-abb4-c75d261b75ae"
                                               NotOnOrAfter="2016-04-11T21:19:35.384Z" Recipient="https://login.microsoftonline.com/login.srf"/>
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="2016-04-11T21:14:35.365Z" NotOnOrAfter="2016-04-11T21:19:35.365Z">
            <saml2:AudienceRestriction>
                <saml2:Audience>urn:federation:MicrosoftOnline</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="2016-04-11T21:14:35.027Z" SessionIndex="_91380d0480ac9af6bcb19f3b26f0ea81">
            <saml2:SubjectLocality Address="2a02:214d:811b:7200:dc15:b7bc:a304:3738" />
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
        <saml2:AttributeStatement>
            <saml2:Attribute FriendlyName="IDPEmail" Name="IDPEmail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xsd:string">ikakavas@mymail.example.com</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement>
    </saml2:Assertion>
 </saml2p:Response>

The ImmutableId that uniquely identifies the user is in the Subject of the Assertion

.. code:: xml

 <saml2:Subject>
        <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">This is where my ImmutableId is</saml2:NameID>
        <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml2:SubjectConfirmationData Address="2a02:214d:811b:7200:dc15:b7bc:a304:3738" InResponseTo="_f6daef39-fb54-407e-abb4-c75d261b75ae"
                                               NotOnOrAfter="2016-04-11T21:19:35.384Z" Recipient="https://login.microsoftonline.com/login.srf"/>
        </saml2:SubjectConfirmation>
 </saml2:Subject>

and the IDPEmail that corresponds to the UPN of the existing account of the user in Azure AD is contained in the Attribute Statement

.. code:: xml

 <saml2:AttributeStatement>
        <saml2:Attribute FriendlyName="IDPEmail" Name="IDPEmail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xsd:string">ikakavas@mymail.example.com</saml2:AttributeValue>
        </saml2:Attribute>
 </saml2:AttributeStatement>

It can also be seen that both the SAML Response and the SAML Assertion are digitally signed. 

What was wrong about the Office 365 Implentation? 
+++++++++++++++++++++++++++++++++++++++++++++++++

In the process of integrating Office 365 as a Service Provider in the `Greek AAI Federation <https://aai.grnet.gr>`_ using the AAI365 solution that `Šola prihodnosti Maribor <http://www.sola-prihodnosti.si/en/>`_ offers we came up with some interesting flaws in how Microsoft implements the SAML Service Provider. 


What about SAML NameID?
---------------------------------
The first thing we noticed is that Office 365 SAML Service Provider disregards the Subject of the Assertion, even though it contains the ImmutableId value that should be the UUID of the user in the Azure AD that would uniquely identify him. 
 
A name identifier, represented by the <NameID> element in SAML 2, is generally used to identify the subject of a SAML assertion. Name identifiers can be anything; an email address or a Kerberos principal name are common, every-day examples of such information. SAML 2 also defines more specialized identifier types with particular properties useful in federated applications. Strictly speaking, SAML assertions don't have to contain an identifier. The subject may be implicitly identified as the bearer of the token or anybody able to demonstrate possession of a key. In SSO use cases, one reason for including an identifier is to enable the relying party to refer to the subject later, such as in a query, or a logout request. 

From an attacker's perspective, the fact that the correctness of the NameID is not checked, makes things easier since the ImmutableID usually comes from AD objectGUID and it's hard to guess or bruteforce. 

Scoping
-------
That leaves the value of the IDPEmail attribute that corresponds to the UPN of the user in the Azure AD, as the sufficient piece of information to identify the user in the Assertion. Well, ok, this is not necessarily
bad in itself as the Assertion also contains the Issuer that generated and signed it, so an unrelated Identity Provider cannot create assertions for other domain's/tenant's users, right? Wrong. 

As it turns out, the Service Provider used the Issuer of the Assertion only to find the mathing certificate in order to verify the SAML Response/Assertion signature, but didn't perform any sanity checks on the supplied
value of the IDPEmail attribute. That basically means that it would happily consume assertions, asserting that Identity Provider X has authenticated users of Identity Provider Y. 

In SAML world this can be  mitigated with the help of scoped attributes. These are attributes that have 2 parts, a value and a scope in the format value@scope. The Identity Provider publishes the scope that it
is authoritative for in it's Metadata and Service Providers are supposed to check that when they consume a scoped attribute from an Identity Provider, they check that the scope that came matches the published one. UPN a.k.a. IDPEmail is scoped by definition as the domain part needs to be one of the (sub-)domains that the administrator has verified in an Office365 tenant.   

How could this be exploited?
----------------------------
At the time of discovery we already had one Office 365 tenant setup as a playground for connecting Office 365 and SAML 2 identity providers. We had a basic Active Directory instance and `SimpleSAMLphp <https://simplesamlphp.org/SimpleSAMLphp>`_ as our Identity Provider. 

The first thing was setting up another organization playing a part of the victim in our experiments. This included a new Office 365 trial subscription and another SimpleSAMLphp instance with a different EntityID.

Our testing enviroment therefore looked something like this:

1. First Office 365 subscription with **someorg-attacker.com** being authenticated at http://idp.someorg-attacker.com/

2. Second Office 365 subscription with **someorg-victim.com** being authenticated at http://idp.someorg-victim.com/

At this point we had to add fake user accounts to *someorg-attacker's* user directory and see what would happen when we try to login with them. With Active Directory this translates to adding a new *alternative UPN suffix* and then adding new users via the included tools.

The user directory at *someorg-victim* contained entries for their own users:

.. figure:: /images/ADusers-victim.png
   :alt: Active Directory users (victim organization)

The user directory at *someorg-attacker* contained user entries for both organizations:

.. figure:: /images/ADusers-attacker.png
   :alt: Active Directory users (attacker organization)

It was now time to test our hypothesis. As described above under `How Office 365 SAML implementation works`_, the process started at `https://login.microsoftonline.com/` and for the first step we had to use *something@someorg-attacker.com* as the username for the login portal to redirect us to *someorg-attacker's* Identity Provider.

When presented with Identity Provider's login form we used one of our fake users created under *someorg-victim.com* (e.g. john.smith@someorg-victim.com) domain and happily finished our login process on the Identity Provider. 

**This was the critical point where things should simply stopped working and Microsoft's login portal should threw an error, yet nothing special happened.** We were welcomed by `Office Portal <http://portal.office.com/>`_ page logged in as *john.smith@someorg-victim.com*. What followed was a moment of silence where we weren't sure whether to be happy about the discovery or terrified about its implications.

For the first few minutes this looked like a critical vulnerability affecting only Microsoft's SAML 2.0 implementation and since SAML usually isn't the preferred Single Sign On protocol for Office 365, the actual number of affected Office 365 subscriptions seemed quite low and limited mostly to the educational sector.

On the other hand, we had identified that the two SSO implementations are intertwined and that SAML 2.0 messages are translated to WS-Trust messages. So, this left us with  another open question - what happens if we try to login with a user that has its domain federated using `Active Directory Federations Services <https://msdn.microsoft.com/en-us/library/bb897402.aspx>`_? Luckily, Šola prihodnosti Maribor (one of the partners in the discovery of this vulnerability, not a randomly selected victim) uses Office 365 with ADFS and it was therefore quite simple to answer this one. We added *klemen.bratec@spmb.si* to our *someorg-attacker's* user directory, repeated the procedure described above and **it worked**! The SAML Service Provider consumed the SAML assertion from the attacker's org Identity Provider even though the spmb.si domain is configured to be federated with WS-Trust, forwarded it to the token translation service which translated it to an WS-Trust token and ... **we were in**.

Now this is where things became really interesting as we were not limited to organizations using SAML and could login with almost any federated Office 365 user (the exception being those with enabled Multi-Factor Authentication).


How bad was it?
---------------

Who is actually using Office 365 anyway? And out of them who has configured their domains as federated, thus being vulnerable? A quick search reveals `this list <https://products.office.com/en-us/business/office-365-customer-stories-office-testimonials>`_ of customer stories, which is not by any means exclusive. It contains 

.. code::
   
   curl -s https://products.office.com/en-us/XMLData/PMG-CustomerStoryContent.xml?_=1460974613740 \
   | xmlstarlet sel -t -v "count(/cusStoryTypes/cusStoryType/industry/story)"

152 Customer stories

Getting the customer names with 

.. code::

   curl -s https://products.office.com/en-us/XMLData/PMG-CustomerStoryContent.xml?_=1460974613740 \
   | xmlstarlet sel -t -n -v "/cusStoryTypes/cusStoryType/industry/story/companyName"

reveals some interesting names such as `telefonika <http://www.telefonika.com>`_, `Caltex Australia <http://www.caltex.com.au>`_, `Aston Martin <http://www.astonmartin.com>`_, `Helly Hansen <http://www.hellyhansen.com>`_, `Georgia State University <http://www.gsu.edu>`_, `Japan Airlines <http://www.jal.com>`_, `Santa Clara County <http://www.sccgov.org>`_, `City of Chicago,IL <http://www.cityofchicago.org>`_, `British Airways <http://www.ba.com>`_.

If only there was a way for an attacker to easily check which of these companies have their domain configured as federated... Scroll up a little to the `How Office 365 SAML implementation works`_ where we discussed how the Office 365 SAML Service Provider handles the IdP Discovery. Yes, it turns out that there is an endpoint that one can use to check if a domain is federated or not 

*https://login.microsoftonline.com/common/userrealm/?user=something@domain&api-version=2.1&checkForMicrosoftAccount=false*

An HTTP GET request for a domain that is federated, returns the following json response

.. code:: json

   {
   "NameSpaceType":"Federated",
   "federation_protocol":"WSTrust",
   "Login":"something@ba.com",
   "AuthURL":"https://sts.baplc.com/adfs/ls/?username=something%40ba.com&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=",
   "DomainName":"ba.com",
   "FederationBrandName":"BA.COM",
   "cloudinstancename":"login.microsoftonline.com"
   }

The response parameters that are of interest are
 - **NameSpaceType** can be *Federated* or *Managed*. If the NameSpaceType is *Federated*, the domain has been set for federated SSO and thus is vulnerable
 - **federation_protocol** can be *WSTrust* or *SAML20* depending on how the SSO is configured. As shown above, both are vulnerable. 


Checking manually for a couple of the aforementioned companies reveals that 
 - `telefonika <http://www.telefonika.com>`_
 - `Caltex Australia <http://www.caltex.com.au>`_
 - `Georgia State University <http://www.gsu.edu>`_
 - `Japan Airlines <http://www.jal.com>`_
 - `Santa Clara County <http://www.sccgov.org>`_
 - `City of Chicago,IL <http://www.cityofchicago.org>`_
 - `British Airways <http://www.ba.com>`_
   
among others have their domains set as federated and thus were vulnerable. Additionally, some random checks against high profile targets showed that big organizations across various sectors use federated SSO with their Office365 subscriptions. Some prominent examples are in the list below
 - `Microsoft <http://www.microsoft.com>`_ (well, duh) 
 - `Vodafone <http://www.vodafone.com>`_
 - `British Telecommunications plc <http://www.bt.com>`_
 - `Verizon <http://www.verizon.com>`_
 - `International Monetary Fund <http://www.imf.org>`_
 - `Royal Dutch Shell <http://www.shell.com>`_
 - `The Daily Mail <http://www.dailymail.co.uk>`_
 - `Novartis Pharma AG <http://www.novartis.com>`_
 - `Pfizer <http://www.pfizer.com>`_
 - `Toyota Motor North America <http://www.toyota.com>`_
 - `Cisco <http://www.cisco.com>`_
 - `IBM <http://www.ibm.com>`_
 - `Intel <http://www.intel.com>`_
 - `Pricewaterhouse Coopers (PwC) <http://www.pwc.com>`_
 - `KPMG <http://www.kpmg.com>`_
 - `Scania AB <http://www.scania.com>`_
 - `Vinci <https://www.vinci.com>`_


It was pretty easy to automate this and check against company domain name lists to identify potential targets, but we did not have the time nor the inclination to do so.  

Outro
+++++
The aforementioned issue fell within the scope of the Online Service bug bounty program and as such has been rewarded and acknowledged by Microsoft on
 - https://technet.microsoft.com/en-us/security/dn469163
 - https://technet.microsoft.com/en-us/security/cc308589.aspx

Timeline
--------
 - *2015-12   :* Discovery and initial testing
 - *2016-01-05:* Disclosure to Microsoft
 - *2016-01-05:* Microsoft acknowledges the issue, mitigates it and rolls out an update in 7 hours (!!).
 - *2016-02-24:* Microsoft closes the issue and allows us to publish the details.
 - *2016-04-27:* Public disclosure
