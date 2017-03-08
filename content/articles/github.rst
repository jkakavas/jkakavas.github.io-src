=========================================================
The road to your codebase is paved with forged assertions
=========================================================

:date: 2017-03-07
:modified: 2013-07-08 01:40
:tags: SAML, authentication, XSW
:category: bounty
:slug: github-saml
:authors: Ioannis Kakavas
:summary: Authentication bypass using vulnerabilities in the Github Enterprise SAML SP implementation

TL;DR
+++++
Two vulnerabilities in the SAML Service Provider implementation of Github Enterprise edition that allowed for full authentication bypass were identified. These vulnerabilities were reported to Github via their `bug bounty program in Hackerone <https://www.hackerone.com/github>`_ and mitigated.


Introduction
++++++++++++++

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

After navigating to `https://192.168.122.244:8443/setup` as instructed, I received the following message informing me that I would need 10 more GB of RAM at least to just bootstrap the installation. 

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

Building on what Orange had described in the writeup, I proceeded to scp the source code from `/data/github/current` to the host machine and used the following script

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





Signature Stripping
+++++++++++++++++++
Setting up the SAML authentication was quite easy following the steps in `the docs <https://help.github.com/enterprise/2.9/admin/guides/user-management/using-saml>`_. For the Identity Provider part, I am using a python project based on `pysaml2 <https://pypi.python.org/pypi/pysaml2>`_ that can handle legitimate IdP functionality as well as a number of automated and semi-automated SAML related attacks. Hopefull it will be released soon and will be the topic of another blog post. I did a test authentication and verified that everything works as expected.

The first thing I tried was to disable signing the SAML Response and the SAML Assertion that my Identity Provider was sending to the GHE Service Provider. I did that more for due diligence so that I can move on to more promising test cases and almost couldn't believe it when the authentication succeeded. If you were too bored to refresh your SAML knowledge above, the equivalent of a Service Provider accepting unsigned SAML assertions is accepting a username without checking the password.  



