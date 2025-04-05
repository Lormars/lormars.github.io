---
title: Notes on ruby-saml Roundtrip Attacks
date: 2025-04-04 1:00:00
categories: [Digest, CVE]
tags: [SAML, Ruby]
---

This blog is just my note of the following three researches because I found I do not understand some of the research quite well. Thus I would assume that you have already read these researches before reading the content below.
1. [portswigger saml roulette](https://portswigger.net/research/saml-roulette-the-hacker-always-wins)
2. [github saml parser differentials](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/)
3. [mattermost securing xml implementations](https://mattermost.com/blog/securing-xml-implementations-across-the-web/)

# Researches

## Round-trip attack
In [Securing XML implementations across the web](https://mattermost.com/blog/securing-xml-implementations-across-the-web/), the author Juho Forsén detailed what a round trip is and how it happens. Basically, round trip attack refers to the mutation of a xml document after multiple parsing and serialising. When the xml was first parsed, it may mean one thing. But after it is re-serialised and parsed again, it means a different thing. Such vulnerable behaviour is typically caused by the mutation of quotation marks (from `'` to `"` ).

![image](/assets/images/roundtrip_1.png){:width="700" height="400"}

This image from the original post shows the attack clearly.

The original `'` before `x` in DTD becomes `"` after serialising and parsing again, which totally altered the meaning of this xml document. (The trailing `-->` in the original xml would not interfere with the parser.)

Before, the first child in the original doc is `Y`, and now it becomes `Z`.

## Portswigger SAML roulette

Enlightened by the above post, portswigger also conducted research on SAML, and found more attacks.

First, Gareth found a new a new way to achieve round-trip attack. Instead of using notation declarations, we can also use SYSTEM identifier:
![image](/assets/images/roundtrip_2.png){:width="700" height="400"}

This is easy to understand. Let's continue reading.

After certification, re-parse occurred, but the....too confused!!! If you are like me, someone who is not that familiar with SAML, I bet you will find the content confusing when you continue reading the original blog. So instead of trying to solve the puzzles, I decided to build a lab to build a PoC myself to help me understand.


## Lab

### Prepare for a valid SAML doc

First you need to generate a private key and certificate to sign the SAML response.

```bash
# Generate a private key
openssl genrsa -out idp_private_key.pem 2048

# Generate a self-signed certificate
openssl req -new -x509 -key idp_private_key.pem -out idp_cert.pem -days 365 -subj "/CN=idp.example.com"
```

Or you can also use the example key and cert given in the ruby-saml library.

Then, prepare an unsigned SAML doc, like below:
```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
                ID="pfx0a3cfa31-f178-71f2-9b94-ad4047591acc" 
                Version="2.0" 
                IssueInstant="2012-04-04T07:33:10.921Z" 
                Destination="https://example.com/endpoint">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
                  Version="2.0" 
                  IssueInstant="2012-04-04T07:33:10.923Z" 
                  ID="pfx7fca52d6-8991-5d99-3147-4f9d7c278d78">
    <saml:Issuer>idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID NameQualifier="idp.example.com" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">someone@example.org</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="https://example.com/endpoint" 
                                      NotOnOrAfter="2032-04-04T07:38:11.442Z"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2012-04-04T07:28:11.442Z" NotOnOrAfter="2032-04-04T07:38:11.442Z">
      <saml:AudienceRestriction>
        <saml:Audience>example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2012-04-04T07:33:11.442Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>
```

Sign it using [online saml signer](https://www.samltool.com/sign_response.php). 

Now, prepare a script like [this](https://github.com/Lormars/ruby_saml_roundtrip/blob/main/test.rb) to test that you can indeed validate the SAML docs. If yes, let's continue to the next step.

### Source instrument

Unless you are really good at static analysis, you would need dynamic analysis to help you understand what the ruby saml is doing. This often involve modifying the source code to add some debug messages. Fortunately, this is quite easy for us to achieve in ruby.

All we need to do is to clone the source code of ruby-saml on github. Then we can set a custom `$LOAD_PATH` at the beginning of our test script to make sure ruby is using our downloaded source code:
```ruby
saml_repo_path = "/ruby-saml/lib"  # Replace with the actual path
puts "Checking path: #{saml_repo_path}"
puts "File exists? #{File.exist?("#{saml_repo_path}/onelogin/ruby-saml.rb")}"
$LOAD_PATH.unshift(saml_repo_path) unless $LOAD_PATH.include?(saml_repo_path)
require 'onelogin/ruby-saml'
```

Then we can simply modify the source code to add debug logic in it.


Now let's dive into the vulnerabilities. First, let's check the round-trip attack.

### Round-trip

The round-trip attack is actually pretty straightforward (only in hindsight). Let's recap: taking advantage of REXML's weakness in parsing `'` and `"`, we can craft a malicious SAML so that the assertion checked would be different after first parsing and second parsing.

Let's define the original doc as `original`, which would check on the `original assertion`, and the doc after round-trip parsing as `parsed`, which would check the `parsed assertion`. In this case, the meat of the assertion, like `NameID` and x509Certificate is retrieved from `original assertion` while signature is verified using `parsed assertion`.

Using the round-trip trick, we can just write anything in `NameID` in the `original assertion`. As long as the x509Certificate is genuine, we will pass all the check on the `original assertion`.

For the `parsed`, we would just use a genuine assertion. Since it is genuine, then it would of course pass the signature check.

An example is [here](https://github.com/Lormars/ruby_saml_roundtrip/blob/main/saml_response_roundtrip.xml). For complete PoC, you can also [clone my repo](https://github.com/Lormars/ruby_saml_roundtrip), and run
```bash
docker build -t saml-roundtrip .
docker run --rm saml-roundtrip
```

So this allows a straightforward privilege escalation. Any authenticated member in an organization can take advantage it to authenticate as anyone in the same organization. All he needs to do is to put his genuine SAML assertion in the `parsed assertion`, and copy the exact assertion also into the `original assertion` after changing the `NameID` of it. 

### Name Confusion

Now let's check the second vulnerability. The second vulnerability is quite easy to understand theoretically. Basically there is a parser vulnerability in `REXML`, so that it would lead to some inconsistencies when there is duplicate attributes.

However, I am quite confused with the purpose of the second vulnerability. Yes there is a bug in how REXML parses `ATTLIST`, and you can take advantage of this fact to privilege escalate. But I don't see how this attack is useful on its own given we already have round-trip attack. It's like, if this exploit depend on round-trip attack for privilege escalation, and round-trip attack and achieve privilege escalation on its own, why bother with this attack?

But anyway, I still mess around with the payload to try this attack in order to understand the portswigger blog more. What I learned is that why round-trip is necessary for this attack. The problem is, like the blog said, there will be schema check initially on the SAML response. And if you include a valid `ATTLIST` in your original SAML response, it will not pass the schema check. Therefore you have to use the round-trip attack so that the `ATTLIST` will only be parsed and processed after round-trip parsing, where schema check is already passed. Then you can take advantage of the REXML `ATTLIST` parsing vulnerability to conduct the attack.

However, I did not finish with building a working payload because I still do not understand how this attack would work independently, and it's use case when round-trip attack can achieve privilege escalation already.

That's it! Hope the above helps!
