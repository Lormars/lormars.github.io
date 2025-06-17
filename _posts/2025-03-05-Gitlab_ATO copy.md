---
title: From Report to Patch - Gitlab ATO Through Password Reset
date: 2025-03-05 1:00:00
categories: [Digest, BBP]
tags: [Gitlab, ATO]
---

This [report](https://hackerone.com/reports/2293343) is quite short and easy to understand, yet its impact is so critical -- a cvss score of 10.0. What I am curious is how this vulnerability is caused, and how Gitlab patched this vulnerability. Let's dive in!

## Disclaimer

I am by no means an expert in ruby/bug bounty hunting/ruby on rails/source code review. As I explore hacking, I use writing and sharing blogs as a way to reinforce my understanding. The content below reflects my best effort to grasp the vulnerability, but it may not be entirely accurate.

## The Patch

Since the attack is quite straightforward and there is actually nothing technical needed to explain, let's jump into the [patch](https://gitlab.com/gitlab-org/gitlab/-/commit/c571840ba2f0e91ca7ec3c436f796532dbb3c550) directly.
```diff
--- a/app/models/concerns/recoverable_by_any_email.rb
+++ b/app/models/concerns/recoverable_by_any_email.rb
 module RecoverableByAnyEmail
   extend ActiveSupport::Concern
 
   class_methods do
     def send_reset_password_instructions(attributes = {})
-      email = attributes.delete(:email)
-      super unless email
+      return super unless attributes[:email]
 
-      recoverable = by_email_with_errors(email)
-      recoverable.send_reset_password_instructions(to: email) if recoverable&.persisted?
-      recoverable
-    end
+      email = Email.confirmed.find_by(email: attributes[:email].to_s)
+      return super unless email

```

The key lies in the `to_s` method. Before the patch, Gitlab would take the email from the param directly, leading to this bug.

Now it would first call `to_s` to the email param. For those who does not know ruby well, `to_s` just converts object to string. If it is called on a string, it is just a no operation. And if it is called on an array, it would just return a string form of the array.
```ruby
irb(main):001:0> array = ["a","b"]
=> ["a", "b"]
irb(main):002:0> array.to_s
=> "[\"a\", \"b\"]"
irb(main):003:0> puts array.to_s
["a", "b"]
=> nil                                                                
```

So this line below would return `nil` given that there would be no confirmed email looking like an email array, and the function would just return without sending any emails.
```ruby
email = Email.confirmed.find_by(email: attributes[:email].to_s)
```

So as you can see, the patch is also relatively easy. It is by no means a very technical vulnerability, yet it is so critical. It also shows that sometimes you do not need to be very technical to find critical bugs. All you need is some creative thinking.
