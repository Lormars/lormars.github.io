---
title: From Report to Patch - Run pipelines on arbitrary branches
date: 2025-06-16 1:00:00
categories: [Digest, BBP]
tags: [Gitlab, Authorisation]
---

[This](https://gitlab.com/gitlab-org/gitlab/-/issues/493946) is a very smart attack. To understand this attack, we need first to understand some key features in Gitlab.

#### External CI/CD

While GitLab typically hosts repositories and runs CI/CD pipelines natively, some users host their code on external platforms like GitHub but want to leverage GitLab’s robust CI/CD capabilities. For this, GitLab provides the **External CI/CD** feature. Users can configure their external repository (e.g., on GitHub) to send a webhook request to GitLab whenever the codebase is updated. Upon receiving the webhook, GitLab mirrors the external repository and executes the pipelines defined in the `.gitlab-ci.yml` file.

#### Report

To ensure webhook requests are legitimate, GitHub includes an `X-Hub-Signature` header in its outgoing requests, which GitLab verifies. The verification process involves generating a signature using the webhook payload and a secret token (`external_webhook_token`) stored in the GitLab project, as shown below:
```ruby
token = project.external_webhook_token.to_s
payload_body = request.body.read
signature = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), token, payload_body)
```
The signature is computed by hashing the payload with the project’s `external_webhook_token`. However, a critical flaw exists: if `external_webhook_token` is `nil`, the signature becomes trivial to forge. This token is only generated when External CI/CD is explicitly configured. For projects using only **repository mirroring** (e.g., pull mirroring), `external_webhook_token` is `nil` by default, leaving the webhook endpoint vulnerable to unauthenticated requests.

#### Exploiting the Vulnerability

With the ability to forge webhook requests, an attacker can trigger CI/CD pipelines in a vulnerable GitLab project without authentication. But the exploit’s impact deepens when we examine how GitLab assigns pipeline ownership:
```ruby
def mirror_user
  current_user || project.mirror_user
end
```

The `mirror_user` method determines the pipeline’s job owner. If no `current_user` is present (as in a webhook-triggered pipeline), the pipeline runs as the `mirror_user`—the user who configured the repository mirroring. This is where the attack becomes devastating.

#### The Attack Scenario

An attacker with developer access to a GitLab project can craft a malicious `.gitlab-ci.yml` file and forge a webhook to trigger a pipeline on any branch. Since the pipeline executes under the `mirror_user`’s identity, the attacker can abuse this to **steal the `mirror_user`’s Job Token**. This token grants significant privileges, potentially allowing the attacker to access sensitive resources, exfiltrate data, or escalate their permissions within the project.

### Patch

The patch is quite simple:
```ruby
       def valid_github_signature?
-        request.body.rewind
+        token = project.external_webhook_token.to_s
+        # project.external_webhook_token should always exist when authenticating
+        # via headers['X-Hub-Signature']. If it doesn't exist, this could be
+        # an attempt to misuse.
+        return false if token.empty?
 
-        token        = project.external_webhook_token.to_s
+        request.body.rewind
         payload_body = request.body.read
         signature    = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), token, payload_body)
```

It simply adds a check to make sure that token is not empty.

### Takeaways

I've observed that the most critical bugs often have surprisingly simple fixes. While some bugs are inherently complex, requiring intricate solutions, many severe issues arise from basic oversights, like flawed assumptions or logic errors. For example, assuming `external_webhook_token` could never be `nil` can lead to significant vulnerabilities in this report.

This dynamic makes vulnerability hunting both challenging and exciting. It involves uncovering bugs by questioning the assumptions developers embed in their code. Outsiders often excel at this because they lack the preconceived notions that developers form during the coding process. This fresh perspective allows bug hunters to spot oversights that might be invisible to those deeply familiar with the codebase, enabling them to identify and address critical flaws with a clear, unbiased view.
