---
title: Patch Analysis - Gitlab 17.8.2 to 17.8.4
date: 2025-03-01 1:00:00
categories: [Analysis, BBP]
tags: [Gitlab, authorisation]
---

In this blog, I will pick some authorization-related security patches and try to reverse engineer how it is caused. This blog would focus on Gitlab 17.8.2 to 17.8.4.

## Disclaimer

I am by no means an expert in ruby/bug bounty hunting/ruby on rails/source code review. As I explore hacking, I use writing and sharing blogs as a way to reinforce my understanding. The content below reflects my best effort to grasp the vulnerability, but it may not be entirely accurate.

# 17.8.2
## Prevent Planner Role to update or delete incidents
Commit: 3c76c42d1451fea9f74aec4ff31d17483f8c2d14

Based on the patch, the vulnerability seems to stem from [/app/services/incident_management/link_alerts/base_service.rb](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/services/incident_management/link_alerts/base_service.rb?ref_type=heads)
```diff
--- a/app/services/incident_management/link_alerts/base_service.rb
+++ b/app/services/incident_management/link_alerts/base_service.rb
@@ -8,7 +8,7 @@ class BaseService < ::BaseProjectService
       attr_reader :incident
 
       def allowed?
-        current_user&.can?(:admin_issue, project)
+        current_user&.can?(:admin_issue, incident)
       end
```

As one can see, the past authorisation confuses authority to manage incidents with the authority to manage projects. It seems to assume that if a role can admin issues in the current project, then it can manage incidents. However, based on the docs, we can clearly see that planner can manage issues in a project, but cannot manage incidents in a project, leading to this vulnerability.

## Invalidate and disconnect Websocket after PAT revocation in ActionCable
Commit: 85760efaf82d85241732360045a1763095740049

Before, after a PAT is revoked, the websocket is still streaming information to the user. As we can see from the patch, now it periodically check and validate scopes every 10 minutes, and will disconnect the websocket after a PAT is revoked:
```diff
--- a/app/channels/application_cable/channel.rb
+++ b/app/channels/application_cable/channel.rb
@@ -6,11 +6,12 @@ class Channel < ActionCable::Channel::Base
     include Gitlab::Auth::AuthFinders
 
     before_subscribe :validate_token_scope
+    periodically :validate_token_scope, every: 10.minutes
 
     def validate_token_scope
-      validate_and_save_access_token!(scopes: authorization_scopes)
+      validate_and_save_access_token!(scopes: authorization_scopes, reset_token: true)
     rescue Gitlab::Auth::AuthenticationError
-      reject
+      handle_authentication_error
     end
```

## Prevent read code access when repository is disabled
Commit: be2a9c24d18e2735f4d8e640bfd61633851da60e

Gitlab allows you to disable repository so that no one should be able to access that repository. However, there is also a custom permission `view repository code` that one can set to a custom role to enable that role to view code. So when a role with that custom permission is set, it enables them to read code from disabled repository.

```diff
--- a/ee/app/policies/ee/project_policy.rb
+++ b/ee/app/policies/ee/project_policy.rb
@@ -536,6 +536,10 @@ module ProjectPolicy
         prevent(*create_read_update_admin_destroy(:iteration))
       end
 
+      rule { repository_disabled }.policy do
+        prevent :read_code
+      end
+
       rule { dependency_scanning_enabled & can?(:download_code) }.enable :read_dependency
 
       rule { license_scanning_enabled & can?(:download_code) }.enable :read_licenses
```
The patch is rather simple, Gitlab simply added a new rule to prevent `read_code` when repository is disabled.
# 17.8.4

## Prevent Planner role to read code review analytics in private projects
Commit: 537159f505cad7d23cded01140fbdfd84e9cdfa2

Based on the patch, the vulnerability is caused by lacking of policy regarding code review analytics:
```diff
--- a/ee/app/policies/ee/project_policy.rb
+++ b/ee/app/policies/ee/project_policy.rb
@@ -733,6 +733,8 @@ module ProjectPolicy
 
       rule { can?(:read_merge_request) & code_review_analytics_enabled }.enable :read_code_review_analytics
 
+      rule { private_project & planner }.prevent :read_code_review_analytics
+
       rule { (admin | reporter) & dora4_analytics_available }
         .enable :read_dora4_analytics
 
```

As we can see, before, you can read code review analytics if the functionality is enabled and if you can read merge requests. Now it explicitly prevent planner to read code review analytics since the documentation is clear you must be at least reporter to be able to view code review analytics.

## Prevent Guest User to Read Security Policy
Commit: 9bfcf4a596b965ce73426d68861cec83ee70f19e

Another vulnerability that stems from similar misconfiguration in [project_policy.rb](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/app/policies/ee/project_policy.rb?ref_type=heads):
```diff
--- a/ee/app/policies/ee/project_policy.rb
+++ b/ee/app/policies/ee/project_policy.rb
@@ -405,7 +405,7 @@ module ProjectPolicy
         enable :update_security_orchestration_policy_project
       end
 
-      rule { security_orchestration_policies_enabled & can?(:guest_access) }.policy do
+      rule { security_orchestration_policies_enabled & can?(:reporter_access) }.policy do
         enable :read_security_orchestration_policy_project
       end
```
Before, the rule would enable anyone with guest access to read security policy project, but now it changed to reporter.

That's about it, see you next time!
