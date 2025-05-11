---
title: Patch Analysis - Gitlab 17.10.5 & 17.10.6
date: 2025-05-11 1:00:00
categories: [Analysis, BBP]
tags: [Gitlab, authorisation]
---

In this blog, I will pick some authorization-related security patches and try to reverse engineer how it is caused. This blog would focus on Gitlab 17.10.5 and 17.10.6

### Disclaimer

I am by no means an expert in ruby/bug bounty hunting/ruby on rails/source code review. As I explore hacking, I use writing and sharing blogs as a way to reinforce my understanding. The content below reflects my best effort to grasp the vulnerability, but it may not be entirely accurate.

### Partial Bypass for Device OAuth flow using Cross Window Forgery
Commit: 57f19d6fde464506dc756621c83e6eaf0bfdfc33

This is kind of straightforward. It is a direct application of [this blog](https://www.paulosyibelo.com/2024/02/cross-window-forgery-web-attack-vector.html), and the patch is to remove the `id` attribute of the sensitive button.

### Group IP restriction bypass allows disclosing issue title of restricted project
Commit:19c44aecc4fd834c9fbde85003e9e20946e82979

According to the patch, it allows users could bypass IP access restrictions of a group, enabling them to disclose issue titles.

Let's check the patch:
```diff
      DeclarativePolicy.user_scope do
---      issues.select { |issue| issue.visible_to_user?(user) }
+++      issues.select { |issue| allowed?(user, :read_issue, issue) }
      end
    end
```
As we can see, it changed user scope check from `issue.visible_to_user?(user)` to `allowed?(user, :read_issue, issue)`.
The added check is a direct check of the user against its ability to read the target issue, but what's the deleted check? Let's see:
```ruby
  def visible_to_user?(user = nil)
    return publicly_visible? unless user
    return true if user.can_read_all_resources?
    return readable_by?(user) unless project

    readable_by?(user) && access_allowed_for_project_with_external_authorization?(user, project)
  end
```

As we can see, `visible_to_user` is actually a check on issue based more on issue itself. For example, it would first check if it is publicly visible, and if it is, then it will directly return true. This kind of check is problematic and would lead to bypass because the access control mechanism of Gitlab is quite complex. For IP restriction it is especially problematic since issues protected by IP restriction can still be public.

### Unauthorized access to branch names when Repository assets are disabled in the project
Commit: 9f9724584d109181e764f79a3b61667520d2212f

According to the patch, a bug could allow users to view certain restricted project information even when related features are disabled in GitLab EE. 

Let's check the patch first:
```ruby
      def branch
        return unless object.project.repository_access_level != ProjectFeature::DISABLED

        object.branch
      end
```

The patch is relatively simple. It added a check on the `branch` field of the graphql request `DastProfile` to check whether the project feature is disabled. If it is disabled, it will not return `branch` info.

In patch 17.10.5, there are several reports by Johan. Given the technical details of these reports, I will write blogs on them separately.

That's it! See you next time!
