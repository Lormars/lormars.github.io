---
title: From Report to Patch - Gitlab's Unauthorized manipulation of status of issues in public projects
date: 2025-05-06 1:00:00
categories: [Digest, BBP]
tags: [Gitlab]
---

This [report](https://gitlab.com/gitlab-org/gitlab/-/issues/508742) is quite straightforward. Basically, the `ProcessCommitWorker` function in GitLab automatically closes issues mentioned in commit messages by attributing the action to the commit author, which is spoofable. An attacker can forge a commit using a victim’s email and reference a public issue, causing it to be closed without authorization. This vulnerability enables unauthorized issue closures, potentially disrupting project workflows and misleading contributors.

### Disclaimer

I am by no means an expert in ruby/bug bounty hunting/ruby on rails/source code review. As I explore hacking, I use writing and sharing blogs as a way to reinforce my understanding. The content below reflects my best effort to grasp the vulnerability, but it may not be entirely accurate.

### Culprit

Let's first check the culprit of this vuln. The reporter mentioned `ProcessCommitWorker`, and let's see the details:
```ruby
  def close_issues(project, user, author, commit, issues)
    Issues::CloseWorker.bulk_perform_async_with_contexts(
      issues,
      arguments_proc: ->(issue) {
        [project.id, issue.id, issue.class.to_s, { closed_by: author.id, commit_hash: commit.to_hash }]
      },
      context_proc: ->(issue) { { project: project } }
    )
  end
```
In `ProcessCommitWorker`, we see this function which calls `Issues::CloseWorker` to close issues mentioned in the commit message. And in `Issues::CloseWorker`, we see
```ruby
      author = User.find_by_id(params["closed_by"])

      unless author
        logger.info(structured_payload(message: "User not found.", user_id: params["closed_by"]))
        return
      end

      commit = Commit.build_from_sidekiq_hash(project, params["commit_hash"])
      service = Issues::CloseService.new(container: project, current_user: author)

      service.execute(issue, commit: commit)
```

Note how the issue is closed with `current_user` set to `author`, which is passed into this function using `closed_by` param. But who is this `author` anyway?
```ruby
author = commit.author || user
```
In `ProcessCommitWorker`, we found that `author` is `commit.author`, and if there is no `commit.author`, it is set to `user`, which is the one pushing the commit.

This then all adds up. The attacker can just forge a commit using victim's email, and then `author` would be set to victim. Then the issue would be closed.

### Patch

The patch is quite straightforward:
```ruby
      unless author
        logger.info(structured_payload(message: "Author not found.", user_id: params["closed_by"]))
        return
      end

      user = User.find_by_id(params["user_id"])

      # Only authorizing if user is present for backwards compatibility.
      # TODO: Remove with https://gitlab.com/gitlab-org/gitlab/-/work_items/509422
      if user && !issue.is_a?(ExternalIssue) && !user.can?(:update_issue, issue)
        logger.info(
          structured_payload(message: "User cannot update issue.", user_id: params["user_id"], issue_id: issue_id)
        )
        return
      end

      commit = Commit.build_from_sidekiq_hash(project, params["commit_hash"])
      service = Issues::CloseService.new(container: project, current_user: author)

```

As we can see here, Gitlab adds a check to make sure the user who pushes the commit is authorized to update the issue in question. The `user` is retrieved using `user_id`, which is passed in here:
```ruby
  def close_issues(project, user, author, commit, issues)
    Issues::CloseWorker.bulk_perform_async_with_contexts(
      issues,
      arguments_proc: ->(issue) {
        [
          project.id,
          issue.id,
          issue.class.to_s,
          { closed_by: author.id, user_id: user.id, commit_hash: commit.to_hash }
        ]
      },
      context_proc: ->(issue) { { project: project } }
    )
  end
```

As we can see, the `user_id` is just `user.id`, which is passed into the close service by the patched `ProcessCommitWorker`.

That's it! See you next time!
