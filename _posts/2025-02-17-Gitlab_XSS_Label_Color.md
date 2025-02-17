---
title: From Report to Patch - XSS via Gitlab labels
date: 2025-02-16 1:00:00
categories: [Digest, BBP]
tags: [Gitlab, XSS, Ruby]
---

In 2022, [yvvdwf](https://hackerone.com/yvvdwf) reported two bugs, one stored-xss in Gitlab via label's color, and another bypass of the fix to this vulnerability. In this blog, we will dive deep into the reports to see how these bugs happened, how the patch works, how the bypass works, and the final patch to fix the bypass.

## Disclaimer

I am by no means an expert in ruby/bug bounty hunting/ruby on rails/source code review. As I explore hacking, I use writing and sharing blogs as a way to reinforce my understanding. The content below reflects my best effort to grasp the vulnerability, but it may not be entirely accurate.

## Technical Deep Dive

### First Vuln

First, both of these vulnerabilities take use of Gitlab's Github import feature. If you are not familiar with this feature, you can check [this blog](https://lormars.github.io/posts/Gitlab_RCE_Github_Import/), where I dive into the import flow. Once you are familiar with the flow, let's see how this XSS happens.

The [report](https://hackerone.com/reports/1665658) wrote that the issue lies in the label colors, so let's first see how the label is imported. From the [labels_importer](https://gitlab.com/gitlab-org/gitlab/-/blob/927ef57ce2e4ae660ce60fffb92b45045c433173/lib/gitlab/github_import/importer/labels_importer.rb), we can see that labels are imported using `#bulk_insert`:
```ruby
        def execute
          bulk_insert(Label, build_labels)
          build_labels_cache
        end
        def build_labels
          build_database_rows(each_label)
        end
```

And `#bulk_insert` is defined in [bulk_importing](https://gitlab.com/gitlab-org/gitlab/-/blob/9bb48c9b87e82324ad36fd6854739fade0c6d045/lib/gitlab/github_import/bulk_importing.rb):
```ruby
      def build_database_rows(enum)
        rows = enum.each_with_object([]) do |(object, _), result|
          result << build(object) unless already_imported?(object)
        end
        log_and_increment_counter(rows.size, :fetched)
        rows
      end
      # Bulk inserts the given rows into the database.
      def bulk_insert(model, rows, batch_size: 100)
        rows.each_slice(batch_size) do |slice|
          ApplicationRecord.legacy_bulk_insert(model.table_name, slice) # rubocop:disable Gitlab/BulkInsert
          log_and_increment_counter(slice.size, :imported)
        end
      end
```

And we can see that `bulk_insert` directly insert labels into the database, without any validation. So this is the source where we can try to insert malicious XSS. But if this is the source, where is the sink?

After injecting our malicious labels into the database, it is then later used in [labels_helper](https://gitlab.com/gitlab-org/gitlab/-/blob/75d1049c136c1ab74c2687793f021357c31589ae/app/helpers/labels_helper.rb)
```ruby
  def render_label_text(name, suffix: '', css_class: nil, bg_color: nil)
    <<~HTML.chomp.html_safe
      <span
        class="#{css_class}"
        data-container="body"
        data-html="true"
        #{"style=\"background-color: #{bg_color}\"" if bg_color}
      >#{ERB::Util.html_escape_once(name)}#{suffix}</span>
    HTML
  end
```

Here, the `bg_color` is retrieved from `label.color`, and it is not even escaped. So the whole flow from our `github import source` to the `html render sink` is completely, achieving XSS.

### First Patch

There are roughly two patches I can find.

First, the `bg_color` is escaped by changing to `h bg_color`, which secures the sink.
Second the source is also secured, and here is the patched [labels_importer](https://gitlab.com/gitlab-org/gitlab/-/blob/a9b7948f44febfe91b450333c57f5785c3708601/lib/gitlab/github_import/importer/labels_importer.rb):
```ruby
 def execute
          rows, validation_errors = build_labels
          bulk_insert(rows)
          bulk_insert_failures(validation_errors) if validation_errors.any?
          build_labels_cache
        end
def build_labels
          build_database_rows(each_label)
        end
```

Here we found a new validation step before inserting rows, and here is the patched [bulk_importing](https://gitlab.com/gitlab-org/gitlab/-/blob/a9b7948f44febfe91b450333c57f5785c3708601/lib/gitlab/github_import/bulk_importing.rb)
```ruby
 def build_database_rows(enum)
        errors = []
        rows = enum.each_with_object([]) do |(object, _), result|
          next if already_imported?(object)
          attrs = build_attributes(object)
          build_record = model.new(attrs)
          if build_record.invalid?
            log_error(object[:id], build_record.errors.full_messages)
            errors << build_record.errors
            next
          end
          result << attrs
        end
        log_and_increment_counter(rows.size, :fetched)
        [rows, errors]
      end
```

Basically the validation works by building a label object before inserting the labels into the database. Since Gitlab already has validation when they build the label objects, this patch takes advantage of that original validation and fixes the vulnerability from the source.

### Bypass

However, this fix has a bypass. According to the [report](https://hackerone.com/reports/1693150), the bypass takes use of scoped labels, but what are scoped labels? Basically, scoped labels are just labels that are mutually exclusive. They follow the format of `key::label_name`. So if you have a scoped label `a::b`, and another scoped label with the same key, `a::c`, you cannot use both of these labels in the same issue.

So how the bypass happened? 

It is actually quite a straightforward bypass. Scoped label is a feature that is only available for paid customers, and the logic of rendering it resides in a different file under folder [/ee](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/app/helpers/ee/labels_helper.rb?ref_type=heads). When Gitlab fix the vulnerability, they forgot to escape label color in this file concerning scoped labels, leaving the reporter a straightforward bypass.

You may ask: "but isn't there a validation on the source when we do bulk importing as well?" Yes, but this validation on source was actually not in place at first. The fix was originally only on the sink. After the Bypass, they added the validation on the source as well to prevent all future bypasses.

## Lessons Learned

For hackers, it is often worthy to check disclosed reports and try to find bypasses. Usually the immediate fix of the vulnerability would often leave some edge cases open, especially for complex code base. So it is always worthy to get yourself familiar with the code base and try to think of any bypasses.

For developers, be sure to implement defense in depth. For vulnerabilities like XSS, it is worthy to spend some times to secure both the source and the sink.