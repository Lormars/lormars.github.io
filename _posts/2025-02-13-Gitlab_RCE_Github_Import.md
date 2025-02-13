---
title: From Report to Patch - RCE via github import
date: 2025-02-12 1:00:00
categories: [Digest, BBP]
tags: [Gitlab, RCE, Redis, Ruby]
---

In this blog post, we’ll dive into a critical **Remote Code Execution (RCE)** vulnerability in GitLab’s GitHub Import feature. The vulnerability, disclosed by security researcher **yvvdwf** on HackerOne ([Report #1672388](https://hackerone.com/reports/1672388)), allowed an attacker to execute arbitrary commands on a GitLab server by exploiting a flaw in how GitHub repository data was processed. We’ll break down the vulnerability, analyze its root cause, and explore how GitLab patched the issue.

---

## **Summary of the Vulnerability**

The vulnerability existed in GitLab’s GitHub Import feature, which allows users to import repositories from GitHub into GitLab. The researcher discovered that by crafting a malicious GitHub repository response, an attacker could inject arbitrary Redis commands. This could escalate to **Remote Code Execution (RCE)** by leveraging GitLab’s internal Redis and Sidekiq job processing system. The vulnerability was rated as **Critical (9.9)** due to its potential for full server compromise.

---

## **Technical Deep Dive**

## Disclaimer

I am by no means an expert in ruby/bug bounty hunting/ruby on rails/source code review. As I explore hacking, I use writing and sharing blogs as a way to reinforce my understanding. The content below reflects my best effort to grasp the vulnerability, but it may not be entirely accurate.

## How Gitlab imports Github repos

The report mentioned that Gitlab uses Octokit to get data from github.com, but what is Octokit? Basically, [Octokit](https://github.com/octokit/octokit.rb) is just a wrapper of Github Apis so that you can call Github Apis easily. 

For example, in [search_repos](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/github_import/clients/search_repos.rb?ref_type=heads#L20), Gitlab uses Octokit to send a post request to the github graphql endpoints. 
```ruby
        def graphql_request(query)
          is_default_host = (URI.parse(api_endpoint).host == URI.parse(::Octokit::Default::API_ENDPOINT).host)
          with_retry do
            octokit.post(
              "#{'/api' unless is_default_host}/graphql",
              { query: query }.to_json
            ).to_h
          end
        end
```

The object returned from octokit, as the report said, is an object of type Sawyer::Resource. And here is what the problem lies. The original report explained this part very well. Basically, Sawyer would convert hash keys to method. So if you have a hash key `to_s` when you instantiate a Sawyer::Resource object like below
```ruby
a = Sawyer::Resource.new( Sawyer::Agent.new(""), to_s: "example", length: 1)
```
when you later call `a.to_s`, the returned value would be `example`.

But why is this a problem? To understand this, we need to first spend sometimes understand Redis, which is used in gitlab as the caching database.

## How Redis serialize

When you use Redis client to send commands to Redis server it is often very easy, all you need to type is things like `SET KEY VALUE` to direct Redis to save...

However, in the backend, the client need to serialize the data using RESP (Redis Serialization Protocol) before sending the data to Redis server, and it is serializing using a quite straightforward [approach](https://redis.io/docs/latest/develop/reference/protocol-spec/#sending-commands-to-a-redis-server).

For example, `SET KEY VALUE` would be serialized to `*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n`.

- `*3`: three arguments.
- First `$3`: the first argument's length is 3 bytes.
- Second `$3`: the second argument's length is 3 bytes.
- `$5`: the third argument's length is 5 bytes.
- `\r\n`: delimiter.

In the report, it gives the source code used by Redis to serialize commands in ruby. Let's see if it conforms with RESP:
```ruby
      def build_command(args)
        command = [nil]

        args.each do |i|
          if i.is_a? Array
            i.each do |j|
              j = j.to_s
              command << "$#{j.bytesize}"
              command << j
            end
          else
            i = i.to_s
            command << "$#{i.bytesize}"
            command << i
          end
        end
```

So it first initialize an empty command array. And for each args, it calculates the length of the argument using `#bytesize` and then append the argument itself after the length, just like the RESP requires.

## How Gitlab uses Redis

Gitlab uses Redis in many places, such as session management, general caching, and so on. What is relevant for us is how Gitlab uses Redis in Github import. Let us follows the code to see.

First, the api for importing github is defined in [here](https://docs.gitlab.com/ee/api/import.html#import-repository-from-github), which is `https://gitlab.com/api/v4/import/github`. This route is defined in `/lib/api/import_github.rb`, and the relevant code is:
```ruby
    post 'import/github' do
      result = Import::GithubService.new(client, current_user, params).execute(access_params, provider)
      if result[:status] == :success
        present ProjectSerializer.new.represent(result[:project], { serializer: :import, warning: result[:warning] })
      else
        status result[:http_status]
        { errors: result[:message] }
      end
    end
```

As one can see, it calls a service `Import::GithubService`, which is defined in [/app/services/import/github_service.rb](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/services/import/github_service.rb?ref_type=heads). Here, it will perform various checks such as access control checks. If everything is fine, it will in turn call `Gitlab::LegacyGithubImport::ProjectCreator` defined in [/lib/gitlab/legacy_github_import/project_creator.rb](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/legacy_github_import/project_creator.rb?ref_type=heads), which in turn call `::Projects::CreateService` defined in [/app/services/projects/create_service.rb](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/services/projects/create_service.rb?ref_type=heads).

In `::Project::CreateService`, Gitlab first check relevant access controls to make sure the user is able to create projects, and then create the project scaffold and hand the import job to background process using `#add_import_job` defined in  [/app/models/project.rb](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/models/project.rb?ref_type=heads), which at last called `RepositoryImportWorker` in the same file. 

I would omit some flows that are not relevant for our discussion. but you can always see [docs](https://docs.gitlab.com/ee/development/github_importer.html) for the detail flow. Basically, what is following is gitlab would send jobs to workers to import repository, wiki, labels, releases and so on one by one.

What is relevant is that in many importers, gitlab would first check whether the item has already been imported before doing the import, which is a natural logic to avoid importing duplicate items from github.

For example, in [collaborators importer](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/github_import/importer/collaborators_importer.rb?ref_type=heads), we can see:
```ruby
 def each_object_to_import
          repo = project.import_source

          direct_collaborators = client.collaborators(repo, affiliation: 'direct')
          outside_collaborators = client.collaborators(repo, affiliation: 'outside')
          collaborators_to_import = direct_collaborators.to_a - outside_collaborators.to_a

          collaborators_to_import.each do |collaborator|
            next if already_imported?(collaborator)

            yield collaborator

            Gitlab::GithubImport::ObjectCounter.increment(project, object_type, :fetched)
            mark_as_imported(collaborator)
          end
```

Note the `already_imported` function, which is defined in [parallel_scheduling.rb](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/github_import/parallel_scheduling.rb?ref_type=heads#L158):
```ruby
      def already_imported?(object)
        id = id_for_already_imported_cache(object)

        Gitlab::Cache::Import::Caching.set_includes?(already_imported_cache_key, id)
      end
```

And finally we catch up the report's second code snippet. Here `#id_for_already_imported_cache` is actually a quite straightforward wrapper to extract the `id` or `number` (depending on the type of item being imported) from the response JSON.

Remember that we can control this `id` as a Sawyer::Resource? Yes, from now on we can consider `id` to be tainted. Let's follow the code to see where this tainted `id` would flow to. Immediately we can see it is passed to `Gitlab::Cache::Import::Caching.set_includes`, and the code is here:
```ruby
        def self.set_includes?(raw_key, value)
          validate_redis_value!(value) #NOTE THIS, this is part of patch

          key = cache_key_for(raw_key)

          with_redis do |redis|
            redis.sismember(key, value || value.to_s)
          end
        end
```

Let's first ignore the `validate_redis_value` as this is actually part of the patch to fix this vulnerability. What is relevant is that the `value` is passed into a `redis` command. And every `redis` command would naturally build and serialise commands following the RESP.

## Payload Analysis

Now that we see the whole flow from the api endpoint to the redis sink, we can try to understand what the payload does. According to the author, the payload is `{"to_s": {"bytesize": 2, "to_s": "1234REDIS_COMMANDS" }}`. Let us see how this payload fits into the sink.

So now the `value` passed to `redis.sismember(key, value || value.to_s)` would be our payload. Since our payload redefined `to_s` and `bytesize`. Why these two functions? Let's review how redis builds commands:
```ruby
      def build_command(args)
        command = [nil]

        args.each do |i|
          if i.is_a? Array
            i.each do |j|
              j = j.to_s
              command << "$#{j.bytesize}"
              command << j
            end
          else
            i = i.to_s
            command << "$#{i.bytesize}"
            command << i
          end
        end
```
Here, we can clearly see that redis would first call `to_s` to convert value to string, and then call `bytesize` to calculate the length of our string. Little did it know that both these commands have been manipulated by us. So `to_s` would actually return `{"bytesize": 2, "to_s": "1234REDIS_COMMANDS" }`, and then `j.to_s.bytesize` would actually return 2. However, our payload is actually `1234REDIS_COMMANDS`, way more than 2 bytes. 

Once this payload is serialized and passed to redis server, the redis server would think the argument has 2 bytes, and would cut the commands off at `1234` (`34` is included as "we need to reserve 4 bytes as 2 additional bytes for CLRF"), which leaves the rest of our command injected into the redis server, achieving RCE.

The exact payload is not important here so I will not explain it. But looking at it in the report, you may ask, "but how does the injected command get executed since the payload is not serialized according to RESP." The reason is that RESP is not the only protocol that Redis accepts. Redis is actually quite lenient in the serialization methods, and even if you do not follow RESP, it would still try to understand your command as an inline command. 

So if you want to execute a `PING` command, both of the following works:
```bash
echo -ne "*2\r\n\$4\r\nPING\r\n\$4\r\nPONG\r\n" | nc localhost 6379 
echo -ne "PING PONG\r\n" | nc localhost 6379
#And so you can inject your second command like this
echo -ne "*2\r\n\$4\r\nPING\r\n\$2\r\n1234PING\r\n" | nc localhost 6379 
```

## Patch Analysis

So how did Github fixed the vulnerability. I did not find the exact merge requests fixing this vulnerability, but I found several fixes about it.

As mentioned above, gitlab added `validate_redis_value!`, which is basically there to check that the value is a string:
```ruby
def self.validate_redis_value!(value)
          value_as_string = value.to_s
          return if value_as_string.is_a?(String)

          raise "Value '#{value_as_string}' of type '#{value_as_string.class}' for '#{value.inspect}' is not a String"
        end
```

But this is of course not enough since in our payload we can also redefine `is_a?`. So gitlab also patched Sawyer to fix it from the root in [/config/initializers/sawyer_patch.rb](https://gitlab.com/gitlab-org/gitlab/-/blob/master/config/initializers/sawyer_patch.rb).
```ruby
  def attr_accessor(*attrs)
    attrs.each do |attribute|
      class_eval do
        define_method attribute do
          raise Sawyer::Error,
            "Sawyer method \"#{attribute}\" access is forbidden. Convert to a hash to access the attribute."
        end

        define_method "#{attribute}=" do |value|
          raise Sawyer::Error,
            "Sawyer method \"#{attribute}=\" access is forbidden. Convert to a hash to access the attribute."
        end

        define_method "#{attribute}?" do
          raise Sawyer::Error,
            "Sawyer method \"#{attribute}?\" overlaps Ruby method. Convert to a hash to access the attribute."
        end
      end
    end
  end

```

That's about it. See you next time!