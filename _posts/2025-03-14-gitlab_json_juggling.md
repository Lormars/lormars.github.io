---
title: From Report to Patch - Gitlab Graphql CSRF Bypass through json juggling
date: 2025-03-13 1:00:00
categories: [Digest, BBP]
tags: [Gitlab, CSRF, Ruby]
---

Recently I read a [blog post](https://nastystereo.com/security/rails-_json-juggling-attack.html) on json juggling attack on ruby on rails. The theory is quite straightforward, and I would summarize succinctly here for my lazy readers. In HTTP request, client would often send parameters, either through request body (in POST request), or in URL (in GET request). ROR would parse these query parameters and turn them into hashes for backend to process them.

Hashes in ruby is just another term for object in other languages, like Javascript, or dictionary, like Python. 

For example, the following are some common translation of query parameters to ruby hashes
```ruby
#?q=a&b=c
{"q"=>"a","b"=>"c"}

#?q=[1,2]
{"q"=>"[1,2]"}

#?q[a]=1&q[b]=2
{"q"=>{"a"=>"1","b"=>"2"}}

#{"a":"b","c":1,"d":true} <= as in json
{"a"=>"b","c"=>1,"d"=>true}
```
As you can see, the translation is quite straightforward and intuitive, but there is one thing that is the special case, which is when the request param is an array, such as a json array. Since array is not a key-value pair structure, ruby has to implement a special way to somehow translate to hash
```ruby
#[1,2,3] <= as in json array
{"_json"=>[1,2,3]}
```
And this is how ROR solves it, by giving the array a key `_json`.

This creates a subtle problem because there is nothing preventing a user to send a request with a query parameter key `_json`, like the following
```ruby
#?_json[][a]=b
{"_json"=>[{"a"=>"b"}]}

#[{"a":"b"}] <= as in json
{"_json"=>[{"a"=>"b"}]}
```
As you can see, these two request would end up with the exact same hash. But you may ask, what's the fuss about it? The original post gave an example on how this could lead to authorization bypass. If someone send a request like this
```ruby
#?_json[][id_to_delete]=unauthorized_victim_id&id_to_delete=authorized_id
{"_json"=>[{"id_to_delete"=>"unauthorized_victim_id"}],"id_to_delete"=>"authorized_id"}
```
Then if there are some parsing or business logic error, maybe the authorization step would check `id_to_delete` and found the attacker is authorized, but the deletion logic would use the `_json["id_to_delete"]` value to delete. This would cause business logic error, leading to access bypass.

But is that even practical? I saw in Reddit some discussions on how is this even practical? Are there any real-life example? Today I would share with you a CSRF [bug](https://gitlab.com/gitlab-org/gitlab/-/issues/462012) in Gitlab reported by `ahacker` that takes advantage of this exact issue.

# Graphql 101
The CSRF bug in Gitlab happens through Graphql. For those who don't know, graphql is just a more sophisticated way to call an API. Unlike REST API, it usually has only one endpoint (`/api/graphql`)

It would send its request in JSON, ask for the information it needs, and the server would respond these exact information to the client.

This Graphql API is quite sophisticated, but to understand this report, we need only to know the following things:
1. NORMALLY, all Graphql API are sent through POST request, whether for read operation (called `query` in graphql language) or update/delete/edit operation (called `mutation` in graphql language)
2. You can also sent these request through GET request, but normally you can only send `query` operation, otherwise you got a simple CSRF since `mutation` would change state, and server usually would not check CSRF token in a GET request
3. There is a special request called `introspection` in graphql, which simply returns the backend schema (similar to API docs) of graphql. This endpoint is usually disabled because it can disclose all the endpoints and shape of graphql api (but of course this is not disabled in Gitlab, an open-source program).
4. Graphql has a `batch mode`, which just means you can send multiple queries in a JSON array in one request. And the server would respond all of these queries in one response as well.


# Gitlab Logic Error

Gitlab uses Graphql in numerous ways, and it also disables anyone to send `mutation` queries using GET, though it allows you to send `non-mutation` queries in GET. But how does it implement this check?

In [graphql controller](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/controllers/graphql_controller.rb?ref_type=heads)
```ruby
  def any_mutating_query?  
    if multiplex?  #whether the request is a batch of queries
      multiplex_queries.any? { |q| mutation?(q[:query], q[:operation_name]) }  
    else  
      mutation?(query)  
    end  
  end  
```
Here, `any_mutating_query` is used to check whether there is `mutation` query in the request, and if there is, would not allow it to be processed in a GET request.

`multiplex?` would check whether the request is a batch of queries, and if it is, would ensure that each of the query would not be mutation.

```ruby
  def multiplex?
    params[:_json].is_a?(Array)
  end
```

Notice here, it checks whether the request is a `batch` by checking whether `:json` is an array. Given what we know about ruby hashing in the above sections, we know that this check is totally controlled by the user. So we can just send a request like 
```http
https://host/path?_json[][query]=query%20{__typename}
```
This would pass the `multiplex?` check, and since we only have `query` here, it would also pass the `any_mutating_query?` check, hence passing the CSRF check.

However, there is a very subtle logic error spotted by `ahacker`, which is how Gitlab executes the graphql queries
```ruby
def execute  
    result = if introspection_query?  
               execute_introspection_query  
             else  
               multiplex? ? execute_multiplex : execute_query  
             end
    render json: result  
  end
```

In the `any_mutating_query`, we checked whether the request is multiplex, and here, we also checked whether the request is multiplex to determine how to execute the query.

However, note there is an extra step before this check, which is `introspection_query?`. In the execution logic, contrast to the check logic, Gitlab first checked whether the query is an introspection query, and only if it is not, it would then check whether it is multiplex.

But how does it know whether it is introspection query?
```ruby
  def introspection_query?
    if permitted_params.key?(:operationName)
      permitted_params[:operationName] == INTROSPECTION_QUERY_OPERATION_NAME
    else
      # If we don't provide operationName param, we infer it from the query
      graphql_query_object.selected_operation_name == INTROSPECTION_QUERY_OPERATION_NAME
    end
  end
```
Basically, it would check whether the `operationName` param in the request parameter would equal to `IntrospectioQuery`. And if it is, Graphql would directly call `execute_introspection_query`, which would basically extract the value associated with the `query` param in the request, and execute that queyr.

SAW THE PROBLEM?

Let's see the following request
```http
https://hostname/path?query=mutation_query&operationName=IntrospectionQuery&_json[][query]=normal_query
```
Take a moment to think what would happen in this case?

The check logic would first see `_json`, and see it is a multiplex, and then check each query in `_json` array and found they are all normal queries. Note the check logic would totally ignore `query=mutation_query&operationName=IntrospectionQuery` and only extract queries from the `_json` array since it would think the request is sending an array of queries.

On the other hand, the execution logic would first see `operationName` and see it is an introspection query, and totally ignore `&_json[][query]=normal_query` to directly extract query from `?query=mutation_query` to execute this `mutation_query`.

Viola! Your managed to achieve CSRF using GET request since the check logic thought all your queries are normal non-mutation queries by inspeding queries only in `_json`, and the execution logic would execute your mutation query outside of `_json`, which is not checked by the check logic.

# Patch

The patch is actually quite simple in this case. Gitlab just switched the execution logic:
```ruby
  def execute
    result = if multiplex?
               execute_multiplex
             else
               introspection_query? ? execute_introspection_query : execute_query
             end

    render json: result
  end
```

That's it! See you next time.