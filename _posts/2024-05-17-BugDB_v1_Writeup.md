---
title: BugDB v1
date: 2024-05-17 1:00:00
categories: [Writeup, CTF]
tags: [GraphQL]
---

# HackerOne CTF: BugDB v1 Write-up

This is a straightforward write-up for the HackerOne CTF challenge, BugDB v1, which focuses on GraphQL.

While this challenge is relatively simple, I want to highlight a useful tool for pentesting GraphQL: [GraphQL Visualizer](http://nathanrandal.com/graphql-visualizer/). This tool is incredibly helpful for visualizing the model relationships within a GraphQL API.

Let's dive in.

## BugDB v1

Upon launching the challenge, it's clear that the task involves probing the GraphQL API to uncover hidden information. The first step in testing GraphQL is to run an
introspection query to discover schema details. If you're using Burp Suite, this step is quite straightforward since it can automatically generate the introspection
queries for you. For more information on what an introspection query is and how to use Burp Suite,
refer to [PortSwigger's GraphQL Academy](https://portswigger.net/web-security/graphql#discovering-schema-information), which offers a detailed explanation.

## GraphQL Visualizer

Given that schema information can often be lengthy and complex, it's much easier to work with by visualizing it through a graph. This is where _GraphQL Visualizer_ comes in, providing a simple interface for visualizing the schema.

All you need to do is paste the schema information into the tool, and it will generate a graph for you, as shown below:

![image](/assets/images/graphql-erd.svg)

Isn't it better to reason with?

Based on the graph, we can tell that we can start our query from `user`, which lead to `UsersConnection`, all the way to `Bugs_`, which contains
fields like `reporterId` and `text`, which may hide the flag. So we can construct a query like below, which will return the flag hidden in the text field:

```graphql
query {
  user {
    edges {
      node {
        bugs {
          edges {
            node {
              id
              reporterId
              text
              private
            }
          }
        }
      }
    }
  }
}
```
