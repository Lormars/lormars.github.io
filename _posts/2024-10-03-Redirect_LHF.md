---
title: Redirect Misconfiguration - A simple bug to try in BBP
date: 2024-10-03 1:00:00
categories: [Writeup, BBP]
tags: [LHF]
---

# Introduction

It is often hard to find the first bug after starting bug hunting. In this blog I will introduce a
simple Low hanging fruit that could help you get started in your bug hunting career.

## Redirect Misconfiguration

Yes we all know what a redirect is. Often when you try to access some pages unauthorized, you will
be redirected to a login page to enter your credentials. However, some programs misconfigured this
redirection logic, in the sense when they return the 301/302 page, they also return sensitive
information in the response body. Of course we cannot see the response in the browser, but with a
proxy like Burpsuite or Caido, it is just obvious what happened behind the scenes.

Moreover, there is another reason why I recommend this bug: it is so simple to automate it! Use your
preferred language, craft a script that scans the endpoints in the scope, and check the response
content length for any redirect. If you find a redirect with a content length of more than 1000, then
there might be something fishy about this endpoint. For me, I have personally found this bug in a VDP after just minutes of automate scanning.

## Prove Impact

Of course you cannot just report it if the response disclosed in the body is not sensitive. But remember,
bugs often happen in cluster. If you find one redirect that is misconfigured, it is very likely to find
other endpoints that are often misconfigured. Try to hit other endpoints, especially endpoints disclosed
in the response body of other misconfigured redirect. Probe it, test it, and you can often find more
sensitive information that would escalate the impact of this simple bug.
