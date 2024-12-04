---
title: Cookie Bomb - A simple trick to get your first bounty
date: 2024-12-04 1:00:00
categories: [Writeup, BBP]
tags: [LHF]
---

# Introduction

It is often hard to find the first bug after starting bug hunting. In this blog I will introduce a
simple Low hanging fruit that could help you get your first bug in your bug bounty career.

## Cookie Bomb

The "Cookie Bomb" is a clever yet simple trick that targets a vulnerability by injecting excessively long cookies into a victim's browser. When these cookies grow beyond a certain size, the server may refuse to process requests, effectively resulting in a Denial of Service (DoS) for the victim.

What makes this exploit particularly impactful is its persistence. Since cookies aren't automatically cleared when the browser is closed, a non-technical victim might struggle to resolve the issue without manually clearing their cookies. This makes the Cookie Bomb a potent tool for causing disruption to the user experience.

By understanding and testing for this vulnerability, you can uncover valuable insights and potentially report it for your first bug bounty success.

## How to find it

To identify a Cookie Bomb vulnerability, closely examine how the server or client-side JavaScript handles cookie-setting behavior. Specifically, look for scenarios where your query parameters or input are reflected in a cookie. If you discover such behavior, test whether you can manipulate the cookie length to create an excessively large payload, potentially leading to a DoS scenario for users.

## Tricks and caveats
While exploiting a Cookie Bomb might seem straightforward, there are important limitations and nuances to consider:
Cookie Length Limitations

Browsers enforce a maximum size for individual cookies, which is typically 4KB per cookie. This means you can't directly set a cookie like controlled=verylongvalue with a value exceeding 4KB.

## Overcoming the Limit

Most servers become vulnerable to a Cookie Bomb when the total size of cookies in a request ranges from 8KB to 20KB, depending on the server's configuration. To achieve this:

1. Control Multiple Cookies: You must control at least two or more cookie names to reach the required payload size.
2. Leveraging Partitioned Cookie: Paritioned cookie is roughly like a cookie storing in a separate storage area. The neat thing about this is that since this cookie is on a separate storage area, you can actually set two cookies with the same name in the victim's browser. And when the browser sends HTTP requests, it will send both of these cookies to the server. For example, many cookie-setting code does not escape `;`, making you can do something like `https://example.com?cookie=asdf;Partitioned`. Here, `Partitioned` will be interpreted as an attribute of the cookie and make this cookie partitioned. So if you send one request with partitioned and another request without, even though both of these cookies have the same name, the second one will not replace the first one. Rather, both of them will be sent when a request is made to the server. It means that you can effectively set 8KB of cookies with control over one cookie name.


With these tricks, you can then try to exploit cookie bomb whenever you find that you can control cookie values.