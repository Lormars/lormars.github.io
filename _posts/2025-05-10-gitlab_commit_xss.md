---
title: From Report to Patch - Gitlab's Stored-XSS injected in commit notes
date: 2025-05-10 1:00:00
categories: [Digest, BBP]
tags: [Gitlab, xss]
---

This [report](https://gitlab.com/gitlab-org/gitlab/-/issues/461773) is quite straightforward. Basically, there is a stored XSS in commit notes. Let's directly check the culprit.

### Disclaimer

I am by no means an expert in ruby/bug bounty hunting/ruby on rails/source code review. As I explore hacking, I use writing and sharing blogs as a way to reinforce my understanding. The content below reflects my best effort to grasp the vulnerability, but it may not be entirely accurate.

### Culprit

```javascript
     const headerMessage = $systemNote  
        .find('.note-text')  
        .find('p')  
        .first()  
        .text()  
        .replace(':', '');

      $systemNote.find('.note-header .system-note-message').html(headerMessage); 
```

The report is quite clear on how this code is vulnerable. Basically, this code extract a message from `$systemNote` using `.text()`, but then insert this note to the html using `.html()`

For those unfamiliar with jQuery, both of these functions are native functions in jQuery, and here is a simple example:
```html
    <h1 id="header">&lt;script&gt;console.log(1)&lt;/script&gt;</h1>

    <script>
        let text = $('#header').text()
        $('#header').html(text)
    </script>
```

Here the first `.text()` method would query the html document and return `<script>console.log(1)</script>`. Yes it would automatically decode html entities. In contrast, if you use `let text = $('#header').html()`, it would return `&lt;script&gt;console.log(1)&lt;/script&gt;`.

Now the `.html(text)` would not escape dangerous characters. So if you pass it in `<script>console.log(1)</script>`, it would lead to XSS.

So basically, Gitlab got it in reverse. If you extract content using `.text()` and inject is later using `.html(text)`, it would automatically decode encoded html entities, and pass them directly in HTML, leading to XSS. In contrast, if you use `.html()` to extract content and `.text()` to inject content, it would work fine.

### Patch

To my surprise, the patch is quite...straightforward: Gitlab simply removed the vulnerable function from the front end. So...that's it! See you next time!
