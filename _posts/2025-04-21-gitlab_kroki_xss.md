---
title: From Report to Patch - XSS via Kroki
date: 2025-04-21 1:00:00
categories: [Digest, BBP]
tags: [Gitlab, XSS]
---

In 2022, [vakzz](https://hackerone.com/vakzz?type=user) reported a Stored XSS via Kroki diagram to Gitlab. Today, we would check the report to understand how this XSS works, and how Gitlab patches this vulnerability. Note that this report contains two parts, one is this Stored XSS, and another is CSP bypass. In this blog we would only focus on the Stored XSS part.

### Disclaimer

I am by no means an expert in ruby/bug bounty hunting/ruby on rails/source code review. As I explore hacking, I use writing and sharing blogs as a way to reinforce my understanding. The content below reflects my best effort to grasp the vulnerability, but it may not be entirely accurate.


But Before we jump into the XSS payload, we need to first understand some concepts and techniques used in web development.
### What is Kroki

Based on [kroki's official website](https://kroki.io/), Kroki is simply a unified API with support for all the diagram libraries like mermaid and graphviz. It follows a client-server model, and basically all you need to do is to craft your diagram, and then encode your diagram and sent it to the Kroki server. The server would process your diagram and return a rendered image of your diagram.

It makes creating a diagram very simple. For example, you can have a diagram like this:
```
graph TD
  C --> E[ Sharing ideas ]
  C --> F[ Advocating ]
```

Then you can just base64 encode it, and send to kroki server using this url: `https://kroki.io/mermaid/svg/eNpLL0osyFAIceFSUHBW0NW1U3CNVgjOSCzKzEtXyExJTSxWiIVLuUUrOKaU5ScnloBkY7kAADIRDA==`. Note how this url specifies the type of your diagram library (mermaid), the format of the returned image (svg), and the base64-encoded content of your diagram.

### What is CSS Selector and XPath

For those who have at least some experience in front end web development, CSS selector would not be a foreign concept. It is used commonly in css files to select and target the html element that one wants to target on.

For example, here are some common CSS selector types:

|Selector|Matches|
|---|---|
|`div`|All `<div>` elements|
|`.class`|Elements with `class="class"`|
|`#id`|Element with `id="id"`|
|`div > p`|`<p>` directly inside a `<div>`|
|`a[href]`|`<a>` tags with an `href` attribute|
|`pre[lang="plantuml"]`|`<pre>` with `lang="plantuml"`|
|`pre > code[lang="plantuml"]`|`<code lang="plantuml">` directly inside a `<pre>`|

Then what is XPath? XPath is actually a quite similar concept, and you can think it like an equivalent of css selector in xml documents, only more powerful. While **CSS selectors** are used primarily in HTML documents, **XPath** is used in both **HTML and XML** for querying and navigating documents as trees.

So for a CSS selector like `pre[lang="plantuml"] > code`, an equivalent XPath would be `//pre[@lang="plantuml"]/code`, and they are exactly the same in the final element they would select.

### Stored XSS

Now let's dive into the [report](https://hackerone.com/reports/1731349).

This report is relatively simple to understand. Basically Gitlab would use XPath to select for an element that needs to be converted into a kroki diagram, but is using another element's attribute to construct the final url used in the image tag.

Let's check the code:
```ruby
def call  
  return doc unless settings.kroki_enabled  
  
  diagram_selectors = ::Gitlab::Kroki.formats(settings)  
                          .map do |diagram_type|  
                            %(pre[lang="#{diagram_type}"] > code,  
                            pre > code[lang="#{diagram_type}"])  
                          end  
                          .join(', ')  
  
  xpath = Gitlab::Utils::Nokogiri.css_to_xpath(diagram_selectors)  
  return doc unless doc.at_xpath(xpath)  
  
  diagram_format = "svg"  
  doc.xpath(xpath).each do |node|  
    diagram_type = node.parent['lang'] || node['lang']  
    diagram_src = node.content  
    image_src = create_image_src(diagram_type, diagram_format, diagram_src)  
    img_tag = Nokogiri::HTML::DocumentFragment.parse(%(<img src="#{image_src}" />))
```

Here, the XPath selector is constructed using 
```ruby
  diagram_selectors = ::Gitlab::Kroki.formats(settings)  
                          .map do |diagram_type|  
                            %(pre[lang="#{diagram_type}"] > code,  
                            pre > code[lang="#{diagram_type}"])  
                          end  
                          .join(', ') 
```
And the final selector would match either of
```ruby
pre[lang="#{diagram_type}"] > code
pre > code[lang="#{diagram_type}"]
```
After the node is selected by the selector, however, the `diagram_type` is defined as
```ruby
    diagram_type = node.parent['lang'] || node['lang']  
```
So it means that if a child node is matched using the CSS selector, the node's parent node is instead used to find the `diagram_type`.

Let's see the example payload given by the researcher:
```html
<a><pre lang='f/" onerror=alert(1) onload=alert(1) '><code lang="wavedrom">xss</code></pre></a>
```

Here, `<code lang="wavedrom">xss</code>` would be selected by the css selector `pre > code[lang="#{diagram_type}"]`, and its parent's `lang` attribute `f/" onerror=alert(1) onload=alert(1) ` would be used to construct the final image tag. Since the image tag is constructed simply by using 
```ruby
img_tag = Nokogiri::HTML::DocumentFragment.parse(%(<img src="#{image_src}" />))
```
The final image tag would look something like `<img src="https://kroki.io/f/" onerror=alert(1) onload = alert(1) /garbages...>`, which would lead to XSS when executed.

### Patch

The patch of this vulnerability is quite straightforward.

First, Gitlab adds a check to the `diagram_type`:
```ruby
diagram_type = node.parent['lang'] || node['lang']  
next unless diagram_selectors.include?(diagram_type)
```
This way, Gitlab would make sure that the `diagram_type` is not some random payload, but a valid kroki digram type.

Second, Gitlab fixed its way to construct the image tag:
```diff
---      img_tag = Nokogiri::HTML::DocumentFragment.parse(%(<img src="#{image_src}" />))
+++      img_tag = Nokogiri::HTML::DocumentFragment.parse(content_tag(:img, nil, src: image_src))
```
Instead of using string interpolation, Gitlab constructs the image tag using `content_tag`, which would make sure that the `image_src` would not escape context.
### Takeaways

1. Pay close attention to how attributes (e.g., lang) are processed, especially when they are used to construct URLs or HTML elements. Misuse of attributes, as seen in this case, can lead to XSS. 
2. Look for areas where string interpolation is used to build HTML or URLs, as it’s a common source of injection vulnerabilities. Test for ways to break out of the intended context, like injecting event handlers.