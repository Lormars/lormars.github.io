---
title: From Report to Patch - Gitlab SSRF mitigation bypass
date: 2025-02-20 1:00:00
categories: [Digest, BBP]
tags: [Gitlab, SSRF, Ruby]
---

In this [report](https://hackerone.com/reports/632101), mclaren650sspider reported a SSRF mitigation bypass to gitlab. We would dive deep into this report, understand how this vulnerability happened, and how Gitlab fixed it.

## Disclaimer

I am by no means an expert in ruby/bug bounty hunting/ruby on rails/source code review. As I explore hacking, I use writing and sharing blogs as a way to reinforce my understanding. The content below reflects my best effort to grasp the vulnerability, but it may not be entirely accurate.
## The Bypass

Gitlab by 2020 is no stranger to SSRF. Many bounties have been paid to hunters due to SSRF in various components of Gitlab. To fix it once and for all, they have a custom validation logic built in to validate every url  received from clients before issuing the request to ensure that the URL would not point to localhost, and the code is [here](https://gitlab.com/gitlab-org/gitlab-foss/-/blob/108c3cf16bed5733ffae086fb62c226961356560/lib/gitlab/url_blocker.rb#L59)
```ruby
     def validate!(
        url,
        ports: [],
        schemes: [],
        allow_localhost: false,
        allow_local_network: true,
        ascii_only: false,
        enforce_user: false,
        enforce_sanitization: false,
        dns_rebind_protection: true)
        # rubocop:enable Metrics/CyclomaticComplexity
        # rubocop:enable Metrics/ParameterLists
        return [nil, nil] if url.nil?
        # Param url can be a string, URI or Addressable::URI
        uri = parse_url(url)
        validate_html_tags!(uri) if enforce_sanitization
        hostname = uri.hostname
        port = get_port(uri)
        unless internal?(uri)
          validate_scheme!(uri.scheme, schemes)
          validate_port!(port, ports) if ports.any?
          validate_user!(uri.user) if enforce_user
          validate_hostname!(hostname)
          validate_unicode_restriction!(uri) if ascii_only
        end
        begin
          addrs_info = Addrinfo.getaddrinfo(hostname, port, nil, :STREAM).map do |addr|
            addr.ipv6_v4mapped? ? addr.ipv6_to_ipv4 : addr
          end
        rescue SocketError
          return [uri, nil]
        end
        protected_uri_with_hostname = enforce_uri_hostname(addrs_info, uri, hostname, dns_rebind_protection)
        # Allow url from the GitLab instance itself but only for the configured hostname and ports
        return protected_uri_with_hostname if internal?(uri)
        validate_localhost!(addrs_info) unless allow_localhost
        validate_loopback!(addrs_info) unless allow_localhost
        validate_local_network!(addrs_info) unless allow_local_network
        validate_link_local!(addrs_info) unless allow_local_network
        protected_uri_with_hostname
      end
```

The vulnerability in this code is explained by the report quite clearly. Basically, for every validation, such as `validate_hostname!`, if the validation failed, it would raise an error directly, and no http request would be sent accordingly.

However, take a closer look at this part:
```ruby
begin
  addrs_info = Addrinfo.getaddrinfo(hostname, port, nil, :STREAM).map do |addr|
    addr.ipv6_v4mapped? ? addr.ipv6_to_ipv4 : addr
    end
rescue SocketError
    return [uri, nil]
end
```
Here if there is an `SocketError`, which happens when DNS failed to resolve, the `SocketError` would be rescued and it will return an array `[uri, nil]` (The expected return of this function is `[uri, ip]`). Note how this `rescue` directly returned the array without raising any errors? That is the problem since the calling function would assume that validation is passed if there is no error!

So an attacker can bypass the mitigation with a malicious DNS server that would fail to resolve (e.g. through timeout) when it was first queried but return internal IP later. Sound complicated, but it is definitely achievable with a custom DNS server.

## The Patch
Here is the [patch](https://gitlab.com/gitlab-org/gitlab/-/blob/master/gems/gitlab-http/lib/gitlab/http_v2/url_blocker.rb?ref_type=heads#L218):
```ruby
        def get_address_info(uri)
          Timeout.timeout(GETADDRINFO_TIMEOUT_SECONDS) do
            Addrinfo.getaddrinfo(uri.hostname, get_port(uri), nil, :STREAM).map do |addr|
              addr.ipv6_v4mapped? ? addr.ipv6_to_ipv4 : addr
            end
          end
        rescue Timeout::Error => e
          raise Gitlab::HTTP_V2::UrlBlocker::BlockedUrlError, e.message
        rescue ArgumentError => e
          # Addrinfo.getaddrinfo errors if the domain exceeds 1024 characters.
          raise unless e.message.include?('hostname too long')

          raise BlockedUrlError, "Host is too long (maximum is 1024 characters)"
        end
```

As you can see, the patch is quite simple. It would wrap the `getaddrinfo` with a Timeout, and raise error if resolve fails due to timeout. 

You may be curious: why only these two errors? What about `SocketError`. The reason is because `SocketError` is captured in the calling function:
```ruby
          begin
            address_info = get_address_info(uri)
          rescue SocketError
            proxy_in_use = uri_under_proxy_setting?(uri, nil)

            unless enforce_address_info_retrievable?(uri,
              dns_rebind_protection,
              deny_all_requests_except_allowed,
              outbound_local_requests_allowlist)
              return Result.new(uri, nil, proxy_in_use)
            end

            raise BlockedUrlError, 'Host cannot be resolved or invalid'
          end
```
Here we can see it captures `SocketError`, performs additional check, and raise an `BlockedUrlError` if the additional check also fails, which effectively fixed this vulnerability.

That's about it. See you next time!
