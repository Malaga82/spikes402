import { describe, expect, it } from "vitest";
import { isAllowedOrigin, siteKey } from "./site";

describe("siteKey", () => {
  it("is the registrable domain, so subdomains share one site", () => {
    expect(siteKey("https://example.com")).toBe("example.com");
    expect(siteKey("https://shop.example.com")).toBe("example.com");
    expect(siteKey("https://a.b.c.example.com:8443")).toBe("example.com");
    expect(siteKey("https://sub0.evil.example")).toBe("evil.example");
    expect(siteKey("https://sub49.evil.example")).toBe("evil.example");
    expect(siteKey("https://www.example.co.uk")).toBe("example.co.uk");
    expect(siteKey("https://EXAMPLE.com.")).toBe("example.com");
  });

  it("keeps tenants of shared hosts apart (Public Suffix List private section)", () => {
    expect(siteKey("https://alice.github.io")).toBe("alice.github.io");
    expect(siteKey("https://bob.github.io")).toBe("bob.github.io");
    expect(siteKey("https://x.alice.github.io")).toBe("alice.github.io");
  });

  it("shows look-alike (IDN) domains in their ASCII form", () => {
    expect(siteKey("https://xn--80ak6aa92e.com")).toBe("xn--80ak6aa92e.com");
  });

  it("keys IP addresses and bare suffixes by their exact host", () => {
    expect(siteKey("https://203.0.113.7")).toBe("203.0.113.7");
    expect(siteKey("https://co.uk")).toBe("co.uk");
    expect(siteKey("https://github.io")).toBe("github.io");
  });

  it("allows http only for local development, keyed with the port", () => {
    expect(siteKey("http://localhost:8080")).toBe("localhost:8080");
    expect(siteKey("http://127.0.0.1:3000")).toBe("127.0.0.1:3000");
    expect(siteKey("http://localhost")).toBe("localhost");
    expect(siteKey("https://localhost:8443")).toBe("localhost:8443");
  });

  it("has no site for hosts named like Object.prototype members", () => {
    for (const o of ["https://constructor", "https://__proto__"]) { // hostnames are lower case: the only such members
      expect(siteKey(o)).toBeUndefined();
    }
    expect(siteKey("https://constructor.example")).toBe("constructor.example");
    expect(siteKey("https://tostring")).toBe("tostring");
  });

  it("has no site for other http origins or other schemes", () => {
    for (const o of ["http://example.com", "http://192.168.1.5", "http://evil.localhost", "http://localhost.evil.com", "ftp://example.com", "file:///x", "null", "", "chrome-extension://abc"]) {
      expect(siteKey(o)).toBeUndefined();
      expect(isAllowedOrigin(o)).toBe(false);
    }
  });
});
