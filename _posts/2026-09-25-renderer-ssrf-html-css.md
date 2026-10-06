---
title: "Renderer SSRF: When HTML and CSS Fetch for You"
date: 2026-09-25 16:55:00 +0700
categories:
  - notes
tags:
  - ssrf
  - renderer
  - html
  - css
  - pdf
  - web
---

Classic SSRF hunts start with an obvious URL field. Renderer bugs often do not. The application takes HTML, Markdown, a template, or a document, hands it to a headless browser or converter, and that worker quietly fetches images, stylesheets, fonts, iframes, or redirects on your behalf.

This note continues from the Interactsh workflow. Once you can detect OOB callbacks, renderer sinks become much easier to prove.

## What "renderer SSRF" means

Any feature that turns markup into a preview, PDF, thumbnail, or email HTML is a candidate:

- HTML-to-PDF export
- invoice or report generators
- Markdown/wiki preview
- email template rendering
- OG/link-preview bots that fetch embedded assets
- "print this page" services

The injection point may look harmless: an image URL in a rich-text editor, a custom CSS field, or a template partial. The privileged fetch happens later, inside a worker with a different network path than the front-end app.

## High-value injection surfaces

Prioritize fields that survive into the rendered document:

1. `<img src="...">`
2. `<link rel="stylesheet" href="...">`
3. `@import url("...")` in CSS
4. `<iframe src="...">` / `<embed>` / `<object>`
5. SVG `<image href="...">`
6. HTML redirects and meta refresh, when the renderer follows them
7. Font URLs and cursor URLs in CSS

If the product sanitizes `<script>` but keeps images and styles, you still have fetch primitives.

## First-pass payloads

Keep them boring. Proof of fetch beats cleverness.

```html
<img src="http://UNIQUE/renderer-img">
<link rel="stylesheet" href="http://UNIQUE/renderer-css">
```

```css
@import url("http://UNIQUE/css-import");
background-image: url("http://UNIQUE/css-bg");
```

```html
<iframe src="http://UNIQUE/iframe"></iframe>
<meta http-equiv="refresh" content="0;url=http://UNIQUE/meta-refresh">
```

Use a unique Interactsh subdomain per surface. When the callback arrives, you immediately know whether image fetch, CSS import, or iframe navigation worked.

## Why renderers bypass "URL field" filters

Front-end validation often only inspects one dedicated URL parameter. Markup sinks are different:

- sanitizers allow `http(s)` images for legitimate content
- HTML is stored raw, then rendered by another service
- the worker may have broader egress than the API pod
- relative URL joins and base tags can rewrite destinations after validation

A common pattern: the API rejects `http://127.0.0.1`, but accepts an HTML body containing `<img src="http://169.254.169.254/...">` because nobody revalidated nested URLs at render time.

## Async is the default

Expect delay. PDF workers, preview queues, and email renderers rarely execute inline with the HTTP response. Practical loop:

1. Submit markup with OOB markers.
2. Trigger the render action explicitly if preview is lazy.
3. Wait 30-90 seconds before declaring a miss.
4. Check DNS and HTTP callbacks separately.
5. Re-render once after editing. Some caches serve the old document.

If DNS hits minutes later, treat that as a real finding and adjust your wait budget for the rest of the engagement.

## From callback to scoped impact

After OOB confirmation:

- identify which renderer fetched you from headers and timing
- test whether HTTPS, HTTP, and non-standard ports all work
- try internal hostnames only inside scope
- for PDF/HTML converters, check if file fetch schemes are enabled at all before spending time on them
- document the exact markup that survived sanitization

Do not jump straight to cloud metadata on the first hit. Prove the fetch class, then escalate inside the rules of engagement.

## Quick checklist

- Rich text, template, CSS, and Markdown fields mapped
- Unique OOB token per markup surface
- Image, CSS, iframe, and SVG vectors tested
- Render action actually triggered
- Async wait observed
- Callback protocol and source recorded

## Closing

Renderer SSRF is SSRF with extra steps and better camouflage. If the product turns user markup into pixels or PDFs, assume nested fetches exist until the worker proves otherwise.

Next note: turning a confirmed renderer fetch into practical internal routing checks without turning the writeup into a payload dump.
