import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fetchAttachment, imageMime } from '../web/src/components/attachmentContent.js'
test('download sends JWT only to the configured API with encoded ID and no redirects', async () => {
  let observed
  const signal = new AbortController().signal
  const blob = await fetchAttachment('https://api.example.invalid/', 'id/with?chars', 'test-token', signal, async (url, options) => {
    observed = { url, options }; return new Response('private bytes')
  })
  assert.equal(observed.url, 'https://api.example.invalid/attachments/id%2Fwith%3Fchars/content')
  assert.equal(observed.options.headers.Authorization, 'Bearer test-token')
  assert.equal(observed.options.redirect, 'error'); assert.equal(observed.options.cache, 'no-store')
  assert.equal(observed.options.signal, signal); assert.equal(await blob.text(), 'private bytes')
})
test('revoked access and expired session never expose response bytes', async () => {
  for (const status of [401, 403]) await assert.rejects(fetchAttachment('https://api.example.invalid', 'id', 'token', undefined, async () => new Response('secret', { status })), /no longer accessible/)
})
test('no request without session or ID; failed storage response is explicit', async () => {
  const forbidden = () => { throw new Error('Network should not be called') }
  await assert.rejects(fetchAttachment('https://api.example.invalid', 'id', '', undefined, forbidden), /sign in/)
  await assert.rejects(fetchAttachment('https://api.example.invalid', '', 'token', undefined, forbidden), /sign in/)
  await assert.rejects(fetchAttachment('https://api.example.invalid', 'id', 'token', undefined, async () => new Response('', { status: 500 })), /try again/)
})
test('HTML and SVG are downloads, not active inline content', () => {
  for (const mime of ['text/html', 'image/svg+xml', 'application/pdf', undefined]) assert.equal(imageMime(mime), null)
  assert.equal(imageMime('image/png'), 'image/png')
})
