// Wordlists used to discover input surface the crawler cannot see.
// Kept deliberately small: every guessed parameter costs a probe, and a
// red-team tool should be hard to tell apart from normal browsing traffic.

const COMMON_PARAMS = [
  'q', 's', 'search', 'query', 'keyword', 'term', 'id', 'page', 'cat',
  'category', 'product', 'item', 'user', 'username', 'name', 'email',
  'file', 'path', 'doc', 'download', 'view', 'template', 'lang', 'ref',
  'action', 'type', 'mode', 'sort', 'filter', 'format', 'debug', 'test',
  'jsonp', 'callback', 'cmd', 'exec'
];

const REDIRECT_PARAMS = [
  'redirect', 'redirect_uri', 'redirect_url', 'url', 'next', 'return',
  'returnurl', 'return_url', 'dest', 'destination', 'goto', 'out', 'link',
  'continue', 'target', 'to', 'r', 'u', 'checkout_url', 'callback_url'
];

const URL_PARAMS = [
  'url', 'uri', 'link', 'src', 'source', 'dest', 'destination', 'target',
  'host', 'site', 'domain', 'feed', 'callback', 'webhook', 'image', 'img',
  'imageurl', 'file', 'path', 'load', 'fetch', 'proxy', 'api', 'endpoint',
  'redirect', 'return', 'next', 'page', 'request'
];

const FILE_PARAMS = [
  'file', 'filename', 'path', 'dir', 'folder', 'page', 'doc', 'download',
  'template', 'include', 'view', 'img', 'image', 'load', 'read', 'src',
  'resource', 'asset', 'theme', 'lang', 'layout'
];

module.exports = { COMMON_PARAMS, REDIRECT_PARAMS, URL_PARAMS, FILE_PARAMS };
